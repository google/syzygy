// Copyright 2013 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Implements the BranchHookTransform class.

#include "syzygy/instrument/transforms/branch_hook_transform.h"

#include "base/logging.h"
#include "base/string_util.h"
#include "base/stringprintf.h"
#include "syzygy/block_graph/block_builder.h"
#include "syzygy/block_graph/block_util.h"
#include "syzygy/common/defs.h"
#include "syzygy/common/indexed_frequency_data.h"
#include "syzygy/instrument/transforms/entry_thunk_transform.h"
#include "syzygy/pe/block_util.h"
#include "syzygy/pe/pe_utils.h"
#include "syzygy/pe/transforms/add_imports_transform.h"

namespace instrument {
namespace transforms {

namespace {

using block_graph::BasicBlock;
using block_graph::BasicBlockAssembler;
using block_graph::BasicBlockReference;
using block_graph::BasicCodeBlock;
using block_graph::BlockBuilder;
using block_graph::BlockGraph;
using block_graph::Displacement;
using block_graph::Immediate;
using block_graph::Operand;
using block_graph::Successor;
using common::kBasicBlockEntryAgentId;
using pe::transforms::AddImportsTransform;

typedef AddImportsTransform::ImportedModule ImportedModule;

const char kDefaultModuleName[] = "basic_block_entry_client.dll";
const char kBranchEnter[] = "_branch_enter";
const char kBranchExit[] = "_branch_exit";

// Sets up the entry and the exit hooks import.
bool SetupEntryHooks(BlockGraph* block_graph,
                     BlockGraph::Block* header_block,
                     const std::string& module_name,
                     BlockGraph::Reference* branch_enter,
                     BlockGraph::Reference* branch_exit) {
  DCHECK(block_graph != NULL);
  DCHECK(header_block != NULL);
  DCHECK(branch_enter != NULL);
  DCHECK(branch_exit != NULL);

  // Setup the import module.
  ImportedModule module(module_name);
  size_t enter_index = module.AddSymbol(kBranchEnter,
                                        ImportedModule::kAlwaysImport);

  size_t exit_index = module.AddSymbol(kBranchExit,
                                       ImportedModule::kAlwaysImport);

  // Setup the add-imports transform.
  AddImportsTransform add_imports;
  add_imports.AddModule(&module);

  // Add the imports to the block-graph.
  if (!ApplyBlockGraphTransform(&add_imports, block_graph, header_block)) {
    LOG(ERROR) << "Unable to add import entry hook functions.";
    return false;
  }

  // Get a reference to the entry-hook function.
  if (!module.GetSymbolReference(enter_index, branch_enter)) {
    LOG(ERROR) << "Unable to get " << kBranchEnter << ".";
    return false;
  }
  DCHECK(branch_enter->IsValid());

  // Get a reference to the exit-hook function.
  if (!module.GetSymbolReference(exit_index, branch_exit)) {
    LOG(ERROR) << "Unable to get " << kBranchExit << ".";
    return false;
  }
  DCHECK(branch_exit->IsValid());

  return true;
}

}  // namespace

const char BranchHookTransform::kTransformName[] = "BranchTransform";

BranchHookTransform::BranchHookTransform()
  : add_frequency_data_(kBasicBlockEntryAgentId,
                        "Basic-Block Branch Information Data",
                        common::kBranchFrequencyDataVersion,
                        common::IndexedFrequencyData::BRANCH),
    thunk_section_(NULL),
    instrument_dll_name_(kDefaultModuleName) {
}

bool BranchHookTransform::PreBlockGraphIteration(
    BlockGraph* block_graph,
    BlockGraph::Block* header_block) {
  DCHECK(block_graph != NULL);
  DCHECK(header_block != NULL);

  // Setup instrumentation functions hooks.
  if (!SetupEntryHooks(block_graph,
                      header_block,
                      instrument_dll_name_,
                      &enter_hook_ref_,
                      &exit_hook_ref_)) {
    return false;
  }

  // Add the static basic-block frequency data.
  if (!ApplyBlockGraphTransform(
          &add_frequency_data_, block_graph, header_block)) {
    LOG(ERROR) << "Failed to insert basic-block frequency data.";
    return false;
  }

  return true;
}

bool BranchHookTransform::OnBlock(BlockGraph* block_graph,
                                  BlockGraph::Block* block) {
  DCHECK(block_graph != NULL);
  DCHECK(block != NULL);

  if (block->type() != BlockGraph::CODE_BLOCK)
    return true;

  // Ignore non-decomposable block.
  if (!pe::CodeBlockIsBasicBlockDecomposable(block))
    return true;

  if (!ApplyBasicBlockSubGraphTransform(this, block_graph, block, NULL))
    return false;

  return true;
}

bool BranchHookTransform::TransformBasicBlockSubGraph(
    BlockGraph* block_graph , BasicBlockSubGraph* subgraph) {
  DCHECK(block_graph != NULL);
  DCHECK(subgraph != NULL);
  DCHECK(enter_hook_ref_.IsValid());
  DCHECK(exit_hook_ref_.IsValid());
  DCHECK(add_frequency_data_.frequency_data_block() != NULL);

  // Insert a call to the basic-block entry hook at the top of each code
  // basic-block.
  BasicBlockSubGraph::BBCollection::iterator it =
      subgraph->basic_blocks().begin();
  for (; it != subgraph->basic_blocks().end(); ++it) {
    BasicCodeBlock* bb = BasicCodeBlock::Cast(*it);
    if (bb == NULL || bb->is_padding())
      continue;

    // Find the source range associated with this basic-block.
    BlockGraph::Block::SourceRange source_range;
    if (!GetBasicBlockSourceRange(*bb, &source_range)) {
      LOG(ERROR) << "Unable to get source range for basic block '"
                 << bb->name() << "'";
      return false;
    }

    // We use the location/index in the bb_ranges vector of the current
    // basic-block range as the basic_block_id, and we pass a pointer to the
    // frequency data block as the module_data parameter. We then make a memory
    // indirect call to the bb_entry_hook.
    Immediate basic_block_id(bb_ranges_.size(), core::kSize32Bit);
    Immediate module_data(add_frequency_data_.frequency_data_block(), 0);

    // Assemble entry hook instrumentation into the instruction stream.
    Operand enter_hook(Displacement(enter_hook_ref_.referenced(),
                                    enter_hook_ref_.offset()));
    BasicBlockAssembler bb_asm_enter(bb->instructions().begin(),
                                     &bb->instructions());
    bb_asm_enter.push(basic_block_id);
    bb_asm_enter.push(module_data);
    bb_asm_enter.call(enter_hook);

    // Find the last non jumping instruction in the basic block.
    BasicBlock::Instructions::iterator last = bb->instructions().begin();
    BasicBlock::Instructions::iterator last_instruction = last;
    for (; last != bb->instructions().end(); ++last) {
      if (!last->IsReturn() && !last->IsBranch()) {
        last_instruction = last;
        ++last_instruction;
      }
    }

    if (last == bb->instructions().end() ||
        !last->CallsNonReturningFunction()) {
      // Assemble exit hook instrumentation into the instruction stream.
      Operand exit_hook(Displacement(exit_hook_ref_.referenced(),
                                     exit_hook_ref_.offset()));
      BasicBlockAssembler bb_asm_exit(last_instruction,
                                      &bb->instructions());
      bb_asm_exit.push(basic_block_id);
      bb_asm_exit.push(module_data);
      bb_asm_exit.call(exit_hook);
    }

    // Push the range for the current basic block.
    bb_ranges_.push_back(source_range);
  }

  return true;
}

bool BranchHookTransform::PostBlockGraphIteration(
    BlockGraph* block_graph, BlockGraph::Block* header_block) {
  DCHECK(block_graph != NULL);
  DCHECK(header_block != NULL);

  size_t num_basic_blocks = bb_ranges_.size();
  if (num_basic_blocks == 0) {
    LOG(WARNING) << "Encountered no basic code blocks during instrumentation.";
    return true;
  }

  if (!add_frequency_data_.ConfigureFrequencyDataBuffer(num_basic_blocks,
                                                        3,
                                                        sizeof(uint32))) {
    LOG(ERROR) << "Failed to configure frequency data buffer.";
    return false;
  }

  // Add the module entry thunks.
  EntryThunkTransform add_thunks;
  add_thunks.set_only_instrument_module_entry(true);
  add_thunks.set_instrument_dll_name(instrument_dll_name_);
  add_thunks.set_src_ranges_for_thunks(true);

  Immediate module_data(add_frequency_data_.frequency_data_block(), 0);
  if (!add_thunks.SetEntryThunkParameter(module_data)) {
    LOG(ERROR) << "Failed to configure the entry thunks with the module_data "
               << "parameter.";
    return false;
  }

  if (!ApplyBlockGraphTransform(&add_thunks, block_graph, header_block)) {
    LOG(ERROR) << "Unable to thunk module entry points.";
    return false;
  }

  // Find or create the section we put our thunks in.
  thunk_section_ = block_graph->FindOrAddSection(common::kThunkSectionName,
                                                 pe::kCodeCharacteristics);
  DCHECK(thunk_section_ != NULL);

  return true;
}

}  // namespace transforms
}  // namespace instrument
