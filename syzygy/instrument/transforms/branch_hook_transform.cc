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
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "syzygy/agent/basic_block_entry/basic_block_entry.h"
#include "syzygy/block_graph/block_builder.h"
#include "syzygy/block_graph/block_util.h"
#include "syzygy/common/defs.h"
#include "syzygy/common/indexed_frequency_data.h"
#include "syzygy/instrument/transforms/entry_thunk_transform.h"
#include "syzygy/pe/pe_utils.h"
#include "syzygy/pe/transforms/pe_add_imports_transform.h"

namespace instrument {
namespace transforms {

namespace {

using agent::basic_block_entry::BasicBlockEntry;
using block_graph::BasicBlock;
using block_graph::BasicBlockAssembler;
using block_graph::BasicBlockReference;
using block_graph::BasicBlockSubGraph;
using block_graph::BasicCodeBlock;
using block_graph::BlockBuilder;
using block_graph::BlockGraph;
using block_graph::Displacement;
using block_graph::Immediate;
using block_graph::Operand;
using block_graph::Successor;
using block_graph::TransformPolicyInterface;
using common::kBasicBlockEntryAgentId;
using pe::transforms::PEAddImportsTransform;

typedef BasicBlockEntry::BasicBlockIndexedFrequencyData
    BasicBlockIndexedFrequencyData;
typedef BasicBlockSubGraph::BlockDescriptionList
    BlockDescriptionList;
typedef pe::transforms::ImportedModule ImportedModule;

const char kDefaultModuleName[] = "basic_block_entry_client.dll";
const char kBranchFunctionEnter[] = "_function_enter";
const char kBranchEnter[] = "_branch_enter";
const char kBranchEnterBuffered[] = "_branch_enter_buffered";
const char kBranchExit[] = "_branch_exit";
const size_t kNumBranchSlot = 4;

// Sets up the entry and the exit hooks import.
bool SetupEntryHooks(const TransformPolicyInterface* policy,
                     BlockGraph* block_graph,
                     BlockGraph::Block* header_block,
                     const std::string& module_name,
                     bool buffering,
                     uint32 fs_slot,
                     BlockGraph::Reference* function_enter,
                     BlockGraph::Reference* branch_enter,
                     BlockGraph::Reference* branch_exit) {
  DCHECK(policy != NULL);
  DCHECK(block_graph != NULL);
  DCHECK(header_block != NULL);
  DCHECK(branch_enter != NULL);
  DCHECK(branch_exit != NULL);

  // Determine which hooks to use.
  std::string function_enter_name;
  std::string branch_enter_name;
  std::string branch_exit_name;

  if (buffering) {
    branch_enter_name = kBranchEnterBuffered;
    branch_exit_name = kBranchExit;
  } else {
    branch_enter_name = kBranchEnter;
    branch_exit_name = kBranchExit;
  }

  if (fs_slot != 0) {
    function_enter_name =
        base::StringPrintf("%s_s%d", kBranchFunctionEnter, fs_slot);
    branch_enter_name =
        base::StringPrintf("%s_s%d", branch_enter_name.c_str(), fs_slot);
    branch_exit_name =
        base::StringPrintf("%s_s%d", branch_exit_name.c_str(), fs_slot);
  }

  // Setup the import module.
  ImportedModule module(module_name);
  size_t enter_index = module.AddSymbol(branch_enter_name,
                                        ImportedModule::kAlwaysImport);

  size_t exit_index = module.AddSymbol(branch_exit_name,
                                       ImportedModule::kAlwaysImport);
  size_t function_enter_index = 0;
  if (!function_enter_name.empty()) {
    function_enter_index = module.AddSymbol(function_enter_name,
                                            ImportedModule::kAlwaysImport);
  }

  // Setup the add-imports transform.
  PEAddImportsTransform add_imports;
  add_imports.AddModule(&module);

  // Add the imports to the block-graph.
  if (!ApplyBlockGraphTransform(
          &add_imports, policy, block_graph, header_block)) {
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

  if (!function_enter_name.empty()) {
    if (!module.GetSymbolReference(function_enter_index, function_enter)) {
      LOG(ERROR) << "Unable to get " << function_enter_name << ".";
      return false;
    }
    DCHECK(function_enter->IsValid());
  }

  return true;
}

}  // namespace

const char BranchHookTransform::kTransformName[] = "BranchTransform";

BranchHookTransform::BranchHookTransform()
  : add_frequency_data_(kBasicBlockEntryAgentId,
                        "Basic-Block Branch Information Data",
                        common::kBranchFrequencyDataVersion,
                        common::IndexedFrequencyData::BRANCH,
                        sizeof(BasicBlockIndexedFrequencyData)),
    thunk_section_(NULL),
    instrument_dll_name_(kDefaultModuleName),
    buffering_(false),
    fs_slot_(0U) {
}

bool BranchHookTransform::PreBlockGraphIteration(
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BlockGraph::Block* header_block) {
  DCHECK_NE(reinterpret_cast<TransformPolicyInterface*>(NULL), policy);
  DCHECK_NE(reinterpret_cast<BlockGraph*>(NULL), block_graph);
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), header_block);
  DCHECK_EQ(BlockGraph::PE_IMAGE, block_graph->image_format());

  // Setup instrumentation functions hooks.
  if (!SetupEntryHooks(policy,
                       block_graph,
                       header_block,
                       instrument_dll_name_,
                       buffering_,
                       fs_slot_,
                       &function_enter_hook_ref_,
                       &enter_hook_ref_,
                       &exit_hook_ref_)) {
    return false;
  }

  // Add the static basic-block frequency data.
  if (!ApplyBlockGraphTransform(
          &add_frequency_data_, policy, block_graph, header_block)) {
    LOG(ERROR) << "Failed to insert basic-block frequency data.";
    return false;
  }

  return true;
}

bool BranchHookTransform::OnBlock(const TransformPolicyInterface* policy,
                                  BlockGraph* block_graph,
                                  BlockGraph::Block* block) {
  DCHECK(block_graph != NULL);
  DCHECK(block != NULL);

  // Ignore non-decomposable blocks.
  if (!policy->BlockIsSafeToBasicBlockDecompose(block))
    return true;

  if (!ApplyBasicBlockSubGraphTransform(this, policy, block_graph, block, NULL))
    return false;

  return true;
}

bool BranchHookTransform::TransformBasicBlockSubGraph(
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BasicBlockSubGraph* subgraph) {
  DCHECK(policy != NULL);
  DCHECK(block_graph != NULL);
  DCHECK(subgraph != NULL);
  DCHECK(enter_hook_ref_.IsValid());
  DCHECK(exit_hook_ref_.IsValid());
  DCHECK(add_frequency_data_.frequency_data_block() != NULL);

  // Determine whether we must pass the module_data pointer to the hooks.
  bool need_module_data = true;
  if (fs_slot_ != 0)
    need_module_data = false;

  BlockDescriptionList& descriptions = subgraph->block_descriptions();
  BlockDescriptionList::iterator description = descriptions.begin();
  for (; description != descriptions.end(); ++description) {
    BasicBlockSubGraph::BasicBlockOrdering& original_order =
        (*description).basic_block_order;

    // Get the first basic block of this ordering.
    DCHECK(!original_order.empty());
    BasicCodeBlock* first_bb = BasicCodeBlock::Cast(*original_order.begin());
    DCHECK(first_bb != NULL);

    // Insert a call to the basic-block entry hook at the beginning and the end
    // of each code basic-block.
    BasicBlockSubGraph::BasicBlockOrdering::const_iterator it =
      original_order.begin();
    for (; it != original_order.end(); ++it) {
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

      // We use the index in the bb_ranges vector of the current basic-block
      // range as the basic_block_id, and we pass a pointer to the frequency
      // data block as the module_data parameter. We then make a memory indirect
      // call to the bb_entry_hook.
      Immediate basic_block_id(bb_ranges_.size(), core::kSize32Bit);
      Immediate module_data(add_frequency_data_.frequency_data_block(), 0);

      // Assemble entry hook instrumentation into the instruction stream.
      BlockGraph::Reference* enter_hook_ref = &enter_hook_ref_;
      Operand enter_hook(Displacement(enter_hook_ref->referenced(),
                                      enter_hook_ref->offset()));
      BasicBlockAssembler bb_asm_enter(bb->instructions().begin(),
                                       &bb->instructions());
      bb_asm_enter.push(basic_block_id);
      if (need_module_data)
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
        if (need_module_data)
          bb_asm_exit.push(module_data);
        bb_asm_exit.call(exit_hook);
      }

      // Push the range for the current basic block.
      bb_ranges_.push_back(source_range);
    }

    // Insert a call to the function entry hook at the beginning of the
    // function.
    if (function_enter_hook_ref_.IsValid()) {
      // Assemble function enter hook instrumentation into the instruction
      // stream.
      Immediate module_data(add_frequency_data_.frequency_data_block(), 0);
      Operand func_hook(Displacement(function_enter_hook_ref_.referenced(),
                                     function_enter_hook_ref_.offset()));
      BasicBlockAssembler func_asm_enter(first_bb->instructions().begin(),
                                         &first_bb->instructions());
      func_asm_enter.push(module_data);
      func_asm_enter.call(func_hook);
    }
  }

  return true;
}

bool BranchHookTransform::PostBlockGraphIteration(
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BlockGraph::Block* header_block) {
  DCHECK(policy != NULL);
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

  // Initialized BasicBlock agent specific fields
  block_graph::TypedBlock<BasicBlockIndexedFrequencyData> frequency_data;
  CHECK(frequency_data.Init(0, add_frequency_data_.frequency_data_block()));
  frequency_data->fs_slot = fs_slot_;
  frequency_data->tls_index = TLS_OUT_OF_INDEXES;

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

  if (!ApplyBlockGraphTransform(
          &add_thunks, policy, block_graph, header_block)) {
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
