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
// Implements the JumpTableCaseCountTransform class.

#include "syzygy/instrument/transforms/jump_table_count_transform.h"

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
using block_graph::BasicBlockSubGraph;
using block_graph::BasicCodeBlock;
using block_graph::BasicDataBlock;
using block_graph::BasicBlockAssembler;
using block_graph::BasicBlockReference;
using block_graph::BlockBuilder;
using block_graph::BlockGraph;
using block_graph::Displacement;
using block_graph::Immediate;
using block_graph::Instruction;
using block_graph::Operand;
using pe::transforms::AddImportsTransform;

typedef AddImportsTransform::ImportedModule ImportedModule;

const char kDefaultModuleName[] = "jump_table_count.dll";
const char kJumpTableCaseCounter[] = "_jump_table_case_counter";
const char kThunkSuffix[] = "_jump_table_thunk";

// TODO(sebmarchand): Move these constants to a header file, merge with the
//     basic-block constants.
const uint32 kJumpTableCountAgentId = 0x07AB1E0C;
const uint32 kJumpTableFrequencyDataVersion = 1;

// Sets up the jump table counter hook import.
// @param block_graph The block-graph to populate.
// @param header_block The header block from block_graph.
// @param module_name The name of the module implementing the hooks.
// @param jump_table_case_counter will refer to the imported hook function.
// @returns true on success, false otherwise.
bool SetupCounterHook(BlockGraph* block_graph,
                      BlockGraph::Block* header_block,
                      const std::string& module_name,
                      BlockGraph::Reference* jump_table_case_counter) {
  DCHECK(block_graph != NULL);
  DCHECK(header_block != NULL);
  DCHECK(jump_table_case_counter != NULL);
  // Setup the import module.
  ImportedModule module(module_name);
  size_t index_case_counter = module.AddSymbol(kJumpTableCaseCounter,
                                               ImportedModule::kAlwaysImport);

  // Setup the add-imports transform.
  AddImportsTransform add_imports;
  add_imports.AddModule(&module);

  // Add the imports to the block-graph.
  if (!ApplyBlockGraphTransform(&add_imports, block_graph, header_block)) {
    LOG(ERROR) << "Unable to add import entry for jump table hook functions.";
    return false;
  }

  // Get a reference to the hook function.
  if (!module.GetSymbolReference(index_case_counter, jump_table_case_counter)) {
    LOG(ERROR) << "Unable to get jump table hooks.";
    return false;
  }
  DCHECK(jump_table_case_counter->IsValid());

  return true;
}

}  // namespace

const char JumpTableCaseCountTransform::kTransformName[] =
    "JumpTableCountTransform";

JumpTableCaseCountTransform::JumpTableCaseCountTransform()
    : add_frequency_data_(kJumpTableCountAgentId,
                          "Jump Table Frequency Data",
                          kJumpTableFrequencyDataVersion),
      instrument_dll_name_(kDefaultModuleName),
      jump_table_case_count_(0) {
}

bool JumpTableCaseCountTransform::PreBlockGraphIteration(
    BlockGraph* block_graph,
    BlockGraph::Block* header_block) {
  DCHECK(block_graph != NULL);
  DCHECK(header_block != NULL);

  // Setup the jump table counter entry hook.
  if (!SetupCounterHook(block_graph,
                        header_block,
                        instrument_dll_name_,
                        &jump_table_case_counter_hook_ref_)) {
    return false;
  }

  // Add the static jump table count frequency data.
  if (!ApplyBlockGraphTransform(
          &add_frequency_data_, block_graph, header_block)) {
    LOG(ERROR) << "Failed to insert jump table count frequency data.";
    return false;
  }

  // Find or create the section we put our thunks in.
  thunk_section_ = block_graph->FindOrAddSection(common::kThunkSectionName,
                                                 pe::kCodeCharacteristics);
  DCHECK(thunk_section_ != NULL);

  return true;
}

bool JumpTableCaseCountTransform::OnBlock(BlockGraph* block_graph,
                                          BlockGraph::Block* block) {
  DCHECK(block_graph != NULL);
  DCHECK(block != NULL);

  if (block->type() != BlockGraph::CODE_BLOCK)
    return true;

  // Iterates over the labels of the block to find the jump tables.
  BlockGraph::Block::LabelMap::const_iterator iter_label =
      block->labels().begin();
  for (; iter_label != block->labels().end();++iter_label) {
    if (!iter_label->second.has_attributes(BlockGraph::JUMP_TABLE_LABEL))
      continue;

    BlockGraph::Offset current_offset = iter_label->first;
    BlockGraph::Offset jump_table_end_offset = 0;

    // Calculates the end offset of this jump table.
    // TODO(sebmarchand): Move this code to an utility function in the pe
    //     namespace. A jump table is a run of contiguous 32-bit absolute
    //     references terminating when there is no next reference, at the next
    //     data label or the end of the block, whichever comes first.
    BlockGraph::Block::LabelMap::const_iterator next_label = iter_label;
    next_label++;
    if (next_label != block->labels().end())
      jump_table_end_offset = next_label->first;
    else
      jump_table_end_offset = block->size();

    DCHECK(jump_table_end_offset != 0);

    BlockGraph::Block::ReferenceMap::const_iterator iter_ref =
        block->references().find(current_offset);

    size_t table_size =
        (jump_table_end_offset - current_offset) / iter_ref->second.size();
    jump_table_infos_.push_back(std::make_pair(block->addr() + current_offset,
                                               table_size));

    // Iterates over the references and thunk them.
    while (current_offset < jump_table_end_offset) {
      DCHECK(iter_ref != block->references().end());
      DCHECK(iter_ref->first == current_offset);

      BlockGraph::Block* thunk_block = CreateOneThunk(block_graph,
                                                      iter_ref->second);

      if (thunk_block == NULL)
        return false;

      BlockGraph::Reference thunk_ref(BlockGraph::ABSOLUTE_REF,
                                      sizeof(core::AbsoluteAddress),
                                      thunk_block, 0, 0);
      block->SetReference(current_offset, thunk_ref);

      current_offset += iter_ref->second.size();
      iter_ref++;
    }
  }

  return true;
}

bool JumpTableCaseCountTransform::PostBlockGraphIteration(
    BlockGraph* block_graph, BlockGraph::Block* header_block) {
  DCHECK(block_graph != NULL);
  DCHECK(header_block != NULL);

  if (jump_table_case_count_ == 0) {
    LOG(INFO) << "Encountered no jump tables during instrumentation.";
    return true;
  }

  if (!add_frequency_data_.ConfigureFrequencyDataBuffer(jump_table_case_count_,
                                                        sizeof(uint32))) {
    LOG(ERROR) << "Failed to configure frequency data buffer.";
    return false;
  }

  // Add the module entry thunks.
  EntryThunkTransform add_thunks;
  add_thunks.set_only_instrument_module_entry(true);
  add_thunks.set_instrument_dll_name(instrument_dll_name_);

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

  return true;
}

BlockGraph::Block* JumpTableCaseCountTransform::CreateOneThunk(
    BlockGraph* block_graph,
    const BlockGraph::Reference& destination) {

  // Construct the name for the new thunk.
  std::string thunk_name(destination.referenced()->name());
  thunk_name.append(kThunkSuffix);

  Operand jump_table_case_counter_hook(
      Displacement(jump_table_case_counter_hook_ref_.referenced(),
                   jump_table_case_counter_hook_ref_.offset()));

  // Construct the thunk basic block.
  BasicBlockSubGraph bbsg;
  BasicBlockSubGraph::BlockDescription* block_desc = bbsg.AddBlockDescription(
      thunk_name, BlockGraph::CODE_BLOCK, thunk_section_->id(), 1, 0);
  BasicCodeBlock* bb = bbsg.AddBasicCodeBlock(thunk_name);
  block_desc->basic_block_order.push_back(bb);
  BasicBlockAssembler assm(bb->instructions().begin(), &bb->instructions());

  assm.push(Immediate(jump_table_case_count_++, core::kSize32Bit));
  assm.call(jump_table_case_counter_hook);
  // TODO(sebmarchand): Update the basic block assembler to allow a jump to a
  //     PC relative address. Also check if it's faster to use an absolute
  //     reference.
  block_graph::BasicBlockReference ref(BlockGraph::PC_RELATIVE_REF,
                                       BlockGraph::Reference::kMaximumSize,
                                       destination.referenced(),
                                       destination.offset(),
                                       destination.offset());
  assm.jmp(Immediate(Displacement(0, core::kSize32Bit, ref)));

  // Condense into a block.
  BlockBuilder block_builder(block_graph);
  if (!block_builder.Merge(&bbsg)) {
    LOG(ERROR) << "Failed to build thunk block.";
    return NULL;
  }

  // Exactly one new block should have been created.
  DCHECK_EQ(1u, block_builder.new_blocks().size());
  BlockGraph::Block* thunk = block_builder.new_blocks().front();

  return thunk;
}

}  // namespace transforms
}  // namespace instrument
