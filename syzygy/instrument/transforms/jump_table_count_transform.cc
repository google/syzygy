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

#include <limits>

#include "base/logging.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
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
using block_graph::TransformPolicyInterface;
using pe::transforms::PEAddImportsTransform;
using pe::transforms::ImportedModule;

const char kDefaultModuleName[] = "basic_block_entry_client.dll";
const char kJumpTableCaseCounter[] = "_increment_indexed_freq_data";
const char kThunkSuffix[] = "_jump_table_thunk";

// Sets up the jump table counter hook import.
// @param policy The policy object restricting how the transform is applied.
// @param block_graph The block-graph to populate.
// @param header_block The header block from block_graph.
// @param module_name The name of the module implementing the hooks.
// @param jump_table_case_counter will refer to the imported hook function.
// @returns true on success, false otherwise.
bool SetupCounterHook(const TransformPolicyInterface* policy,
                      BlockGraph* block_graph,
                      BlockGraph::Block* header_block,
                      const std::string& module_name,
                      BlockGraph::Reference* jump_table_case_counter) {
  DCHECK(block_graph != NULL);
  DCHECK(header_block != NULL);
  DCHECK(jump_table_case_counter != NULL);

  // Setup the import module.
  ImportedModule module(module_name);
  size_t index_case_counter = module.AddSymbol(
      kJumpTableCaseCounter,
      ImportedModule::kAlwaysImport);

  // Setup the add-imports transform.
  PEAddImportsTransform add_imports;
  add_imports.AddModule(&module);

  // Add the imports to the block-graph.
  if (!ApplyBlockGraphTransform(
          &add_imports, policy, block_graph, header_block)) {
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
    : add_frequency_data_(common::kJumpTableCountAgentId,
                          "Jump Table Frequency Data",
                          common::kJumpTableFrequencyDataVersion,
                          common::IndexedFrequencyData::JUMP_TABLE,
                          sizeof(common::IndexedFrequencyData)),
      instrument_dll_name_(kDefaultModuleName),
      jump_table_case_count_(0) {
}

bool JumpTableCaseCountTransform::PreBlockGraphIteration(
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BlockGraph::Block* header_block) {
  DCHECK_NE(reinterpret_cast<TransformPolicyInterface*>(NULL), policy);
  DCHECK_NE(reinterpret_cast<BlockGraph*>(NULL), block_graph);
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), header_block);
  DCHECK_EQ(BlockGraph::PE_IMAGE, block_graph->image_format());

  // Setup the jump table counter entry hook.
  if (!SetupCounterHook(policy,
                        block_graph,
                        header_block,
                        instrument_dll_name_,
                        &jump_table_case_counter_hook_ref_)) {
    return false;
  }

  // Add the static jump table count frequency data.
  if (!ApplyBlockGraphTransform(&add_frequency_data_,
                                policy,
                                block_graph,
                                header_block)) {
    LOG(ERROR) << "Failed to insert jump table count frequency data.";
    return false;
  }

  // Find or create the section we put our thunks in.
  thunk_section_ = block_graph->FindOrAddSection(common::kThunkSectionName,
                                                 pe::kCodeCharacteristics);
  DCHECK(thunk_section_ != NULL);

  return true;
}

bool JumpTableCaseCountTransform::OnBlock(
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BlockGraph::Block* block) {
  DCHECK(policy != NULL);
  DCHECK(block_graph != NULL);
  DCHECK(block != NULL);

  if (block->type() != BlockGraph::CODE_BLOCK)
    return true;

  // Iterate over the labels of the block to find the jump tables.
  for (BlockGraph::Block::LabelMap::const_iterator iter_label(
           block->labels().begin());
      iter_label != block->labels().end();
      ++iter_label) {
    if (!iter_label->second.has_attributes(BlockGraph::JUMP_TABLE_LABEL))
      continue;

    size_t table_size = 0;
    if (!block_graph::GetJumpTableSize(block, iter_label, &table_size))
      return false;

    jump_table_infos_.push_back(
        std::make_pair(block->addr() + iter_label->first, table_size));

    BlockGraph::Block::ReferenceMap::const_iterator iter_ref =
        block->references().find(iter_label->first);

    // Iterate over the references and thunk them.
    for (size_t i = 0; i < table_size; ++i) {
      DCHECK(iter_ref != block->references().end());

      BlockGraph::Block* thunk_block = CreateOneThunk(block_graph,
                                                      iter_ref->second);
      if (thunk_block == NULL) {
        jump_table_infos_.pop_back();
        return false;
      }

      BlockGraph::Reference thunk_ref(BlockGraph::ABSOLUTE_REF,
                                      sizeof(iter_ref->second.size()),
                                      thunk_block, 0, 0);
      block->SetReference(iter_ref->first, thunk_ref);
      ++iter_ref;
    }
  }

  return true;
}

bool JumpTableCaseCountTransform::PostBlockGraphIteration(
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BlockGraph::Block* header_block) {
  DCHECK(policy != NULL);
  DCHECK(block_graph != NULL);
  DCHECK(header_block != NULL);

  if (jump_table_case_count_ == 0) {
    LOG(INFO) << "Encountered no jump tables during instrumentation.";
    return true;
  }

  if (!add_frequency_data_.ConfigureFrequencyDataBuffer(jump_table_case_count_,
                                                        1,
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

  if (!ApplyBlockGraphTransform(
          &add_thunks, policy, block_graph, header_block)) {
    LOG(ERROR) << "Unable to thunk module entry points.";
    return false;
  }

  return true;
}

BlockGraph::Block* JumpTableCaseCountTransform::CreateOneThunk(
    BlockGraph* block_graph,
    const BlockGraph::Reference& destination) {
  // Construct the name for the new thunk.
  std::string thunk_name(destination.referenced()->name() + kThunkSuffix);

  Operand jump_table_case_counter_hook(
      Displacement(jump_table_case_counter_hook_ref_.referenced(),
                   jump_table_case_counter_hook_ref_.offset()));

  // Construct the thunk basic block.
  BasicBlockSubGraph bbsg;
  BasicBlockSubGraph::BlockDescription* block_desc = bbsg.AddBlockDescription(
      thunk_name,
      NULL,
      BlockGraph::CODE_BLOCK,
      thunk_section_->id(),
      1,
      0);
  BasicCodeBlock* bb = bbsg.AddBasicCodeBlock(thunk_name);
  block_desc->basic_block_order.push_back(bb);

  BasicBlockAssembler assm(bb->instructions().begin(), &bb->instructions());
  DCHECK_LT(jump_table_case_count_, std::numeric_limits<size_t>::max());
  assm.push(Immediate(jump_table_case_count_++, core::kSize32Bit));
  assm.call(jump_table_case_counter_hook);
  assm.jmp(Immediate(destination.referenced(), destination.offset()));

  // Condense into a block.
  BlockBuilder block_builder(block_graph);
  if (!block_builder.Merge(&bbsg)) {
    LOG(ERROR) << "Failed to build thunk block.";
    return NULL;
  }

  // Exactly one new block should have been created.
  DCHECK_EQ(1u, block_builder.new_blocks().size());
  return block_builder.new_blocks().front();
}

}  // namespace transforms
}  // namespace instrument
