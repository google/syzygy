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
// Jump table case count instrumentation transform unit-tests.

#include "syzygy/instrument/transforms/jump_table_count_transform.h"

#include "gtest/gtest.h"
#include "syzygy/block_graph/basic_block.h"
#include "syzygy/block_graph/basic_block_decomposer.h"
#include "syzygy/block_graph/basic_block_subgraph.h"
#include "syzygy/block_graph/block_graph.h"
#include "syzygy/block_graph/block_util.h"
#include "syzygy/block_graph/typed_block.h"
#include "syzygy/common/indexed_frequency_data.h"
#include "syzygy/instrument/transforms/unittest_util.h"

#include "mnemonics.h"  // NOLINT

namespace instrument {
namespace transforms {

namespace {

using block_graph::BasicBlock;
using block_graph::BasicCodeBlock;
using block_graph::BasicBlockDecomposer;
using block_graph::BasicBlockSubGraph;
using block_graph::BlockGraph;
using block_graph::Instruction;
using common::IndexedFrequencyData;

class TestJumpTableCaseCountTransform : public JumpTableCaseCountTransform {
 public:
  using JumpTableCaseCountTransform::add_frequency_data;
  using JumpTableCaseCountTransform::jump_table_case_counter_hook_ref;
  using JumpTableCaseCountTransform::thunk_section;

  BlockGraph::Block* frequency_data_block() {
    return add_frequency_data()->frequency_data_block();
  }

  BlockGraph::Block* frequency_data_buffer_block() {
    return add_frequency_data()->frequency_data_buffer_block();
  }
};

typedef testing::TestDllTransformTest JumpTableCaseCountTransformTest;

// Ensures that the @p block is a jump table case count thunk.
void CheckBlockIsAThunk(BlockGraph::Block* block) {
  // Decompose the block to basic-blocks.
  BasicBlockSubGraph subgraph;
  BasicBlockDecomposer bb_decomposer(block, &subgraph);
  ASSERT_TRUE(bb_decomposer.Decompose());

  ASSERT_EQ(1, subgraph.basic_blocks().size());
  const BasicCodeBlock* bb = BasicCodeBlock::Cast(
      *subgraph.basic_blocks().begin());
  ASSERT_TRUE(bb != NULL);
  ASSERT_FALSE(bb->is_padding());

  ASSERT_EQ(2U, bb->instructions().size());
  BasicBlock::Instructions::const_iterator inst_iter =
      bb->instructions().begin();

  // Instruction 1 should push the case id.
  EXPECT_EQ(I_PUSH, inst_iter->representation().opcode);

  // Instruction 2 should call the jump table counter hook.
  ++inst_iter;
  EXPECT_EQ(I_CALL, inst_iter->representation().opcode);
}

}  // namespace

TEST_F(JumpTableCaseCountTransformTest, Apply) {
  ASSERT_NO_FATAL_FAILURE(DecomposeTestDll());

  // Apply the transform.
  TestJumpTableCaseCountTransform tx;
  ASSERT_TRUE(block_graph::ApplyBlockGraphTransform(
      &tx, &policy_, &block_graph_, dos_header_block_));
  ASSERT_TRUE(tx.frequency_data_block() != NULL);
  ASSERT_TRUE(tx.thunk_section() != NULL);
  ASSERT_TRUE(tx.jump_table_case_counter_hook_ref() != NULL);
  ASSERT_TRUE(tx.jump_table_case_counter_hook_ref()->IsValid());

  // Validate the jump table frequency data structure.
  block_graph::ConstTypedBlock<IndexedFrequencyData> frequency_data;
  ASSERT_TRUE(frequency_data.Init(0, tx.frequency_data_block()));
  EXPECT_EQ(sizeof(uint32), frequency_data->frequency_size);
  EXPECT_EQ(common::kJumpTableCountAgentId, frequency_data->agent_id);
  EXPECT_EQ(common::kJumpTableFrequencyDataVersion, frequency_data->version);
  EXPECT_EQ(IndexedFrequencyData::JUMP_TABLE, frequency_data->data_type);
  EXPECT_EQ(sizeof(IndexedFrequencyData), tx.frequency_data_block()->size());
  EXPECT_EQ(sizeof(IndexedFrequencyData),
            tx.frequency_data_block()->data_size());
  EXPECT_TRUE(frequency_data.HasReferenceAt(
      frequency_data.OffsetOf(frequency_data->frequency_data)));
  BlockGraph::Reference frequency_data_reference;
  ASSERT_TRUE(frequency_data.block()->GetReference(
      frequency_data.OffsetOf(frequency_data->frequency_data),
      &frequency_data_reference));
  EXPECT_EQ(frequency_data_reference.referenced(),
            tx.frequency_data_buffer_block());
  EXPECT_EQ(frequency_data->num_entries * frequency_data->frequency_size,
            tx.frequency_data_buffer_block()->size());

  // Examine each eligible block to verify that all the jump tables have
  // been instrumented.
  size_t jump_table_entries = 0;
  for (BlockGraph::BlockMap::const_iterator block_iter(
           block_graph_.blocks().begin());
      block_iter != block_graph_.blocks().end();
      ++block_iter) {
    const BlockGraph::Block& block = block_iter->second;

    // Skip non-code blocks.
    if (block.type() != BlockGraph::CODE_BLOCK)
      continue;

    // We don't want to check the thunk blocks.
    if (block.section() == tx.thunk_section()->id())
      continue;

    // Iterate over the labels to find the jump tables.
    for (BlockGraph::Block::LabelMap::const_iterator iter_label(
             block.labels().begin());
        iter_label != block.labels().end();
        ++iter_label) {
      if (!iter_label->second.has_attributes(BlockGraph::JUMP_TABLE_LABEL))
        continue;

      size_t table_size = 0;
      ASSERT_TRUE(
          block_graph::GetJumpTableSize(&block, iter_label, &table_size));

      BlockGraph::Block::ReferenceMap::const_iterator iter_ref =
          block.references().find(iter_label->first);
      ASSERT_TRUE(iter_ref != block.references().end());

      // Iterate over the references and ensure that they are thunked.
      for (size_t i = 0; i < table_size; ++i) {
        BlockGraph::Block* ref_block = iter_ref->second.referenced();
        CheckBlockIsAThunk(ref_block);
        ++iter_ref;
      }

      jump_table_entries += table_size;
    }
  }
  DCHECK_EQ(frequency_data->num_entries, jump_table_entries);
}

}  // namespace transforms
}  // namespace instrument
