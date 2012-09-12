// Copyright 2012 Google Inc. All Rights Reserved.
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
// Basic-block entry hook instrumentation transform unit-tests.

#include "syzygy/instrument/transforms/basic_block_entry_hook_transform.h"

#include "gtest/gtest.h"
#include "syzygy/block_graph/basic_block.h"
#include "syzygy/block_graph/basic_block_decomposer.h"
#include "syzygy/block_graph/basic_block_subgraph.h"
#include "syzygy/block_graph/block_graph.h"
#include "syzygy/block_graph/typed_block.h"
#include "syzygy/common/basic_block_frequency_data.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/instrument/transforms/unittest_util.h"
#include "syzygy/pe/block_util.h"
#include "syzygy/pe/unittest_util.h"

#include "mnemonics.h"  // NOLINT

namespace instrument {
namespace transforms {
namespace {

using block_graph::BasicBlock;
using block_graph::BasicBlockDecomposer;
using block_graph::BasicBlockSubGraph;
using block_graph::BlockGraph;
using block_graph::Instruction;
using common::BasicBlockFrequencyData;
using common::kBasicBlockEntryAgentId;
using common::kBasicBlockFrequencyDataVersion;

class TestBasicBlockEntryHookTransform : public BasicBlockEntryHookTransform {
 public:
  using BasicBlockEntryHookTransform::bb_entry_hook_ref_;
  using BasicBlockEntryHookTransform::thunk_section_;

  BlockGraph::Block* frequency_data_block() {
    return add_frequency_data_.frequency_data_block();
  }
};

typedef testing::TestDllTransformTest BasicBlockEntryHookTransformTest;

}  // namespace

TEST_F(BasicBlockEntryHookTransformTest, Apply) {
  ASSERT_NO_FATAL_FAILURE(DecomposeTestDll());

  // Apply the transform.
  TestBasicBlockEntryHookTransform tx;
  tx.set_src_ranges_for_thunks(true);
  ASSERT_TRUE(block_graph::ApplyBlockGraphTransform(&tx, &block_graph_,
                                                    dos_header_block_));
  ASSERT_TRUE(tx.frequency_data_block() != NULL);
  ASSERT_TRUE(tx.thunk_section_ != NULL);
  ASSERT_TRUE(tx.bb_entry_hook_ref_.IsValid());
  ASSERT_LT(0u, tx.bb_ranges().size());

  // Validate the basic-block frequency data structure.
  block_graph::ConstTypedBlock<BasicBlockFrequencyData> frequency_data;
  ASSERT_TRUE(frequency_data.Init(0, tx.frequency_data_block()));
  EXPECT_EQ(kBasicBlockEntryAgentId, frequency_data->agent_id);
  EXPECT_EQ(kBasicBlockFrequencyDataVersion, frequency_data->version);
  EXPECT_EQ(tx.bb_ranges().size(), frequency_data->num_basic_blocks);
  EXPECT_EQ(sizeof(uint32), frequency_data->frequency_size);
  EXPECT_TRUE(
      frequency_data.HasReferenceAt(
          frequency_data.OffsetOf(frequency_data->frequency_data)));
  EXPECT_EQ(
      sizeof(BasicBlockFrequencyData) +
          (frequency_data->num_basic_blocks * frequency_data->frequency_size),
      tx.frequency_data_block()->size());

  // Let's examine each eligible block to verify that its BB's have been
  // instrumented.
  size_t num_decomposed_blocks = 0;
  size_t total_basic_blocks = 0;
  BlockGraph::BlockMap::const_iterator block_iter =
      block_graph_.blocks().begin();
  for (; block_iter != block_graph_.blocks().end(); ++block_iter) {
    const BlockGraph::Block& block = block_iter->second;

    // Skip ineligible blocks.
    if (block.type() != BlockGraph::CODE_BLOCK)
      continue;
    if (!pe::CodeBlockIsBasicBlockDecomposable(&block))
      continue;
    if (block.section() == tx.thunk_section_->id())
      continue;

    // Note that we have attempted to validate a block.
    ++num_decomposed_blocks;

    // Decompose the block to basic-blocks.
    BasicBlockSubGraph subgraph;
    BasicBlockDecomposer bb_decomposer(&block, &subgraph);
    ASSERT_TRUE(bb_decomposer.Decompose());

    // Check if each basic block begins with the instrumentation sequence.
    size_t num_basic_blocks = 0;
    BasicBlockSubGraph::BBCollection::const_iterator bb_iter =
        subgraph.basic_blocks().begin();
    for (; bb_iter != subgraph.basic_blocks().end(); ++bb_iter) {
      const BasicBlock& bb = bb_iter->second;
      if (bb.type() != BasicBlock::BASIC_CODE_BLOCK)
        continue;
      ++num_basic_blocks;
      ASSERT_LE(3U, bb.instructions().size());
      BasicBlock::Instructions::const_iterator inst_iter =
          bb.instructions().begin();

      // Instruction 1 should push the basic block id.
      const Instruction& inst1 = *inst_iter;
      EXPECT_EQ(I_PUSH, inst1.representation().opcode);

      // Instruction 2 should push the frequency data block pointer.
      const Instruction& inst2 = *(++inst_iter);
      EXPECT_EQ(I_PUSH, inst2.representation().opcode);
      ASSERT_EQ(1U, inst2.references().size());
      EXPECT_EQ(tx.frequency_data_block(),
                inst2.references().begin()->second.block());

      // Instruction 3 should be a call to the bb entry hook.
      const Instruction& inst3 = *(++inst_iter);
      EXPECT_EQ(I_CALL, inst3.representation().opcode);
      ASSERT_EQ(1U, inst3.references().size());
      EXPECT_EQ(tx.bb_entry_hook_ref_.referenced(),
                inst3.references().begin()->second.block());
    }
    EXPECT_NE(0U, num_basic_blocks);
    total_basic_blocks += num_basic_blocks;
  }

  EXPECT_NE(0U, num_decomposed_blocks);
  EXPECT_EQ(total_basic_blocks, tx.bb_ranges().size());
}

}  // namespace transforms
}  // namespace instrument
