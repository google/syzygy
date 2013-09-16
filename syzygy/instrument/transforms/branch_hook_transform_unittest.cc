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
// Branch hook instrumentation transform unit-tests.

#include "syzygy/instrument/transforms/branch_hook_transform.h"

#include "gtest/gtest.h"
#include "syzygy/block_graph/basic_block.h"
#include "syzygy/block_graph/basic_block_decomposer.h"
#include "syzygy/block_graph/basic_block_subgraph.h"
#include "syzygy/block_graph/block_graph.h"
#include "syzygy/block_graph/typed_block.h"
#include "syzygy/common/indexed_frequency_data.h"
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
using block_graph::BasicCodeBlock;
using block_graph::BlockGraph;
using block_graph::Instruction;
using common::IndexedFrequencyData;
using common::kBasicBlockEntryAgentId;
using common::kBasicBlockFrequencyDataVersion;

class TestBranchHookTransform : public BranchHookTransform {
 public:
  using BranchHookTransform::enter_hook_ref_;
  using BranchHookTransform::enter_buffered_hook_ref_;
  using BranchHookTransform::exit_hook_ref_;
  using BranchHookTransform::thunk_section_;

  BlockGraph::Block* frequency_data_block() {
    return add_frequency_data_.frequency_data_block();
  }

  BlockGraph::Block* frequency_data_buffer_block() {
    return add_frequency_data_.frequency_data_buffer_block();
  }
};

class BranchHookTransformTest : public testing::TestDllTransformTest {
 public:
  enum InstrumentationKind {
    kBasicInstrumentation,
    kBufferedInstrumentation
  };

  void CheckBasicBlockInstrumentation(InstrumentationKind mode);

 protected:
  TestBranchHookTransform tx_;
};

void BranchHookTransformTest::CheckBasicBlockInstrumentation(
    InstrumentationKind mode) {
  // Let's examine each eligible block to verify that its basic blocks have been
  // instrumented.
  BlockGraph::BlockMap::const_iterator block_iter =
      block_graph_.blocks().begin();
  for (; block_iter != block_graph_.blocks().end(); ++block_iter) {
    const BlockGraph::Block& block = block_iter->second;

    // Skip non-code blocks.
    if (block.type() != BlockGraph::CODE_BLOCK)
      continue;

    // We'll skip thunks, they're a mixed bag of things.
    if (block.section() == tx_.thunk_section_->id())
      continue;

    // Skip non-decomposable.
    if (!pe::CodeBlockIsBasicBlockDecomposable(&block))
      continue;

    // Decompose the block to basic-blocks.
    BasicBlockSubGraph subgraph;
    BasicBlockDecomposer bb_decomposer(&block, &subgraph);
    ASSERT_TRUE(bb_decomposer.Decompose());

    // Check if each non-padding basic code-block begins with the
    // instrumentation sequence.
    BasicBlockSubGraph::BBCollection::const_iterator bb_iter =
        subgraph.basic_blocks().begin();
    for (; bb_iter != subgraph.basic_blocks().end(); ++bb_iter) {
      const BasicCodeBlock* bb = BasicCodeBlock::Cast(*bb_iter);
      if (bb == NULL || bb->is_padding())
        continue;

      // Check entry hook function call.
      BasicBlock::Instructions::const_iterator inst_iter =
          bb->instructions().begin();
      ASSERT_TRUE(inst_iter != bb->instructions().end());

      // Instruction 1 should push the basic block id.
      const Instruction& inst1 = *inst_iter;
      EXPECT_EQ(I_PUSH, inst1.representation().opcode);
      ASSERT_TRUE(++inst_iter != bb->instructions().end());

      // Instruction 2 should push the frequency data block pointer.
      const Instruction& inst2 = *inst_iter;
      EXPECT_EQ(I_PUSH, inst2.representation().opcode);
      ASSERT_EQ(1U, inst2.references().size());
      EXPECT_EQ(tx_.frequency_data_block(),
                inst2.references().begin()->second.block());
      ASSERT_TRUE(++inst_iter != bb->instructions().end());

      // Instruction 3 should be a call to the enter hook.
      const Instruction& inst3 = *inst_iter;
      EXPECT_EQ(I_CALL, inst3.representation().opcode);
      ASSERT_EQ(1U, inst3.references().size());
      if (mode == kBasicInstrumentation) {
        EXPECT_EQ(tx_.enter_hook_ref_.referenced(),
                  inst3.references().begin()->second.block());
      } else if (mode == kBufferedInstrumentation) {
        EXPECT_EQ(tx_.enter_buffered_hook_ref_.referenced(),
                  inst3.references().begin()->second.block());
      } else {
        NOTREACHED();
      }
      ASSERT_TRUE(++inst_iter != bb->instructions().end());

      // Check exit hook function call.
      BasicBlock::Instructions::const_reverse_iterator rev_inst_iter =
          bb->instructions().rbegin();
      ASSERT_TRUE(rev_inst_iter != bb->instructions().rend());

      // Find last non branching instruction.
      for (; rev_inst_iter != bb->instructions().rend(); ++rev_inst_iter) {
        if (!rev_inst_iter->IsBranch() && !rev_inst_iter->IsReturn())
          break;
      }
      ASSERT_TRUE(rev_inst_iter != bb->instructions().rend());

      // Skip non returning basic block.
      if (rev_inst_iter->CallsNonReturningFunction())
        continue;

      // Instruction 3 should be a call to the exit hook.
      const Instruction& rev_inst3 = *rev_inst_iter;
      EXPECT_EQ(I_CALL, rev_inst3.representation().opcode);
      ASSERT_EQ(1U, rev_inst3.references().size());
      EXPECT_EQ(tx_.enter_hook_ref_.referenced(),
                rev_inst3.references().begin()->second.block());
      ASSERT_TRUE(++rev_inst_iter != bb->instructions().rend());

      // Instruction 2 should push the frequency data block pointer.
      const Instruction& rev_inst2 = *rev_inst_iter;
      EXPECT_EQ(I_PUSH, rev_inst2.representation().opcode);
      ASSERT_EQ(1U, rev_inst2.references().size());
      EXPECT_EQ(tx_.frequency_data_block(),
                rev_inst2.references().begin()->second.block());
      ASSERT_TRUE(++rev_inst_iter != bb->instructions().rend());

      // Instruction 1 should push the basic block id.
      const Instruction& rev_inst1 = *rev_inst_iter;
      EXPECT_EQ(I_PUSH, rev_inst1.representation().opcode);
      ASSERT_TRUE(++rev_inst_iter != bb->instructions().rend());
    }
  }
}

}  // namespace

TEST_F(BranchHookTransformTest, ApplyAgentInstrumentation) {
  ASSERT_NO_FATAL_FAILURE(DecomposeTestDll());

  // Apply the transform.
  ASSERT_TRUE(block_graph::ApplyBlockGraphTransform(&tx_, &block_graph_,
                                                    dos_header_block_));
  ASSERT_TRUE(tx_.frequency_data_block() != NULL);
  ASSERT_TRUE(tx_.enter_hook_ref_.IsValid());
  ASSERT_TRUE(tx_.exit_hook_ref_.IsValid());
  ASSERT_LT(0u, tx_.bb_ranges().size());

  // Validate the basic-block frequency data structure.
  block_graph::ConstTypedBlock<IndexedFrequencyData> frequency_data;
  ASSERT_TRUE(frequency_data.Init(0, tx_.frequency_data_block()));
  EXPECT_EQ(kBasicBlockEntryAgentId, frequency_data->agent_id);
  EXPECT_EQ(kBasicBlockFrequencyDataVersion, frequency_data->version);
  EXPECT_EQ(IndexedFrequencyData::BRANCH, frequency_data->data_type);
  EXPECT_EQ(tx_.bb_ranges().size(), frequency_data->num_entries);
  EXPECT_EQ(3U, frequency_data->num_columns);
  EXPECT_EQ(sizeof(uint32), frequency_data->frequency_size);
  EXPECT_TRUE(frequency_data.HasReferenceAt(
      frequency_data.OffsetOf(frequency_data->frequency_data)));
  EXPECT_EQ(sizeof(IndexedFrequencyData), tx_.frequency_data_block()->size());
  EXPECT_EQ(sizeof(IndexedFrequencyData),
            tx_.frequency_data_block()->data_size());

  uint32 expected_size = frequency_data->num_entries *
      frequency_data->num_columns * frequency_data->frequency_size;
  EXPECT_EQ(expected_size, tx_.frequency_data_buffer_block()->size());

  // Validate that all basic blocks have been instrumented.
  ASSERT_NO_FATAL_FAILURE(
      CheckBasicBlockInstrumentation(kBasicInstrumentation));
}

TEST_F(BranchHookTransformTest, ApplyBufferedAgentInstrumentation) {
  ASSERT_NO_FATAL_FAILURE(DecomposeTestDll());

  // Activate buffering.
  tx_.set_buffering(true);

  // Apply the transform.
  ASSERT_TRUE(block_graph::ApplyBlockGraphTransform(&tx_, &block_graph_,
                                                    dos_header_block_));
  ASSERT_TRUE(tx_.enter_buffered_hook_ref_.IsValid());

  // Validate that all basic blocks have been instrumented.
  ASSERT_NO_FATAL_FAILURE(
      CheckBasicBlockInstrumentation(kBufferedInstrumentation));
}

}  // namespace transforms
}  // namespace instrument
