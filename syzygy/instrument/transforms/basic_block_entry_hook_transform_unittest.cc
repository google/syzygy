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
#include "syzygy/agent/basic_block_entry/basic_block_entry.h"
#include "syzygy/block_graph/basic_block.h"
#include "syzygy/block_graph/basic_block_decomposer.h"
#include "syzygy/block_graph/basic_block_subgraph.h"
#include "syzygy/block_graph/block_graph.h"
#include "syzygy/block_graph/typed_block.h"
#include "syzygy/common/indexed_frequency_data.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/instrument/transforms/unittest_util.h"
#include "syzygy/pe/unittest_util.h"

#include "mnemonics.h"  // NOLINT

namespace instrument {
namespace transforms {
namespace {

using agent::basic_block_entry::BasicBlockEntry;
using block_graph::BasicBlock;
using block_graph::BasicBlockDecomposer;
using block_graph::BasicBlockSubGraph;
using block_graph::BasicCodeBlock;
using block_graph::BlockGraph;
using block_graph::Instruction;
using common::IndexedFrequencyData;
using common::kBasicBlockEntryAgentId;
using common::kBasicBlockFrequencyDataVersion;

typedef BasicBlockEntry::BasicBlockIndexedFrequencyData
   BasicBlockIndexedFrequencyData;

class TestBasicBlockEntryHookTransform : public BasicBlockEntryHookTransform {
 public:
  using BasicBlockEntryHookTransform::bb_entry_hook_ref_;
  using BasicBlockEntryHookTransform::thunk_section_;

  BlockGraph::Block* frequency_data_block() {
    return add_frequency_data_.frequency_data_block();
  }

  BlockGraph::Block* frequency_data_buffer_block() {
    return add_frequency_data_.frequency_data_buffer_block();
  }
};

class BasicBlockEntryHookTransformTest : public testing::TestDllTransformTest {
 public:
  enum InstrumentationKind {
    kAgentInstrumentation,
    kFastPathInstrumentation
  };

  void CheckBasicBlockInstrumentation(InstrumentationKind kind);

 protected:
  TestBasicBlockEntryHookTransform tx_;
};

void BasicBlockEntryHookTransformTest::CheckBasicBlockInstrumentation(
    InstrumentationKind kind) {
  // Let's examine each eligible block to verify that its basic blocks have been
  // instrumented.
  size_t num_decomposed_blocks = 0;
  size_t total_basic_blocks = 0;
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

    // Blocks which are not bb-decomposable should be thunked. While there may
    // be some internal referrers, the only external referrers should be thunks.
    if (!policy_->BlockIsSafeToBasicBlockDecompose(&block)) {
      size_t num_external_thunks = 0;
      BlockGraph::Block::ReferrerSet::const_iterator ref_iter =
          block.referrers().begin();
      for (; ref_iter != block.referrers().end(); ++ref_iter) {
        if (ref_iter->first != &block) {
          ASSERT_EQ(tx_.thunk_section_->id(), ref_iter->first->section());
          ++num_external_thunks;
        }
      }

      // Each of the thunks for a non-decomposable block will reuse the same
      // id to source range map entry, so we increment total_basic_blocks once
      // if num_external_thunks is non-zero. Note that we cannot assert that
      // num_external_thunks > 0 because the block could be statically dead
      // (in a debug build, for example).
      if (num_external_thunks != 0U)
        ++total_basic_blocks;
      continue;
    }

    // Note that we have attempted to validate a block.
    ++num_decomposed_blocks;

    // Decompose the block to basic-blocks.
    BasicBlockSubGraph subgraph;
    BasicBlockDecomposer bb_decomposer(&block, &subgraph);
    ASSERT_TRUE(bb_decomposer.Decompose());

    // Check if each non-padding basic code-block begins with the
    // instrumentation sequence.
    size_t num_basic_blocks = 0;
    BasicBlockSubGraph::BBCollection::const_iterator bb_iter =
        subgraph.basic_blocks().begin();
    for (; bb_iter != subgraph.basic_blocks().end(); ++bb_iter) {
      const BasicCodeBlock* bb = BasicCodeBlock::Cast(*bb_iter);
      if (bb == NULL || bb->is_padding())
        continue;
      ++num_basic_blocks;

      if (kind == kAgentInstrumentation) {
        ASSERT_LE(3U, bb->instructions().size());
        BasicBlock::Instructions::const_iterator inst_iter =
            bb->instructions().begin();

        // Instruction 1 should push the basic block id.
        const Instruction& inst1 = *inst_iter;
        EXPECT_EQ(I_PUSH, inst1.representation().opcode);

        // Instruction 2 should push the frequency data block pointer.
        const Instruction& inst2 = *(++inst_iter);
        EXPECT_EQ(I_PUSH, inst2.representation().opcode);
        ASSERT_EQ(1U, inst2.references().size());
        EXPECT_EQ(tx_.frequency_data_block(),
                  inst2.references().begin()->second.block());

        // Instruction 3 should be a call to the bb entry hook.
        const Instruction& inst3 = *(++inst_iter);
        EXPECT_EQ(I_CALL, inst3.representation().opcode);
        ASSERT_EQ(1U, inst3.references().size());
        EXPECT_EQ(tx_.bb_entry_hook_ref_.referenced(),
                  inst3.references().begin()->second.block());
      } else {
        DCHECK(kind == kFastPathInstrumentation);
        ASSERT_LE(2U, bb->instructions().size());
        BasicBlock::Instructions::const_iterator inst_iter =
            bb->instructions().begin();

        // Instruction 1 should push the basic block id.
        const Instruction& inst1 = *inst_iter;
        EXPECT_EQ(I_PUSH, inst1.representation().opcode);

        // Instruction 2 should be a call to the fast bb entry hook.
        const Instruction& inst2 = *(++inst_iter);
        EXPECT_EQ(I_CALL, inst2.representation().opcode);
        ASSERT_EQ(1U, inst2.references().size());
      }
    }
    EXPECT_NE(0U, num_basic_blocks);
    total_basic_blocks += num_basic_blocks;
  }

  EXPECT_NE(0U, num_decomposed_blocks);
  EXPECT_EQ(total_basic_blocks, tx_.bb_ranges().size());
}

}  // namespace

TEST_F(BasicBlockEntryHookTransformTest, SetInlinePathFlag) {
  EXPECT_FALSE(tx_.inline_fast_path());
  tx_.set_inline_fast_path(true);
  EXPECT_TRUE(tx_.inline_fast_path());
  tx_.set_inline_fast_path(false);
  EXPECT_FALSE(tx_.inline_fast_path());
}

TEST_F(BasicBlockEntryHookTransformTest, ApplyAgentInstrumentation) {
  ASSERT_NO_FATAL_FAILURE(DecomposeTestDll());

  // Apply the transform.
  tx_.set_src_ranges_for_thunks(true);
  ASSERT_TRUE(block_graph::ApplyBlockGraphTransform(
      &tx_, policy_, &block_graph_, header_block_));
  ASSERT_TRUE(tx_.frequency_data_block() != NULL);
  ASSERT_TRUE(tx_.thunk_section_ != NULL);
  ASSERT_TRUE(tx_.bb_entry_hook_ref_.IsValid());
  ASSERT_LT(0u, tx_.bb_ranges().size());

  // Validate the basic-block frequency data structure.
  block_graph::ConstTypedBlock<IndexedFrequencyData> frequency_data;
  ASSERT_TRUE(frequency_data.Init(0, tx_.frequency_data_block()));
  EXPECT_EQ(kBasicBlockEntryAgentId, frequency_data->agent_id);
  EXPECT_EQ(kBasicBlockFrequencyDataVersion, frequency_data->version);
  EXPECT_EQ(IndexedFrequencyData::BASIC_BLOCK_ENTRY, frequency_data->data_type);
  EXPECT_EQ(tx_.bb_ranges().size(), frequency_data->num_entries);
  EXPECT_EQ(sizeof(uint32), frequency_data->frequency_size);
  EXPECT_TRUE(frequency_data.HasReferenceAt(
      frequency_data.OffsetOf(frequency_data->frequency_data)));
  EXPECT_EQ(sizeof(BasicBlockIndexedFrequencyData),
            tx_.frequency_data_block()->size());
  EXPECT_EQ(sizeof(BasicBlockIndexedFrequencyData),
            tx_.frequency_data_block()->data_size());
  EXPECT_EQ(frequency_data->num_entries * frequency_data->frequency_size,
            tx_.frequency_data_buffer_block()->size());

  // Validate that all basic block have been instrumented.
  CheckBasicBlockInstrumentation(kAgentInstrumentation);
}

}  // namespace transforms
}  // namespace instrument
