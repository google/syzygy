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
// Tests for basic block disassembler.

#include "syzygy/block_graph/basic_block_decomposer.h"

#include <algorithm>
#include <vector>

#include "base/bind.h"
#include "base/command_line.h"
#include "base/file_util.h"
#include "base/memory/scoped_ptr.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/block_graph/basic_block_test_util.h"
#include "syzygy/core/address.h"
#include "syzygy/core/unittest_util.h"

#include "mnemonics.h"  // NOLINT

namespace block_graph {

namespace {

using block_graph::BasicBlock;
using block_graph::BasicBlockSubGraph;
using block_graph::BlockGraph;
using block_graph::BlockGraphSerializer;
using block_graph::Successor;
using core::AbsoluteAddress;
using core::Disassembler;
using testing::_;
using testing::BasicBlockTest;
using testing::Return;

typedef BlockGraph::Block Block;
typedef BlockGraph::Offset Offset;
typedef BlockGraph::Reference Reference;
typedef BlockGraph::Size Size;

// A helper to count basic blocks of a given type.
size_t CountBasicBlocks(const BasicBlockSubGraph& subgraph,
                        BasicBlock::BasicBlockType type) {
  size_t counter = 0;
  BasicBlockSubGraph::BBCollection::const_iterator code_it =
      subgraph.basic_blocks().begin();
  for (; code_it != subgraph.basic_blocks().end(); ++code_it) {
    if ((*code_it)->type() == type)
      ++counter;
  }

  return counter;
}

// A helper comparator to that returns true if lhs and rhs are not adjacent
// and in order.
bool HasGapOrIsOutOfOrder(const BasicBlock* lhs, const BasicBlock* rhs) {
  typedef BasicBlock::Size Size;

  Offset lhs_end = lhs->offset();

  const BasicCodeBlock* lhs_code = BasicCodeBlock::Cast(lhs);
  if (lhs_code != NULL) {
    lhs_end += lhs_code->GetInstructionSize();

    BasicBlock::Successors::const_iterator it(lhs_code->successors().begin());
    for (; it != lhs_code->successors().end(); ++it) {
      lhs_end += it->instruction_size();
    }
  }
  const BasicDataBlock* lhs_data = BasicDataBlock::Cast(lhs);
  if (lhs_data != NULL)
    lhs_end += lhs_data->size();

  return lhs_end != rhs->offset();
}

// A test fixture which generates a block-graph to use for basic-block
// related testing.
// See: basic_block_assembly_func.asm
class BasicBlockDecomposerTest : public BasicBlockTest {
 public:
  virtual void SetUp() OVERRIDE {
    BasicBlockTest::SetUp();
    ASSERT_NO_FATAL_FAILURE(InitBlockGraph());
  }
};

}

TEST_F(BasicBlockDecomposerTest, Decompose) {
  ASSERT_NO_FATAL_FAILURE(InitBasicBlockSubGraph());

  // Ensure we have the expected number and types of blocks.
  ASSERT_EQ(kNumCodeBasicBlocks + kNumDataBasicBlocks + kNumPaddingBasicBlocks,
            subgraph_.basic_blocks().size());
  ASSERT_EQ(kNumCodeBasicBlocks,
            CountBasicBlocks(subgraph_, BasicBlock::BASIC_CODE_BLOCK));
  ASSERT_EQ(kNumDataBasicBlocks,
            CountBasicBlocks(subgraph_, BasicBlock::BASIC_DATA_BLOCK));
  ASSERT_EQ(kNumPaddingBasicBlocks,
            CountBasicBlocks(subgraph_, BasicBlock::BASIC_PADDING_BLOCK));

  // There should be no gaps and all of the blocks should be used.
  ASSERT_EQ(1U, subgraph_.block_descriptions().size());
  const BasicBlockSubGraph::BlockDescription& desc =
      subgraph_.block_descriptions().back();
  EXPECT_EQ(kNumBasicBlocks, desc.basic_block_order.size());
  EXPECT_TRUE(
      std::adjacent_find(
          desc.basic_block_order.begin(),
          desc.basic_block_order.end(),
          &HasGapOrIsOutOfOrder) == desc.basic_block_order.end());

  BasicBlockSubGraph::ReachabilityMap rm;
  subgraph_.GetReachabilityMap(&rm);

  // Basic-block 0 - assembly_func.
  ASSERT_TRUE(BasicBlockSubGraph::IsReachable(rm, bbs_[0]));
  ASSERT_EQ(BasicBlock::BASIC_CODE_BLOCK, bbs_[0]->type());
  BasicCodeBlock* bb0 = BasicCodeBlock::Cast(bbs_[0]);
  ASSERT_TRUE(bb0 != NULL);
  ASSERT_EQ(4u, bb0->instructions().size());
  ASSERT_EQ(0u, bb0->successors().size());
  BasicBlock::Instructions::const_iterator inst_iter =
      bb0->instructions().begin();
  std::advance(inst_iter, 2);
  ASSERT_EQ(1u, inst_iter->references().size());
  ASSERT_EQ(bbs_[9], inst_iter->references().begin()->second.basic_block());
  std::advance(inst_iter, 1);
  ASSERT_EQ(1u, inst_iter->references().size());
  ASSERT_EQ(bbs_[8], inst_iter->references().begin()->second.basic_block());
  ASSERT_EQ(1u, bbs_[0]->alignment());

  // Basic-block 1 - unreachable-label.
  ASSERT_FALSE(BasicBlockSubGraph::IsReachable(rm, bbs_[1]));
  ASSERT_EQ(BasicBlock::BASIC_PADDING_BLOCK, bbs_[1]->type());
  BasicCodeBlock* bb1 = BasicCodeBlock::Cast(bbs_[1]);
  ASSERT_EQ(1u, bb1->instructions().size());
  ASSERT_EQ(1u, bb1->successors().size());;
  ASSERT_EQ(bbs_[2],
            bb1->successors().front().reference().basic_block());
  ASSERT_EQ(1u, bb1->alignment());

  // Basic-block 2 - case_0.
  ASSERT_TRUE(BasicBlockSubGraph::IsReachable(rm, bbs_[2]));
  ASSERT_EQ(BasicBlock::BASIC_CODE_BLOCK, bbs_[2]->type());
  BasicCodeBlock* bb2 = BasicCodeBlock::Cast(bbs_[2]);
  ASSERT_TRUE(bb2 != NULL);
  ASSERT_EQ(2u, bb2->instructions().size());
  ASSERT_EQ(1u, bb2->successors().size());;
  ASSERT_EQ(bbs_[3], bb2->successors().front().reference().basic_block());
  ASSERT_EQ(1u, bbs_[2]->alignment());

  // Basic-block 3 - sub eax to jnz.
  ASSERT_TRUE(BasicBlockSubGraph::IsReachable(rm, bbs_[3]));
  ASSERT_EQ(BasicBlock::BASIC_CODE_BLOCK, bbs_[3]->type());
  BasicCodeBlock* bb3 = BasicCodeBlock::Cast(bbs_[3]);
  ASSERT_TRUE(bb3 != NULL);
  ASSERT_EQ(1u, bb3->instructions().size());
  ASSERT_EQ(2u, bb3->successors().size());;
  ASSERT_EQ(bb3, bb3->successors().front().reference().basic_block());
  ASSERT_EQ(bbs_[4], bb3->successors().back().reference().basic_block());
  ASSERT_EQ(1u, bbs_[3]->alignment());

  // Basic-block 4 - ret.
  ASSERT_TRUE(BasicBlockSubGraph::IsReachable(rm, bbs_[4]));
  ASSERT_EQ(BasicBlock::BASIC_CODE_BLOCK, bbs_[4]->type());
  BasicCodeBlock* bb4 = BasicCodeBlock::Cast(bbs_[4]);
  ASSERT_TRUE(bb4 != NULL);
  ASSERT_EQ(1u, bb4->instructions().size());
  ASSERT_EQ(0u, bb4->successors().size());;
  ASSERT_EQ(1u, bbs_[4]->alignment());

  // Basic-block 5 - case_1.
  ASSERT_TRUE(BasicBlockSubGraph::IsReachable(rm, bbs_[5]));
  ASSERT_EQ(BasicBlock::BASIC_CODE_BLOCK, bbs_[5]->type());
  BasicCodeBlock* bb5 = BasicCodeBlock::Cast(bbs_[5]);
  ASSERT_TRUE(bb5 != NULL);
  ASSERT_EQ(1u, bb5->instructions().size());
  ASSERT_EQ(
      func1_,
      bb5->instructions().front().references().begin()->second.block());
  ASSERT_EQ(1u, bb5->successors().size());
  ASSERT_EQ(bbs_[6], bb5->successors().front().reference().basic_block());
  ASSERT_EQ(1u, bbs_[5]->alignment());

  // Basic-block 6 - case_default.
  ASSERT_TRUE(BasicBlockSubGraph::IsReachable(rm, bbs_[6]));
  ASSERT_EQ(BasicBlock::BASIC_CODE_BLOCK, bbs_[6]->type());
  BasicCodeBlock* bb6 = BasicCodeBlock::Cast(bbs_[6]);
  ASSERT_TRUE(bb6 != NULL);
  ASSERT_EQ(2u, bb6->instructions().size());
  ASSERT_EQ(
      func2_,
      bb6->instructions().back().references().begin()->second.block());
  ASSERT_EQ(0u, bb6->successors().size());
  ASSERT_EQ(1u, bbs_[6]->alignment());

  // Basic-block 7 - interrupt_label.
  ASSERT_FALSE(BasicBlockSubGraph::IsReachable(rm, bbs_[7]));
  ASSERT_EQ(BasicBlock::BASIC_PADDING_BLOCK, bbs_[7]->type());
  BasicCodeBlock* bb7 = BasicCodeBlock::Cast(bbs_[7]);
  ASSERT_TRUE(bb7 != NULL);
  ASSERT_EQ(3u, bb7->instructions().size());
  ASSERT_EQ(0u, bb7->successors().size());
  ASSERT_EQ(1u, bbs_[7]->alignment());

  // Basic-block 8 - jump_table.
  ASSERT_TRUE(BasicBlockSubGraph::IsReachable(rm, bbs_[8]));
  ASSERT_EQ(BasicBlock::BASIC_DATA_BLOCK, bbs_[8]->type());
  BasicDataBlock* bb8 = BasicDataBlock::Cast(bbs_[8]);
  ASSERT_TRUE(bb8 != NULL);
  ASSERT_EQ(3 * Reference::kMaximumSize, bb8->size());
  ASSERT_EQ(3u, bb8->references().size());
  ASSERT_EQ(4u, bbs_[8]->alignment());

  // Basic-block 9 - case_table.
  ASSERT_TRUE(BasicBlockSubGraph::IsReachable(rm, bbs_[9]));
  ASSERT_EQ(BasicBlock::BASIC_DATA_BLOCK, bbs_[9]->type());
  BasicDataBlock* bb9 = BasicDataBlock::Cast(bbs_[9]);
  ASSERT_TRUE(bb9 != NULL);
  ASSERT_EQ(256, bb9->size());
  ASSERT_EQ(0u, bb9->references().size());
  ASSERT_EQ(4u, bbs_[9]->alignment());

  // Validate all source ranges.
  core::RelativeAddress next_addr(start_addr_);
  for (size_t i = 0; i < bbs_.size(); ++i) {
    const BasicCodeBlock* code_block = BasicCodeBlock::Cast(bbs_[i]);
    const BasicDataBlock* data_block = BasicDataBlock::Cast(bbs_[i]);

    if (code_block != NULL) {
      ASSERT_TRUE(data_block == NULL);

      BasicBlock::Instructions::const_iterator instr_it =
          code_block->instructions().begin();
      for (; instr_it != code_block->instructions().end(); ++instr_it) {
        const Instruction& instr = *instr_it;
        ASSERT_EQ(next_addr, instr.source_range().start());
        ASSERT_EQ(instr.size(), instr.source_range().size());

        next_addr += instr.size();
      }

      BasicBlock::Successors::const_iterator succ_it =
          code_block->successors().begin();
      for (; succ_it != code_block->successors().end(); ++succ_it) {
        const Successor& succ = *succ_it;
        if (succ.source_range().size() != 0) {
          ASSERT_EQ(next_addr, succ.source_range().start());
          ASSERT_EQ(succ.instruction_size(), succ.source_range().size());
        } else {
          ASSERT_EQ(0, succ.instruction_size());
        }

        next_addr += succ.instruction_size();
      }
    }

    if (data_block != NULL) {
      ASSERT_TRUE(code_block == NULL);
      ASSERT_TRUE(data_block->type() == BasicBlock::BASIC_DATA_BLOCK);
      ASSERT_EQ(next_addr, data_block->source_range().start());
      ASSERT_EQ(data_block->size(), data_block->source_range().size());

      next_addr += data_block->size();
    }
  }
}

}  // namespace block_graph
