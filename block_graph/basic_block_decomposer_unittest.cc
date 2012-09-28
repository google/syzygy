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

typedef BasicBlockSubGraph::BBAddressSpace BBAddressSpace;
typedef BlockGraph::Block Block;
typedef BlockGraph::Offset Offset;
typedef BlockGraph::Reference Reference;
typedef BlockGraph::Size Size;

// A helper to count basic blocks of a given type.
size_t CountBasicBlocks(const BasicBlockSubGraph& subgraph,
                        BasicBlock::BasicBlockType type) {
  size_t counter = 0;
  BasicBlockSubGraph::BBCollection::const_iterator it =
      subgraph.basic_blocks().begin();
  for (; it != subgraph.basic_blocks().end(); ++it) {
    if (it->second.type() == type)
      ++counter;
  }
  return counter;
}

// A helper comparator to that returns true if lhs and rhs are not adjacent
// and in order.
bool HasGapOrIsOutOfOrder(const BasicBlock* lhs, const BasicBlock* rhs) {
  typedef BasicBlock::Size Size;
  return lhs->offset() + lhs->size() != static_cast<Size>(rhs->offset());
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
  ASSERT_EQ(kNumBasicBlocks, subgraph_.basic_blocks().size());
  ASSERT_EQ(kNumBasicBlocks, subgraph_.original_address_space().size());
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
  ASSERT_EQ(4u, bbs_[0]->instructions().size());
  ASSERT_EQ(0u, bbs_[0]->successors().size());;
  BasicBlock::Instructions::const_iterator inst_iter =
      bbs_[0]->instructions().begin();
  std::advance(inst_iter, 2);
  ASSERT_EQ(1u, inst_iter->references().size());
  ASSERT_EQ(bbs_[9], inst_iter->references().begin()->second.basic_block());
  std::advance(inst_iter, 1);
  ASSERT_EQ(1u, inst_iter->references().size());
  ASSERT_EQ(bbs_[8], inst_iter->references().begin()->second.basic_block());

  // Basic-block 1 - unreachable-label.
  // TODO(rogerm): This is classified as padding for now, it will become code
  //     once the decomposer switches to just doing a straight disassembly of
  //     the entire code region.
  ASSERT_FALSE(BasicBlockSubGraph::IsReachable(rm, bbs_[1]));
  ASSERT_EQ(BasicBlock::BASIC_PADDING_BLOCK, bbs_[1]->type());
  // ASSERT_EQ(1u, bbs_[1]->instructions().size());
  // ASSERT_EQ(1u, bbs_[1]->successors().size());;
  // ASSERT_EQ(bbs_[2],
  //           bbs_[1]->successors().front().reference().basic_block());

  // Basic-block 2 - case_0.
  ASSERT_TRUE(BasicBlockSubGraph::IsReachable(rm, bbs_[2]));
  ASSERT_EQ(BasicBlock::BASIC_CODE_BLOCK, bbs_[2]->type());
  ASSERT_EQ(2u, bbs_[2]->instructions().size());
  ASSERT_EQ(1u, bbs_[2]->successors().size());;
  ASSERT_EQ(bbs_[3], bbs_[2]->successors().front().reference().basic_block());

  // Basic-block 3 - sub eax to jnz.
  ASSERT_TRUE(BasicBlockSubGraph::IsReachable(rm, bbs_[3]));
  ASSERT_EQ(BasicBlock::BASIC_CODE_BLOCK, bbs_[3]->type());
  ASSERT_EQ(1u, bbs_[3]->instructions().size());
  ASSERT_EQ(2u, bbs_[3]->successors().size());;
  ASSERT_EQ(bbs_[3], bbs_[3]->successors().front().reference().basic_block());
  ASSERT_EQ(bbs_[4], bbs_[3]->successors().back().reference().basic_block());

  // Basic-block 4 - ret.
  ASSERT_TRUE(BasicBlockSubGraph::IsReachable(rm, bbs_[4]));
  ASSERT_EQ(BasicBlock::BASIC_CODE_BLOCK, bbs_[4]->type());
  ASSERT_EQ(1u, bbs_[4]->instructions().size());
  ASSERT_EQ(0u, bbs_[4]->successors().size());;

  // Basic-block 5 - case_1.
  ASSERT_TRUE(BasicBlockSubGraph::IsReachable(rm, bbs_[5]));
  ASSERT_EQ(BasicBlock::BASIC_CODE_BLOCK, bbs_[5]->type());
  ASSERT_EQ(1u, bbs_[5]->instructions().size());
  ASSERT_EQ(
      func1_,
      bbs_[5]->instructions().front().references().begin()->second.block());
  ASSERT_EQ(1u, bbs_[5]->successors().size());
  ASSERT_EQ(bbs_[6], bbs_[5]->successors().front().reference().basic_block());

  // Basic-block 6 - case_default.
  ASSERT_TRUE(BasicBlockSubGraph::IsReachable(rm, bbs_[6]));
  ASSERT_EQ(BasicBlock::BASIC_CODE_BLOCK, bbs_[6]->type());
  ASSERT_EQ(2u, bbs_[6]->instructions().size());
  ASSERT_EQ(
      func2_,
      bbs_[6]->instructions().back().references().begin()->second.block());
  ASSERT_EQ(0u, bbs_[6]->successors().size());

  // Basic-block 7 - interrupt_label.
  ASSERT_FALSE(BasicBlockSubGraph::IsReachable(rm, bbs_[7]));
  ASSERT_EQ(BasicBlock::BASIC_CODE_BLOCK, bbs_[7]->type());
  ASSERT_EQ(1u, bbs_[7]->instructions().size());
  ASSERT_EQ(0u, bbs_[7]->successors().size());

  // Basic-block 8 - jump_table.
  ASSERT_TRUE(BasicBlockSubGraph::IsReachable(rm, bbs_[8]));
  ASSERT_EQ(BasicBlock::BASIC_DATA_BLOCK, bbs_[8]->type());
  ASSERT_EQ(3 * Reference::kMaximumSize, bbs_[8]->size());
  ASSERT_EQ(3u, bbs_[8]->references().size());

  // Basic-block 9 - case_table.
  ASSERT_TRUE(BasicBlockSubGraph::IsReachable(rm, bbs_[9]));
  ASSERT_EQ(BasicBlock::BASIC_DATA_BLOCK, bbs_[9]->type());
  ASSERT_EQ(256, bbs_[9]->size());
  ASSERT_EQ(0u, bbs_[9]->references().size());
}

}  // namespace block_graph
