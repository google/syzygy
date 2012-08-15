// Copyright 2012 Google Inc.
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
#include "syzygy/block_graph/block_graph_serializer.h"
#include "syzygy/block_graph/block_util.h"
#include "syzygy/block_graph/unittest_util.h"
#include "syzygy/core/address.h"
#include "syzygy/core/unittest_util.h"

#include "mnemonics.h"  // NOLINT

extern "C" {

// Functions and labels exposed from our .asm test stub.
extern int assembly_func();
extern int unreachable_label();
extern int interrupt_label();
extern int assembly_func_end();

extern int case_0();
extern int case_1();
extern int case_default();
extern int jump_table();
extern int case_table();

// Functions invoked or referred by the .asm test stub.
int func1() {
  return 1;
}

int func2() {
  return 2;
}

}  // extern "C"


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
using testing::Return;

typedef BasicBlockSubGraph::BBAddressSpace BBAddressSpace;
typedef BlockGraph::Block Block;
typedef BlockGraph::Offset Offset;
typedef BlockGraph::Reference Reference;
typedef BlockGraph::Size Size;

#define POINTER_DIFF(x, y) \
    (reinterpret_cast<const uint8*>(x) - reinterpret_cast<const uint8*>(y))
const Size kAssemblyFuncSize = POINTER_DIFF(assembly_func_end, assembly_func);
const Offset kCaseTableOffset = POINTER_DIFF(case_table, assembly_func);
const Offset kJumpTableOffset = POINTER_DIFF(jump_table, assembly_func);
const Offset kCase0Offset = POINTER_DIFF(case_0, assembly_func);
const Offset kCase1Offset = POINTER_DIFF(case_1, assembly_func);
const Offset kCaseDefaultOffset = POINTER_DIFF(case_default, assembly_func);
const Offset kInterruptOffset = POINTER_DIFF(interrupt_label, assembly_func);
const Offset kUnreachableOffset = POINTER_DIFF(unreachable_label,
                                               assembly_func);
#undef POINTER_DIFF

// The number and type of basic blocks.
// TODO(rogerm): The padding block will go away once the decomposer switches
//     to doing a straight disassembly of the entire code region.
const size_t kNumCodeBasicBlocks = 7;
const size_t kNumDataBasicBlocks = 2;
const size_t kNumPaddingBasicBlocks = 1;
const size_t kNumBasicBlocks =
    kNumCodeBasicBlocks + kNumDataBasicBlocks + kNumPaddingBasicBlocks;

const BlockGraph::LabelAttributes kCaseTableAttributes =
    BlockGraph::DATA_LABEL | BlockGraph::CASE_TABLE_LABEL;

const BlockGraph::LabelAttributes kJumpTableAttributes =
    BlockGraph::DATA_LABEL | BlockGraph::JUMP_TABLE_LABEL;

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
class BasicBlockDecomposerTest : public ::testing::Test {
 public:
  virtual void SetUp() OVERRIDE {
    testing::Test::SetUp();

    // Create func1, which will be called from assembly_func.
    func1_ = block_graph_.AddBlock(BlockGraph::CODE_BLOCK, 1, "func1");
    ASSERT_TRUE(func1_ != NULL);

    // Create func2, a non-returning function called from assembly_func.
    func2_ = block_graph_.AddBlock(BlockGraph::CODE_BLOCK, 1, "func2");
    ASSERT_TRUE(func2_ != NULL);
    func2_->set_attributes(BlockGraph::NON_RETURN_FUNCTION);

    // Create a data block to refer to assembly_func.
    data_ = block_graph_.AddBlock(BlockGraph::DATA_BLOCK, 4, "data");
    ASSERT_TRUE(data_ != NULL);

    // Create assembly_func, and mark it as BUILT_BY_SYZYGY so the basic-block
    // decomposer is willing to process it.
    assembly_func_ = block_graph_.AddBlock(BlockGraph::CODE_BLOCK,
                                           kAssemblyFuncSize,
                                           "assembly_func_");
    ASSERT_TRUE(assembly_func_ != NULL);
    assembly_func_->SetData(reinterpret_cast<const uint8*>(assembly_func),
                            kAssemblyFuncSize);
    assembly_func_->set_attributes(BlockGraph::BUILT_BY_SYZYGY);

    // Add the data labels.
    ASSERT_TRUE(assembly_func_->SetLabel(
        kCaseTableOffset, "case_table", kCaseTableAttributes));
    ASSERT_TRUE(assembly_func_->SetLabel(
        kJumpTableOffset, "jump_table", kCaseTableAttributes));

    // Add the instruction references to the jump and case tables. Note that
    // the jump table reference is at the end of the indirect jmp instruction
    // (7-bytes) that immediately precedes the unreachable label and that the
    // case table reference is at the end of the movzx instruction which
    // immediately preceeds the jmp.
    ASSERT_TRUE(assembly_func_->SetReference(
        kUnreachableOffset - (Reference::kMaximumSize + 7),
        Reference(BlockGraph::RELATIVE_REF, Reference::kMaximumSize,
                  assembly_func_, kCaseTableOffset, kCaseTableOffset)));
    ASSERT_TRUE(assembly_func_->SetReference(
        kUnreachableOffset - Reference::kMaximumSize,
        Reference(BlockGraph::RELATIVE_REF, Reference::kMaximumSize,
                  assembly_func_, kJumpTableOffset, kJumpTableOffset)));
    // Add the jump table references to the cases.
    ASSERT_TRUE(assembly_func_->SetReference(
        kJumpTableOffset + (Reference::kMaximumSize * 0),
        Reference(BlockGraph::RELATIVE_REF, Reference::kMaximumSize,
                  assembly_func_, kCase0Offset, kCase0Offset)));
    ASSERT_TRUE(assembly_func_->SetReference(
        kJumpTableOffset + (Reference::kMaximumSize * 1),
        Reference(BlockGraph::RELATIVE_REF, Reference::kMaximumSize,
                  assembly_func_, kCase1Offset, kCase1Offset)));
    ASSERT_TRUE(assembly_func_->SetReference(
        kJumpTableOffset + (Reference::kMaximumSize * 2),
        Reference(BlockGraph::RELATIVE_REF, Reference::kMaximumSize,
                  assembly_func_, kCaseDefaultOffset, kCaseDefaultOffset)));

    // Add the external outbound references.
    ASSERT_TRUE(assembly_func_->SetReference(
        kCase1Offset + 1,
        Reference(BlockGraph::RELATIVE_REF, Reference::kMaximumSize,
                  func1_, 0, 0)));
    ASSERT_TRUE(assembly_func_->SetReference(
        kInterruptOffset - Reference::kMaximumSize,
        Reference(BlockGraph::RELATIVE_REF, Reference::kMaximumSize,
                  func2_, 0, 0)));

    // Add an inbound reference to the top of the function.
    ASSERT_TRUE(data_->SetReference(
        0,
        Reference(BlockGraph::RELATIVE_REF, Reference::kMaximumSize,
                  assembly_func_, 0, 0)));
  }

 protected:
  BlockGraph block_graph_;
  BlockGraph::Block* assembly_func_;
  BlockGraph::Block* func1_;
  BlockGraph::Block* func2_;
  BlockGraph::Block* data_;
};

}

TEST_F(BasicBlockDecomposerTest, Decompose) {
  BasicBlockSubGraph subgraph;
  BasicBlockDecomposer bb_decomposer(assembly_func_, &subgraph);
  logging::SetMinLogLevel(3);
  ASSERT_TRUE(bb_decomposer.Decompose());
  ASSERT_TRUE(subgraph.IsValid());

  // Ensure we have the expected number and types of blocks.
  ASSERT_EQ(kNumBasicBlocks, subgraph.basic_blocks().size());
  ASSERT_EQ(kNumBasicBlocks, subgraph.original_address_space().size());
  ASSERT_EQ(kNumCodeBasicBlocks,
            CountBasicBlocks(subgraph, BasicBlock::BASIC_CODE_BLOCK));
  ASSERT_EQ(kNumDataBasicBlocks,
            CountBasicBlocks(subgraph, BasicBlock::BASIC_DATA_BLOCK));
  ASSERT_EQ(kNumPaddingBasicBlocks,
            CountBasicBlocks(subgraph, BasicBlock::BASIC_PADDING_BLOCK));

  // There should be no gaps and all of the blocks should be used.
  ASSERT_EQ(1U, subgraph.block_descriptions().size());
  const BasicBlockSubGraph::BlockDescription& desc =
      subgraph.block_descriptions().back();
  EXPECT_EQ(kNumBasicBlocks, desc.basic_block_order.size());
  EXPECT_TRUE(
      std::adjacent_find(
          desc.basic_block_order.begin(),
          desc.basic_block_order.end(),
          &HasGapOrIsOutOfOrder) == desc.basic_block_order.end());

  // Let's validate the contents of the basic blocks.
  std::vector<BasicBlock*> bb;
  bb.reserve(desc.basic_block_order.size());
  bb.assign(desc.basic_block_order.begin(), desc.basic_block_order.end());

  BasicBlockSubGraph::ReachabilityMap rm;
  subgraph.GetReachabilityMap(&rm);

  // Basic-block 0 - assembly_func.
  ASSERT_TRUE(BasicBlockSubGraph::IsReachable(rm, bb[0]));
  ASSERT_EQ(BasicBlock::BASIC_CODE_BLOCK, bb[0]->type());
  ASSERT_EQ(4u, bb[0]->instructions().size());
  ASSERT_EQ(0u, bb[0]->successors().size());;
  BasicBlock::Instructions::const_iterator inst_iter =
      bb[0]->instructions().begin();
  std::advance(inst_iter, 2);
  ASSERT_EQ(1u, inst_iter->references().size());
  ASSERT_EQ(bb[9], inst_iter->references().begin()->second.basic_block());
  std::advance(inst_iter, 1);
  ASSERT_EQ(1u, inst_iter->references().size());
  ASSERT_EQ(bb[8], inst_iter->references().begin()->second.basic_block());

  // Basic-block 1 - unreachable-label.
  // TODO(rogerm): This is classified as padding for now, it will become code
  //     once the decomposer switches to just doing a straight disassembly of
  //     the entire code region.
  ASSERT_FALSE(BasicBlockSubGraph::IsReachable(rm, bb[1]));
  ASSERT_EQ(BasicBlock::BASIC_PADDING_BLOCK, bb[1]->type());
  // ASSERT_EQ(1u, bb[1]->instructions().size());
  // ASSERT_EQ(1u, bb[1]->successors().size());;
  // ASSERT_EQ(bb[2], bb[1]->successors().front().reference().basic_block());

  // Basic-block 2 - case_0.
  ASSERT_TRUE(BasicBlockSubGraph::IsReachable(rm, bb[2]));
  ASSERT_EQ(BasicBlock::BASIC_CODE_BLOCK, bb[2]->type());
  ASSERT_EQ(2u, bb[2]->instructions().size());
  ASSERT_EQ(1u, bb[2]->successors().size());;
  ASSERT_EQ(bb[3], bb[2]->successors().front().reference().basic_block());

  // Basic-block 3 - sub eax to jnz.
  ASSERT_TRUE(BasicBlockSubGraph::IsReachable(rm, bb[3]));
  ASSERT_EQ(BasicBlock::BASIC_CODE_BLOCK, bb[3]->type());
  ASSERT_EQ(1u, bb[3]->instructions().size());
  ASSERT_EQ(2u, bb[3]->successors().size());;
  ASSERT_EQ(bb[3], bb[3]->successors().front().reference().basic_block());
  ASSERT_EQ(bb[4], bb[3]->successors().back().reference().basic_block());

  // Basic-block 4 - ret.
  ASSERT_TRUE(BasicBlockSubGraph::IsReachable(rm, bb[4]));
  ASSERT_EQ(BasicBlock::BASIC_CODE_BLOCK, bb[4]->type());
  ASSERT_EQ(1u, bb[4]->instructions().size());
  ASSERT_EQ(0u, bb[4]->successors().size());;

  // Basic-block 5 - case_1.
  ASSERT_TRUE(BasicBlockSubGraph::IsReachable(rm, bb[5]));
  ASSERT_EQ(BasicBlock::BASIC_CODE_BLOCK, bb[5]->type());
  ASSERT_EQ(1u, bb[5]->instructions().size());
  ASSERT_EQ(func1_,
            bb[5]->instructions().front().references().begin()->second.block());
  ASSERT_EQ(1u, bb[5]->successors().size());
  ASSERT_EQ(bb[6], bb[5]->successors().front().reference().basic_block());

  // Basic-block 6 - case_default.
  ASSERT_TRUE(BasicBlockSubGraph::IsReachable(rm, bb[6]));
  ASSERT_EQ(BasicBlock::BASIC_CODE_BLOCK, bb[6]->type());
  ASSERT_EQ(2u, bb[6]->instructions().size());
  ASSERT_EQ(func2_,
            bb[6]->instructions().back().references().begin()->second.block());
  ASSERT_EQ(0u, bb[6]->successors().size());

  // Basic-block 7 - interrupt_label.
  ASSERT_FALSE(BasicBlockSubGraph::IsReachable(rm, bb[7]));
  ASSERT_EQ(BasicBlock::BASIC_CODE_BLOCK, bb[7]->type());
  ASSERT_EQ(1u, bb[7]->instructions().size());
  ASSERT_EQ(0u, bb[7]->successors().size());

  // Basic-block 8 - jump_table.
  ASSERT_TRUE(BasicBlockSubGraph::IsReachable(rm, bb[8]));
  ASSERT_EQ(BasicBlock::BASIC_DATA_BLOCK, bb[8]->type());
  ASSERT_EQ(3 * Reference::kMaximumSize, bb[8]->size());
  ASSERT_EQ(3u, bb[8]->references().size());

  // Basic-block 9 - case_table.
  ASSERT_TRUE(BasicBlockSubGraph::IsReachable(rm, bb[9]));
  ASSERT_EQ(BasicBlock::BASIC_DATA_BLOCK, bb[9]->type());
  ASSERT_EQ(256, bb[9]->size());
  ASSERT_EQ(0u, bb[9]->references().size());
}

}  // namespace block_graph
