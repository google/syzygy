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

#include "syzygy/block_graph/block_util.h"

#include "gtest/gtest.h"
#include "syzygy/block_graph/basic_block_assembler.h"
#include "syzygy/block_graph/basic_block_test_util.h"

namespace block_graph {

namespace {

class BlockUtilTest: public testing::Test {
 public:
  BlockUtilTest()
      : bb_(NULL),
        start_addr_(0xF00D) {
    bb_ = subgraph_.AddBasicCodeBlock("foo");
  }

  BlockGraph::Size AddInstructions(bool add_source_ranges) {
    using core::eax;
    using core::ebp;
    using core::esp;

    BasicBlockAssembler assm(bb_->instructions().begin(), &bb_->instructions());

    assm.push(ebp);
    assm.mov(ebp, esp);
    assm.mov(eax, Operand(ebp,  Displacement(8)));
    assm.pop(ebp);
    // assm.ret(0);

    BasicBlock::Instructions::iterator inst_it(bb_->instructions().begin());
    BlockGraph::RelativeAddress next_addr(start_addr_);

    BasicBlock::Offset next_offs = 0;
    for (; inst_it != bb_->instructions().end(); ++inst_it) {
      if (add_source_ranges)
        inst_it->set_source_range(
            Instruction::SourceRange(next_addr, inst_it->size()));

      next_addr += inst_it->size();
      next_offs += inst_it->size();
    }

    BasicBlockReference ref(BlockGraph::PC_RELATIVE_REF, 4, bb_);
    bb_->successors().push_back(
        Successor(Successor::kConditionAbove, ref, 5));
    next_offs += 5;

    if (add_source_ranges)
      bb_->successors().back().set_source_range(
          Successor::SourceRange(next_addr, 5));

    bb_->successors().push_back(
        Successor(Successor::kConditionBelowOrEqual, ref, 0));

    return next_offs;
  }

 protected:
  BlockGraph image_;
  BlockGraph::RelativeAddress start_addr_;
  BasicBlockSubGraph subgraph_;
  BasicCodeBlock* bb_;
};

}  // namespace

TEST_F(BlockUtilTest, GetBasicBlockSourceRangeEmptyFails) {
  BlockGraph::Size instr_len = AddInstructions(false);

  BlockGraph::Block::SourceRange source_range;
  ASSERT_FALSE(GetBasicBlockSourceRange(*bb_, &source_range));
  EXPECT_EQ(0, source_range.size());
}

TEST_F(BlockUtilTest, GetBasicBlockSourceRangeNonContiguousFails) {
  BlockGraph::Size instr_len = AddInstructions(true);

  // Make the range non-contiguous by pushing the successor out one byte.
  BlockGraph::Block::SourceRange range =
      bb_->successors().front().source_range();
  bb_->successors().front().set_source_range(
      BlockGraph::Block::SourceRange(range.start() + 1, range.size()));

  BlockGraph::Block::SourceRange source_range;
  ASSERT_FALSE(GetBasicBlockSourceRange(*bb_, &source_range));
  EXPECT_EQ(0, source_range.size());
}

TEST_F(BlockUtilTest, GetBasicBlockSourceRangeSequentialSucceeds) {
  BlockGraph::Size instr_len = AddInstructions(true);

  BlockGraph::Block::SourceRange source_range;
  ASSERT_TRUE(GetBasicBlockSourceRange(*bb_, &source_range));
  BlockGraph::Block::SourceRange expected_range(
      BlockGraph::RelativeAddress(0xF00D), instr_len);
  EXPECT_EQ(expected_range, source_range);
}

TEST_F(BlockUtilTest, GetBasicBlockSourceRangeNonSequentialSucceeds) {
  BlockGraph::Size instr_len = AddInstructions(true);

  // Shuffle the ranges by flipping the first and last ranges.
  BlockGraph::Block::SourceRange temp =
      bb_->successors().front().source_range();
  bb_->successors().front().set_source_range(
      bb_->instructions().front().source_range());
  bb_->instructions().front().set_source_range(temp);

  BlockGraph::Block::SourceRange source_range;
  ASSERT_TRUE(GetBasicBlockSourceRange(*bb_, &source_range));
  BlockGraph::Block::SourceRange expected_range(
      BlockGraph::RelativeAddress(0xF00D), instr_len);
  EXPECT_EQ(expected_range, source_range);
}

TEST_F(BlockUtilTest, GetBasicBlockSourceRangePrependInstructionsSucceeds) {
  BlockGraph::Size instr_len = AddInstructions(true);

  // Prepend some instrumentation-like code.
  BasicBlockAssembler assm(bb_->instructions().begin(), &bb_->instructions());
  assm.push(Immediate(0xBADF00D));
  assm.call(Displacement(bb_));

  BlockGraph::Block::SourceRange source_range;
  ASSERT_TRUE(GetBasicBlockSourceRange(*bb_, &source_range));
  BlockGraph::Block::SourceRange expected_range(
      BlockGraph::RelativeAddress(0xF00D), instr_len);
  EXPECT_EQ(expected_range, source_range);
}

TEST_F(BlockUtilTest, IsUnsafeReference) {
  // Some safe blocks.
  BlockGraph::Block* s1 = image_.AddBlock(BlockGraph::CODE_BLOCK, 40, "s1");
  BlockGraph::Block* s2 = image_.AddBlock(BlockGraph::CODE_BLOCK, 40, "s2");

  // Some unsafe blocks.
  BlockGraph::Block* u1 = image_.AddBlock(BlockGraph::CODE_BLOCK, 40, "u1");
  u1->set_attribute(BlockGraph::HAS_INLINE_ASSEMBLY);
  BlockGraph::Block* u2 = image_.AddBlock(BlockGraph::CODE_BLOCK, 40, "u2");
  u2->set_attribute(BlockGraph::BUILT_BY_UNSUPPORTED_COMPILER);

  // If neither or only one has an unsafe attribute then it's not unsafe.
  EXPECT_FALSE(IsUnsafeReference(s1, BlockGraph::Reference(
      BlockGraph::PC_RELATIVE_REF,
      BlockGraph::Reference::kMaximumSize,
      s2, 0, 0)));
  EXPECT_FALSE(IsUnsafeReference(s1, BlockGraph::Reference(
      BlockGraph::PC_RELATIVE_REF,
      BlockGraph::Reference::kMaximumSize,
      u1, 0, 0)));
  EXPECT_FALSE(IsUnsafeReference(u2, BlockGraph::Reference(
      BlockGraph::PC_RELATIVE_REF,
      BlockGraph::Reference::kMaximumSize,
      s2, 0, 0)));

  // If the reference points to a non-zero offset then it's unsafe.
  EXPECT_TRUE(IsUnsafeReference(s1, BlockGraph::Reference(
      BlockGraph::PC_RELATIVE_REF,
      BlockGraph::Reference::kMaximumSize,
      s2, 4, 4)));

  // If both the referring and referred blocks have unsafe attributes,
  // the reference is unsafe.
  EXPECT_TRUE(IsUnsafeReference(u1, BlockGraph::Reference(
      BlockGraph::PC_RELATIVE_REF,
      BlockGraph::Reference::kMaximumSize,
      u2, 0, 0)));
}

TEST_F(BlockUtilTest, CheckNoUnexpectedStackFrameManipulation) {
  // Prepend some instrumentation with a conventional calling convention.
  BasicBlockAssembler assm(bb_->instructions().begin(), &bb_->instructions());
  assm.push(core::ebp);
  assm.mov(core::ebp, core::esp);
  assm.mov(core::eax, Operand(core::ebp,  Displacement(8)));
  assm.pop(core::ebp);
  assm.ret(0);

  EXPECT_FALSE(HasUnexpectedStackFrameManipulation(&subgraph_));
}

TEST_F(BlockUtilTest, CheckInvalidInstructionUnexpectedStackFrameManipulation) {
  // Prepend some instrumentation with a conventional calling convention.
  BasicBlockAssembler assm(bb_->instructions().begin(), &bb_->instructions());
  assm.push(core::ebp);
  assm.mov(core::ebp, core::esp);
  // The instruction LEA is invalid stack frame manipulation.
  assm.lea(core::ebp, Operand(core::ebp,  Displacement(8)));
  assm.pop(core::ebp);
  assm.ret(0);

  EXPECT_TRUE(HasUnexpectedStackFrameManipulation(&subgraph_));
}

TEST_F(BlockUtilTest, CheckInvalidRegisterUnexpectedStackFrameManipulation) {
  // Prepend some instrumentation with a conventional calling convention.
  BasicBlockAssembler assm(bb_->instructions().begin(), &bb_->instructions());
  assm.push(core::ebp);
  // The instruction MOV use an invalid register EAX.
  assm.mov(core::ebp, core::eax);
  assm.lea(core::ebp, Operand(core::ebp,  Displacement(8)));
  assm.pop(core::ebp);
  assm.ret(0);

  EXPECT_TRUE(HasUnexpectedStackFrameManipulation(&subgraph_));
}

namespace {

// A utility class for using the test data built around the function in
// basic_block_assembly_func.asm.
class BlockUtilOnTestDataTest : public testing::BasicBlockTest {
 public:
  virtual void SetUp() OVERRIDE {
    BasicBlockTest::SetUp();
    ASSERT_NO_FATAL_FAILURE(InitBlockGraph());
  }
};

}  // namespace

TEST_F(BlockUtilOnTestDataTest, GetJumpTableSize) {
  block_graph::BlockGraph::BlockMap::const_iterator block_iter =
      block_graph_.blocks().begin();

  size_t table_size = 0;
  bool table_found = false;

  // Iterates over the blocks of the block_graph. We expect to find only one
  // block containing one jump table.
  for (; block_iter != block_graph_.blocks().end(); ++block_iter) {
    if (block_iter->second.type() != BlockGraph::CODE_BLOCK)
      continue;

    // Iterates over the labels of the block to find the jump tables.
    BlockGraph::Block::LabelMap::const_iterator iter_label =
        block_iter->second.labels().begin();
    for (; iter_label != block_iter->second.labels().end(); ++iter_label) {
      if (!iter_label->second.has_attributes(BlockGraph::JUMP_TABLE_LABEL))
        continue;

      // There's only one jump table in the test data.
      EXPECT_FALSE(table_found);
      table_found = true;

      EXPECT_TRUE(block_graph::GetJumpTableSize(&block_iter->second,
                                                iter_label,
                                                &table_size));
    }
  }
  EXPECT_EQ(3U, table_size);
}

}  // namespace block_graph
