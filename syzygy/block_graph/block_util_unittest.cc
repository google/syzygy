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

namespace block_graph {

namespace {

class BlockUtilTest: public testing::Test {
 public:
  BlockUtilTest()
      : bb_("foo"),
        start_addr_(0xF00D) {
  }

  void TestAttributes(BlockGraph::BlockAttributes attributes, bool expected) {
    BlockGraph::Block* code = image_.AddBlock(BlockGraph::CODE_BLOCK, 40, "c");
    code->set_attributes(attributes);
    ASSERT_EQ(expected, CodeBlockAttributesAreBasicBlockSafe(code));
  }

  BlockGraph::Size AddInstructions(bool add_source_ranges) {
    using core::eax;
    using core::ebp;
    using core::esp;

    BasicBlockAssembler assm(bb_.instructions().begin(), &bb_.instructions());

    assm.push(ebp);
    assm.mov(ebp, esp);
    assm.mov(eax, Operand(ebp,  Displacement(8)));
    assm.pop(ebp);
    // assm.ret(0);

    BasicBlock::Instructions::iterator inst_it(bb_.instructions().begin());
    BlockGraph::RelativeAddress next_addr(start_addr_);

    BasicBlock::Offset next_offs = 0;
    for (; inst_it != bb_.instructions().end(); ++inst_it) {
      if (add_source_ranges)
        inst_it->set_source_range(
            Instruction::SourceRange(next_addr, inst_it->size()));

      next_addr += inst_it->size();
      next_offs += inst_it->size();
    }

    BasicBlockReference ref(BlockGraph::PC_RELATIVE_REF, 4, &bb_);
    bb_.successors().push_back(
        Successor(Successor::kConditionAbove, ref, next_offs, 5));
    next_offs += 5;

    if (add_source_ranges)
      bb_.successors().back().set_source_range(
          Successor::SourceRange(next_addr, 5));

    bb_.successors().push_back(
        Successor(Successor::kConditionBelowOrEqual, ref, 0, 0));

    return next_offs;
  }

 protected:
  BlockGraph image_;
  BlockGraph::RelativeAddress start_addr_;
  BasicCodeBlock bb_;
};

}  // namespace

TEST_F(BlockUtilTest, CodeBlockAttributesAreBasicBlockSafeGapBlock) {
  ASSERT_NO_FATAL_FAILURE(TestAttributes(BlockGraph::GAP_BLOCK, false));
}

TEST_F(BlockUtilTest, CodeBlockAttributesAreBasicBlockSafePaddingBlock) {
  ASSERT_NO_FATAL_FAILURE(TestAttributes(BlockGraph::PADDING_BLOCK, false));
}

TEST_F(BlockUtilTest, CodeBlockAttributesAreBasicBlockSafeHasInlineAssembly) {
  ASSERT_NO_FATAL_FAILURE(TestAttributes(BlockGraph::HAS_INLINE_ASSEMBLY,
                                         false));
}

TEST_F(BlockUtilTest, CodeBlockAttributesAreBasicBlockSafeUnsupportedCompiler) {
  ASSERT_NO_FATAL_FAILURE(TestAttributes(
      BlockGraph::BUILT_BY_UNSUPPORTED_COMPILER, false));
}

TEST_F(BlockUtilTest, CodeBlockAttributesAreBasicBlockSafeErroredDisassembly) {
  ASSERT_NO_FATAL_FAILURE(TestAttributes(BlockGraph::ERRORED_DISASSEMBLY,
                                         false));
}

TEST_F(BlockUtilTest, CodeBlockAttributesAreBasicBlockSafeExceptionHandling) {
  ASSERT_NO_FATAL_FAILURE(TestAttributes(BlockGraph::HAS_EXCEPTION_HANDLING,
                                         false));
}

TEST_F(BlockUtilTest, CodeBlockAttributesAreBasicBlockSafeDisassembledPastEnd) {
  ASSERT_NO_FATAL_FAILURE(TestAttributes(BlockGraph::DISASSEMBLED_PAST_END,
                                         false));
}

TEST_F(BlockUtilTest, CodeBlockAttributesAreBasicBlockSafeBuiltBySyzygy) {
  ASSERT_NO_FATAL_FAILURE(TestAttributes(
      BlockGraph::HAS_INLINE_ASSEMBLY | BlockGraph::BUILT_BY_SYZYGY, true));
}

TEST_F(BlockUtilTest, GetBasicBlockSourceRangeEmptyFails) {
  BlockGraph::Size instr_len = AddInstructions(false);

  BlockGraph::Block::SourceRange source_range;
  ASSERT_FALSE(GetBasicBlockSourceRange(bb_, &source_range));
  EXPECT_EQ(0, source_range.size());
}

TEST_F(BlockUtilTest, GetBasicBlockSourceRangeNonContiguousFails) {
  BlockGraph::Size instr_len = AddInstructions(true);

  // Make the range non-contiguous by pushing the successor out one byte.
  BlockGraph::Block::SourceRange range =
      bb_.successors().front().source_range();
  bb_.successors().front().set_source_range(
      BlockGraph::Block::SourceRange(range.start() + 1, range.size()));

  BlockGraph::Block::SourceRange source_range;
  ASSERT_FALSE(GetBasicBlockSourceRange(bb_, &source_range));
  EXPECT_EQ(0, source_range.size());
}

TEST_F(BlockUtilTest, GetBasicBlockSourceRangeSequentialSucceeds) {
  BlockGraph::Size instr_len = AddInstructions(true);

  BlockGraph::Block::SourceRange source_range;
  ASSERT_TRUE(GetBasicBlockSourceRange(bb_, &source_range));
  BlockGraph::Block::SourceRange expected_range(
      BlockGraph::RelativeAddress(0xF00D), instr_len);
  EXPECT_EQ(expected_range, source_range);
}

TEST_F(BlockUtilTest, GetBasicBlockSourceRangeNonSequentialSucceeds) {
  BlockGraph::Size instr_len = AddInstructions(true);

  // Shuffle the ranges by flipping the first and last ranges.
  BlockGraph::Block::SourceRange temp = bb_.successors().front().source_range();
  bb_.successors().front().set_source_range(
      bb_.instructions().front().source_range());
  bb_.instructions().front().set_source_range(temp);

  BlockGraph::Block::SourceRange source_range;
  ASSERT_TRUE(GetBasicBlockSourceRange(bb_, &source_range));
  BlockGraph::Block::SourceRange expected_range(
      BlockGraph::RelativeAddress(0xF00D), instr_len);
  EXPECT_EQ(expected_range, source_range);
}

TEST_F(BlockUtilTest, GetBasicBlockSourceRangePrependInstructionsSucceeds) {
  BlockGraph::Size instr_len = AddInstructions(true);

  // Prepend some instrumentation-like code.
  BasicBlockAssembler assm(bb_.instructions().begin(), &bb_.instructions());
  assm.push(Immediate(0xBADF00D));
  assm.call(Displacement(&bb_));

  BlockGraph::Block::SourceRange source_range;
  ASSERT_TRUE(GetBasicBlockSourceRange(bb_, &source_range));
  BlockGraph::Block::SourceRange expected_range(
      BlockGraph::RelativeAddress(0xF00D), instr_len);
  EXPECT_EQ(expected_range, source_range);
}

}  // namespace block_graph
