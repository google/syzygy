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
// Tests for the basic block classes.

#include "syzygy/block_graph/basic_block.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "distorm.h"  // NOLINT
#include "mnemonics.h"  // NOLINT

namespace block_graph {

using core::AbsoluteAddress;

class BasicBlockTest: public testing::Test {
 public:
  // Initializes this fixture.
  //
  // Note that each test invocation is its own unique instance of this
  // fixture, so each will have it's on fresh instance of basic_block_
  // and macro_block_ to play with.
  BasicBlockTest()
      : basic_block_(
            kBlockId, kBasicBlockType, kBlockData, kBlockSize, kBlockName),
        macro_block_(kBlockId, kMacroBlockType, kBlockSize, kBlockName) {
  }

  // Convert @p opcode to a branch type.
  //
  // @returns FC_CND_BRANCH on conditional branch opcodes; FC_UNC_BRANCH on
  //     unconditional branch opcodes; or FC_NONE if the opocode is not a
  //     branch.
  static uint8 BranchToType(uint16 opcode) {
    switch (opcode) {
      // Uncoditional branch instructions.
      case I_JMP:
      case I_JMP_FAR:
        return FC_UNC_BRANCH;

      // Conditional branch instructions.
      case I_JA:   // Equivalent to JNBE
      case I_JAE:  // Equivalent to JNB and JNC.
      case I_JB:   // Equivalent to JNAE and JC.
      case I_JBE:  // Equivalent to JNA.
      case I_JCXZ:
      case I_JECXZ:
      case I_JG:   // Equivalent to JNLE.
      case I_JGE:  // Equivalent to JNL.
      case I_JL:   // Equivalent to I_JNGE.
      case I_JLE:  // Equivalent to JNG.
      case I_JNO:
      case I_JNP:  // Equivalent to JPO.
      case I_JNS:
      case I_JNZ:  // Equivalent to JNE.
      case I_JO:
      case I_JP:   // Equivalent to JPE.
      case I_JS:
      case I_JZ:   // Equivalent to JE.
      case I_LOOP:
      case I_LOOPNZ:
      case I_LOOPZ:
        return FC_CND_BRANCH;

      // Everything else.
      default:
        ADD_FAILURE() << "Unexpected opcode: " << opcode << ".";
        return FC_NONE;
    }
  }

  // Helper function to create a RET instruction.
  Instruction CreateRet() {
    Instruction::Representation ret = {};
    ret.addr = 0;
    ret.opcode = I_RET;
    ret.size = 1;
    META_SET_ISC(&ret, ISC_INTEGER);
    return Instruction(ret, Instruction::SourceRange());
  }

  // Helper function to create a successor branch instruction.
  Successor CreateBranch(uint16 opcode, core::AbsoluteAddress target) {
    return Successor(Successor::OpCodeToCondition(opcode),
                     target,
                     Successor::SourceRange());
  }

  // Some handy constants we'll use throughout the tests.
  // @{
  static const BasicBlock::BlockId kBlockId;
  static const BasicBlock::BlockType kBasicBlockType;
  static const BasicBlock::BlockType kMacroBlockType;
  static const char kBlockName[];
  static const size_t kBlockSize;
  static const uint8 kBlockData[];
  static const size_t kRefSize;
  static const AbsoluteAddress kAddr1;
  static const AbsoluteAddress kAddr2;
  // @}

 protected:
  BasicBlock basic_block_;
  BlockGraph::Block macro_block_;
};

const BasicBlock::BlockId BasicBlockTest::kBlockId = 1;
const BasicBlock::BlockType BasicBlockTest::kBasicBlockType =
    BlockGraph::BASIC_CODE_BLOCK;
const BasicBlock::BlockType BasicBlockTest::kMacroBlockType =
    BlockGraph::CODE_BLOCK;
const char BasicBlockTest::kBlockName[] = "test block";
const size_t BasicBlockTest::kBlockSize = 32;
const uint8 BasicBlockTest::kBlockData[BasicBlockTest::kBlockSize] = {};
const size_t BasicBlockTest::kRefSize = BlockGraph::Reference::kMaximumSize;
const AbsoluteAddress BasicBlockTest::kAddr1(0xAABBCCDD);
const AbsoluteAddress BasicBlockTest::kAddr2(0x11223344);

TEST_F(BasicBlockTest, BasicBlockAccessors) {
  EXPECT_EQ(kBlockId, basic_block_.id());
  EXPECT_EQ(kBasicBlockType, basic_block_.type());
  EXPECT_STREQ(kBlockName, basic_block_.name());
  EXPECT_EQ(&kBlockData[0], basic_block_.data());
  EXPECT_EQ(kBlockSize, basic_block_.size());
}

TEST_F(BasicBlockTest, EmptyBasicBlockIsNotValid) {
  // Upon creation the basic block (which happens to be a code block) has
  // neither instructions nor successors, which we consider to be an invalid
  // state.
  ASSERT_FALSE(basic_block_.IsValid());
}

TEST_F(BasicBlockTest, BasicBlockWithOnlyConditionalSuccessorIsNotValid) {
  basic_block_.successors().push_back(CreateBranch(I_JNZ, kAddr1));
  ASSERT_FALSE(basic_block_.IsValid());
}

TEST_F(BasicBlockTest,
       BasicBlockWithConditionalAndFallThroughSuccessorsIsValid) {
  basic_block_.successors().push_back(CreateBranch(I_JNZ, kAddr1));
  basic_block_.successors().push_back(CreateBranch(I_JZ, kAddr2));
  ASSERT_TRUE(basic_block_.IsValid());
}

TEST_F(BasicBlockTest,
       BasicBlockWithFallThroughSuccessorIsValid) {
  basic_block_.successors().push_back(CreateBranch(I_JMP, kAddr2));
  ASSERT_TRUE(basic_block_.IsValid());
}

TEST_F(BasicBlockTest,
       BasicBlockWithTerminalInstructionNoSuccessorsIsValid) {
  basic_block_.instructions().push_back(CreateRet());
  ASSERT_TRUE(basic_block_.IsValid());
}

TEST_F(BasicBlockTest, InvalidBasicBlockReference) {
  // Validate that a ref that points to nothing is not valid and doesn't claim
  // to point to anything.
  BasicBlockReference ref;
  EXPECT_FALSE(ref.IsValid());
}

TEST_F(BasicBlockTest, BasicBlockReference) {
  BasicBlockReference ref(BlockGraph::RELATIVE_REF, kRefSize, &basic_block_, 0);

  EXPECT_TRUE(ref.IsValid());
}

TEST_F(BasicBlockTest, CompareBasicBlockReferences) {
  BasicBlockReference r1(BlockGraph::RELATIVE_REF, kRefSize, &basic_block_, 0);
  BasicBlockReference r2(BlockGraph::RELATIVE_REF, kRefSize, &basic_block_, 0);
  BasicBlockReference r3(BlockGraph::RELATIVE_REF, kRefSize, &basic_block_, 4);

  EXPECT_TRUE(r1 == r2);
  EXPECT_TRUE(r2 == r1);
  EXPECT_FALSE(r2 == r3);
  EXPECT_FALSE(r3 == r1);
}

TEST_F(BasicBlockTest, InvertConditionalBranchOpcode) {
  // This structure represents an entry in the opcode inversion table that
  // we'll use to drive the opcode inversion unit-test.
  struct OpcodeInversion {
    // The original opcode.
    uint16 original;

    // The inverted opcode. It will be zero (0) if the opcode isn't invertible.
    uint16 inverted;
  };

  static const OpcodeInversion kOpcodeInversionTable[] = {
      // We'll only encode one direction, and the test will infer the reverse.
      { I_JA, I_JBE },
      { I_JAE, I_JB },
      { I_JG, I_JLE },
      { I_JGE, I_JL },
      { I_JO, I_JNO },
      { I_JP, I_JNP, },
      { I_JS, I_JNS, },
      { I_JZ, I_JNZ, },

      // @TODO(rogerm): These opcodes are not supported yet.
      { I_JCXZ, 0 },
      { I_JECXZ, 0 },
      { I_LOOP, 0 },
      { I_LOOPNZ, 0 },
      { I_LOOPZ, 0 },

      // These opcodes are not invertible.
      { I_CALL, 0 },
      { I_MOV, 0 },
      { I_RET, 0 },
  };

  // Walk through the table validating that the InvertConditionalBranchOpcode()
  // function returns the same inversion results.
  for (int i = 0; i < arraysize(kOpcodeInversionTable); ++i) {
    uint16 opcode = kOpcodeInversionTable[i].original;
    bool should_pass = kOpcodeInversionTable[i].inverted != 0;
    EXPECT_EQ(should_pass,
              Instruction::InvertConditionalBranchOpcode(&opcode));
    if (should_pass) {
      EXPECT_EQ(kOpcodeInversionTable[i].inverted, opcode);
      EXPECT_TRUE(Instruction::InvertConditionalBranchOpcode(&opcode));
      EXPECT_EQ(kOpcodeInversionTable[i].original, opcode);
    }
  }
}

TEST(Successor, DefaultConstructor) {
  Successor s;
  EXPECT_EQ(Successor::kInvalidCondition, s.condition());
  EXPECT_EQ(Successor::AbsoluteAddress(), s.original_target_address());
  EXPECT_EQ(NULL, s.branch_target());
  EXPECT_EQ(Successor::SourceRange(), s.source_range());
}

TEST(Successor, AddressConstructor) {
  const Successor::Condition kCondition = Successor::kConditionAbove;
  const Successor::AbsoluteAddress kAddr(0x12345678);
  const Successor::SourceRange kRange(kAddr, 32);
  Successor s(Successor::kConditionAbove, kAddr, kRange);

  EXPECT_EQ(kCondition, s.condition());
  EXPECT_EQ(kAddr, s.original_target_address());
  EXPECT_EQ(NULL, s.branch_target());
  EXPECT_EQ(kRange, s.source_range());
}

TEST(Successor, BasicBlockConstructor) {
  const Successor::Condition kCondition = Successor::kConditionAbove;
  const Successor::AbsoluteAddress kAddr(0x12345678);
  const Successor::SourceRange kRange(kAddr, 32);

  uint8 data[20] = {};
  BasicBlock bb(1, BlockGraph::BASIC_CODE_BLOCK, data, sizeof(data), "bb");

  Successor s(Successor::kConditionAbove, &bb, kRange);

  EXPECT_EQ(kCondition, s.condition());
  EXPECT_EQ(Successor::AbsoluteAddress(), s.original_target_address());
  EXPECT_EQ(&bb, s.branch_target());
  EXPECT_EQ(kRange, s.source_range());
}

TEST(Successor, SetBranchTarget) {
  uint8 data[20] = {};
  BasicBlock bb(1, BlockGraph::BASIC_CODE_BLOCK, data, sizeof(data), "bb");

  Successor s;
  s.set_branch_target(&bb);
  EXPECT_EQ(&bb, s.branch_target());
}

TEST(Successor, OpCodeToCondition) {
  struct TableEntry {
    uint16 op_code;
    Successor::Condition condition;
  };

  const TableEntry kOpCodeToConditionTable[] = {
      { I_MOV, Successor::kInvalidCondition },
      { I_JMP, Successor::kConditionTrue },
      { I_JA, Successor::kConditionAbove },
      { I_JAE, Successor::kConditionAboveOrEqual },
      { I_JB, Successor::kConditionBelow },
      { I_JBE, Successor::kConditionBelowOrEqual },
      { I_JCXZ, Successor::kCounterIsZero },
      { I_JECXZ, Successor::kCounterIsZero },
      { I_JG, Successor::kConditionGreater },
      { I_JGE, Successor::kConditionGreaterOrEqual },
      { I_JL, Successor::kConditionLess },
      { I_JLE, Successor::kConditionLessOrEqual },
      { I_JNO, Successor::kConditionNotOverflow },
      { I_JNP, Successor::kConditionNotParity },
      { I_JNS, Successor::kConditionNotSigned },
      { I_JNZ, Successor::kConditionNotEqual },
      { I_JO, Successor::kConditionOverflow },
      { I_JP, Successor::kConditionParity },
      { I_JS, Successor::kConditionSigned },
      { I_JZ, Successor::kConditionEqual },
      { I_LOOP, Successor::kLoopTrue },
      { I_LOOPNZ, Successor::kLoopIfNotEqual },
      { I_LOOPZ, Successor::kLoopIfEqual },
  };

  // Four conditions do not have an corresponding instruction (the four symbolic
  // inverses kInverseCounterIsZero, kInverseLoop, kInverseLoopIfEqual, and
  // kInverseLoopIfNotEqual); two instructions map to kCounterIsZero; and we
  // test kInvalidCondition with MOV. So the total number of instructions we
  // expect is three less than the total number of branch types.
  COMPILE_ASSERT(
      arraysize(kOpCodeToConditionTable) == Successor::kMaxCondition - 3,
      unexpected_number_of_map_entries);

  for (size_t i = 0; i < arraysize(kOpCodeToConditionTable); ++i) {
    const TableEntry& entry = kOpCodeToConditionTable[i];
    EXPECT_EQ(entry.condition, Successor::OpCodeToCondition(entry.op_code));
  }
}

TEST(Successor, InvertCondition) {
  struct TableEntry {
    Successor::Condition original;
    Successor::Condition inverse;
  };
  static const TableEntry kConditionInversionTable[] = {
      { Successor::kInvalidCondition, Successor::kInvalidCondition },
      { Successor::kConditionTrue, Successor::kInvalidCondition },
      { Successor::kConditionAbove, Successor::kConditionBelowOrEqual },
      { Successor::kConditionAboveOrEqual, Successor::kConditionBelow },
      { Successor::kConditionBelow, Successor::kConditionAboveOrEqual },
      { Successor::kConditionBelowOrEqual, Successor::kConditionAbove },
      { Successor::kConditionEqual, Successor::kConditionNotEqual },
      { Successor::kConditionGreater, Successor::kConditionLessOrEqual },
      { Successor::kConditionGreaterOrEqual, Successor::kConditionLess },
      { Successor::kConditionLess, Successor::kConditionGreaterOrEqual },
      { Successor::kConditionLessOrEqual, Successor::kConditionGreater },
      { Successor::kConditionNotEqual, Successor::kConditionEqual },
      { Successor::kConditionNotOverflow, Successor::kConditionOverflow },
      { Successor::kConditionNotParity, Successor::kConditionParity },
      { Successor::kConditionNotSigned, Successor::kConditionSigned },
      { Successor::kConditionOverflow, Successor::kConditionNotOverflow },
      { Successor::kConditionParity, Successor::kConditionNotParity },
      { Successor::kConditionSigned, Successor::kConditionNotSigned },
      { Successor::kCounterIsZero, Successor::kInverseCounterIsZero },
      { Successor::kLoopTrue, Successor::kInverseLoopTrue },
      { Successor::kLoopIfEqual, Successor::kInverseLoopIfEqual },
      { Successor::kLoopIfNotEqual, Successor::kInverseLoopIfNotEqual },
      { Successor::kInverseCounterIsZero, Successor::kCounterIsZero },
      { Successor::kInverseLoopTrue, Successor::kLoopTrue },
      { Successor::kInverseLoopIfEqual, Successor::kLoopIfEqual },
      { Successor::kInverseLoopIfNotEqual, Successor::kLoopIfNotEqual },
  };

  COMPILE_ASSERT(
      arraysize(kConditionInversionTable) == Successor::kMaxCondition,
      unexpected_number_of_inversion_table_entries);

  for (size_t i = 0; i < arraysize(kConditionInversionTable); ++i) {
    const TableEntry& entry = kConditionInversionTable[i];
    EXPECT_EQ(entry.inverse, Successor::InvertCondition(entry.original));
  }
}

}  // namespace block_graph
