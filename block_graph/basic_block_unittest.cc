// Copyright 2011 Google Inc.
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

  // Helper function to create a branching instruction.
  Instruction CreateBranch(uint16 opcode, core::AbsoluteAddress target) {
    Instruction::Representation branch = {};
    branch.addr = 0;
    branch.opcode = opcode;
    branch.ops[0].type = O_IMM;
    branch.ops[0].size = 32;
    branch.size = sizeof(branch.opcode) + sizeof(void*);
    branch.imm.addr = target.value();
    branch.meta = BranchToType(opcode);
    META_SET_ISC(&branch, ISC_INTEGER);
    return Instruction(branch, Instruction::SourceRange());
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
  basic_block_.successors().push_back(CreateBranch(I_JMP, kAddr2));
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
  EXPECT_FALSE(ref.RefersToBasicBlock());
  EXPECT_FALSE(ref.RefersToMacroBlock());
}

TEST_F(BasicBlockTest, MacroBlockReference) {
  BasicBlockReference ref(BlockGraph::RELATIVE_REF, kRefSize, &macro_block_, 0);

  EXPECT_TRUE(ref.IsValid());
  EXPECT_FALSE(ref.RefersToBasicBlock());
  EXPECT_TRUE(ref.RefersToMacroBlock());
}

TEST_F(BasicBlockTest, BasicBlockReference) {
  BasicBlockReference ref(BlockGraph::RELATIVE_REF, kRefSize, &basic_block_, 0);

  EXPECT_TRUE(ref.IsValid());
  EXPECT_TRUE(ref.RefersToBasicBlock());
  EXPECT_FALSE(ref.RefersToMacroBlock());
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

}  // namespace block_graph
