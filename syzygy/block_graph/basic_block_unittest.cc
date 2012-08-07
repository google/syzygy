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
#include "syzygy/core/assembler.h"

#include "distorm.h"  // NOLINT
#include "mnemonics.h"  // NOLINT

namespace block_graph {

namespace {

using core::AbsoluteAddress;

class BasicBlockTest: public testing::Test {
 public:
  // Initializes this fixture.
  //
  // Note that each test invocation is its own unique instance of this
  // fixture, so each will have its own fresh instance of basic_code_block_
  // and macro_block_ to play with.
  BasicBlockTest()
      : basic_code_block_(kBlockId, kBlockName, BasicBlock::BASIC_CODE_BLOCK,
                          kBlockOffset, kBlockSize, kBlockData),
        basic_data_block_(kBlockId, kBlockName, BasicBlock::BASIC_DATA_BLOCK,
                          kBlockOffset, kBlockSize, kBlockData),
        macro_block_(kBlockId, kMacroBlockType, kBlockSize, kBlockName) {
     basic_data_block_.set_label(BlockGraph::Label(
         "data", BlockGraph::DATA_LABEL | BlockGraph::CASE_TABLE_LABEL));
  }

  // Convert @p opcode to a branch type.
  //
  // @returns FC_CND_BRANCH on conditional branch opcodes; FC_UNC_BRANCH on
  //     unconditional branch opcodes; or FC_NONE if the opocode is not a
  //     branch.
  static uint8 BranchToType(uint16 opcode) {
    switch (opcode) {
      // Unconditional branch instructions.
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
    static const uint8 data[] = { 0xC3 };
    Instruction::Representation ret = {};
    ret.addr = 0;
    ret.opcode = I_RET;
    ret.size = 1;
    META_SET_ISC(&ret, ISC_INTEGER);
    return Instruction(ret, -1, sizeof(data), data);
  }

  // Helper function to create a CALL instruction.
  Instruction CreateCall(BasicBlockReference ref) {
    static const uint8 data[] = { 0xE8, 0x00, 0x00, 0x00, 0x00 };
    Instruction::Representation call = {};
    call.addr = 0;
    call.opcode = I_CALL;
    call.size = 5;
    META_SET_ISC(&call, ISC_INTEGER);
    Instruction call_inst(call, -1, sizeof(data), data);
    call_inst.SetReference(1, ref);
    EXPECT_FALSE(call_inst.has_label());
    call_inst.set_label(BlockGraph::Label("call", BlockGraph::CALL_SITE_LABEL));
    EXPECT_TRUE(call_inst.has_label());
    EXPECT_TRUE(call_inst.label().has_attributes(BlockGraph::CALL_SITE_LABEL));
    return call_inst;
  }

  // Helper function to create a successor branch instruction.
  Successor CreateBranch(uint16 opcode, Successor::Offset target) {
    return Successor(Successor::OpCodeToCondition(opcode), target, -1, 0);
  }

  // Some handy constants we'll use throughout the tests.
  // @{
  static const BasicBlock::BlockId kBlockId;
  static const BasicBlock::BasicBlockType kBasicBlockType;
  static const BlockGraph::BlockType kMacroBlockType;
  static const char kBlockName[];
  static const BasicBlock::Offset kBlockOffset;
  static const BasicBlock::Size kBlockSize;
  static const uint8 kBlockData[];
  static const size_t kRefSize;
  static const Successor::Offset kOffset1;
  static const Successor::Offset kOffset2;
  // @}

 protected:
  BasicBlock basic_code_block_;
  BasicBlock basic_data_block_;
  BlockGraph::Block macro_block_;
};

const BasicBlock::BlockId BasicBlockTest::kBlockId = 1;
const BasicBlock::BasicBlockType BasicBlockTest::kBasicBlockType =
    BasicBlock::BASIC_CODE_BLOCK;
const BlockGraph::BlockType BasicBlockTest::kMacroBlockType =
    BlockGraph::CODE_BLOCK;
const char BasicBlockTest::kBlockName[] = "test block";
const BasicBlock::Offset BasicBlockTest::kBlockOffset = 0;
const BasicBlock::Size BasicBlockTest::kBlockSize = 32;
const uint8 BasicBlockTest::kBlockData[BasicBlockTest::kBlockSize] = {};
const size_t BasicBlockTest::kRefSize = BlockGraph::Reference::kMaximumSize;
const Successor::Offset BasicBlockTest::kOffset1(0xAABBCCDD);
const Successor::Offset BasicBlockTest::kOffset2(0x11223344);

}  // namespace

TEST_F(BasicBlockTest, InstructionConstructor) {
  Instruction ret_instr(CreateRet());
  ASSERT_FALSE(ret_instr.owns_data());

  {
    // This should not copy the data.
    Instruction ret_temp(ret_instr);
    ASSERT_FALSE(ret_temp.owns_data());
    ASSERT_EQ(ret_instr.data(), ret_temp.data());
  }

  {
    // Construction from data should make a copy of the data.
    Instruction ret_temp(ret_instr.size(), ret_instr.data());
    ASSERT_TRUE(ret_temp.owns_data());
    ASSERT_NE(ret_instr.data(), ret_temp.data());
  }

  {
    // This should copy the references.
    BasicBlockReference r1(
        BlockGraph::RELATIVE_REF, kRefSize, &basic_code_block_);
    Instruction call_instr = CreateCall(r1);
    ASSERT_TRUE(call_instr.references().size() == 1);
    Instruction call_temp(call_instr);
    ASSERT_EQ(call_instr.references(), call_temp.references());
  }
}

TEST_F(BasicBlockTest, BasicBlockAccessors) {
  EXPECT_EQ(kBlockId, basic_code_block_.id());
  EXPECT_EQ(kBasicBlockType, basic_code_block_.type());
  EXPECT_STREQ(kBlockName, basic_code_block_.name().c_str());
  EXPECT_EQ(&kBlockData[0], basic_code_block_.data());
  EXPECT_EQ(kBlockSize, basic_code_block_.size());
  EXPECT_TRUE(basic_code_block_.references().empty());
  EXPECT_TRUE(basic_code_block_.referrers().empty());
  EXPECT_FALSE(basic_code_block_.has_label());
  EXPECT_TRUE(basic_data_block_.has_label());
  EXPECT_TRUE(basic_data_block_.label().has_attributes(
      BlockGraph::DATA_LABEL | BlockGraph::CASE_TABLE_LABEL));
}

TEST_F(BasicBlockTest, GetMaxCodeSize) {
  basic_code_block_.instructions().push_back(CreateRet());
  basic_code_block_.instructions().push_back(CreateRet());
  basic_code_block_.instructions().push_back(CreateRet());
  basic_code_block_.instructions().push_back(CreateRet());
  basic_code_block_.successors().push_back(CreateBranch(I_JZ, kOffset1));

  ASSERT_EQ(4 * CreateRet().size() + core::AssemblerImpl::kMaxInstructionLength,
            basic_code_block_.GetMaxSize());
}

TEST_F(BasicBlockTest, GetMaxDataSize) {
  BasicBlock bb(kBlockId, kBlockName, BasicBlock::BASIC_DATA_BLOCK,
                kBlockOffset, kBlockSize, kBlockData);

  ASSERT_EQ(kBlockSize, bb.GetMaxSize());
}

TEST_F(BasicBlockTest, EmptyBasicBlockIsNotValid) {
  // Upon creation the basic block (which happens to be a code block) has
  // neither instructions nor successors, which we consider to be an invalid
  // state.
  ASSERT_FALSE(basic_code_block_.IsValid());
}

TEST_F(BasicBlockTest, BasicBlockWithOnlyConditionalSuccessorIsNotValid) {
  basic_code_block_.successors().push_back(CreateBranch(I_JNZ, kOffset1));
  ASSERT_FALSE(basic_code_block_.IsValid());
}

TEST_F(BasicBlockTest,
       BasicBlockWithConditionalAndFallThroughSuccessorsIsValid) {
  basic_code_block_.successors().push_back(CreateBranch(I_JNZ, kOffset1));
  basic_code_block_.successors().push_back(CreateBranch(I_JZ, kOffset2));
  ASSERT_TRUE(basic_code_block_.IsValid());
}

TEST_F(BasicBlockTest,
       BasicBlockWithFallThroughSuccessorIsValid) {
  basic_code_block_.successors().push_back(CreateBranch(I_JMP, kOffset2));
  ASSERT_TRUE(basic_code_block_.IsValid());
}

TEST_F(BasicBlockTest,
       BasicBlockWithTerminalInstructionNoSuccessorsIsValid) {
  basic_code_block_.instructions().push_back(CreateRet());
  ASSERT_TRUE(basic_code_block_.IsValid());
}

TEST_F(BasicBlockTest, InvalidBasicBlockReference) {
  // Validate that a ref that points to nothing is not valid and doesn't claim
  // to point to anything.
  BasicBlockReference ref;
  EXPECT_EQ(BasicBlockReference::REFERRED_TYPE_UNKNOWN, ref.referred_type());
  EXPECT_EQ(NULL, ref.block());
  EXPECT_EQ(NULL, ref.basic_block());
  EXPECT_EQ(-1, ref.offset());
  EXPECT_EQ(0, ref.size());
  EXPECT_FALSE(ref.IsValid());
}

TEST_F(BasicBlockTest, BasicBlockReference) {
  BasicBlockReference ref(BlockGraph::RELATIVE_REF,
                          kRefSize,
                          &basic_code_block_);

  EXPECT_EQ(BasicBlockReference::REFERRED_TYPE_BASIC_BLOCK,
            ref.referred_type());
  EXPECT_EQ(NULL, ref.block());
  EXPECT_EQ(&basic_code_block_, ref.basic_block());
  EXPECT_EQ(kRefSize, ref.size());
  EXPECT_EQ(0, ref.offset());
  EXPECT_EQ(0, ref.base());
  EXPECT_TRUE(ref.IsValid());
}

TEST_F(BasicBlockTest, BlockReference) {
  static const BasicBlockReference::Offset kOffset = 48;
  static const BasicBlockReference::Offset kBase = kBlockSize / 2;

  BasicBlockReference ref(BlockGraph::RELATIVE_REF,
                          kRefSize,
                          &macro_block_,
                          kOffset,
                          kBase);

  EXPECT_EQ(BasicBlockReference::REFERRED_TYPE_BLOCK, ref.referred_type());
  EXPECT_EQ(NULL, ref.basic_block());
  EXPECT_EQ(&macro_block_, ref.block());
  EXPECT_EQ(kRefSize, ref.size());
  EXPECT_EQ(kOffset, ref.offset());
  EXPECT_EQ(kBase, ref.base());
  EXPECT_TRUE(ref.IsValid());
}

TEST_F(BasicBlockTest, CompareBasicBlockReferences) {
  BasicBlockReference r1(
      BlockGraph::RELATIVE_REF, kRefSize, &basic_code_block_);
  BasicBlockReference r2(
      BlockGraph::RELATIVE_REF, kRefSize, &basic_code_block_);
  BasicBlockReference r3(
      BlockGraph::RELATIVE_REF, kRefSize, &macro_block_, 8, 8);

  EXPECT_TRUE(r1 == r2);
  EXPECT_TRUE(r2 == r1);
  EXPECT_FALSE(r2 == r3);
  EXPECT_FALSE(r3 == r1);
}

TEST_F(BasicBlockTest, InvalidBasicBlockReferrer) {
  // Validate that an empty referrer is not valid.
  BasicBlockReferrer referrer;
  EXPECT_EQ(BasicBlockReference::REFERRED_TYPE_UNKNOWN,
            referrer.referrer_type());
  EXPECT_EQ(NULL, referrer.block());
  EXPECT_EQ(NULL, referrer.basic_block());
  EXPECT_EQ(-1, referrer.offset());
  EXPECT_FALSE(referrer.IsValid());
}

TEST_F(BasicBlockTest, BasicBlockReferrer) {
  static const BasicBlockReference::Offset kOffset = kBlockSize / 2;

  BasicBlockReferrer referrer(&basic_data_block_, kOffset);

  EXPECT_EQ(BasicBlockReferrer::REFERRER_TYPE_BASIC_BLOCK,
            referrer.referrer_type());
  EXPECT_EQ(NULL, referrer.block());
  EXPECT_EQ(NULL, referrer.successor());
  EXPECT_EQ(NULL, referrer.instruction());
  EXPECT_EQ(&basic_data_block_, referrer.basic_block());
  EXPECT_EQ(kOffset, referrer.offset());
  EXPECT_TRUE(referrer.IsValid());
}

TEST_F(BasicBlockTest, BlockReferrer) {
  static const BasicBlockReference::Offset kOffset = kBlockSize / 2;

  BasicBlockReferrer referrer(&macro_block_, kOffset);

  EXPECT_EQ(BasicBlockReferrer::REFERRER_TYPE_BLOCK, referrer.referrer_type());
  EXPECT_EQ(NULL, referrer.basic_block());
  EXPECT_EQ(NULL, referrer.successor());
  EXPECT_EQ(NULL, referrer.instruction());
  EXPECT_EQ(&macro_block_, referrer.block());
  EXPECT_EQ(kOffset, referrer.offset());
  EXPECT_TRUE(referrer.IsValid());
}

TEST_F(BasicBlockTest, InstructionReferrer) {
  static const BasicBlockReference::Offset kOffset = 2;
  Instruction instr(Instruction::Representation(), kOffset, 5, kBlockData);
  BasicBlockReferrer referrer(&instr, kOffset);

  EXPECT_EQ(BasicBlockReferrer::REFERRER_TYPE_INSTRUCTION,
            referrer.referrer_type());
  EXPECT_EQ(NULL, referrer.basic_block());
  EXPECT_EQ(NULL, referrer.block());
  EXPECT_EQ(NULL, referrer.successor());
  EXPECT_EQ(&instr, referrer.instruction());
  EXPECT_EQ(kOffset, referrer.offset());
  EXPECT_TRUE(referrer.IsValid());
}

TEST_F(BasicBlockTest, SuccessorReferrer) {
  Successor succ(Successor::kConditionGreater, -12, 5, 5);
  BasicBlockReferrer referrer(&succ);

  EXPECT_EQ(BasicBlockReferrer::REFERRER_TYPE_SUCCESSOR,
            referrer.referrer_type());
  EXPECT_EQ(NULL, referrer.basic_block());
  EXPECT_EQ(NULL, referrer.block());
  EXPECT_EQ(NULL, referrer.instruction());
  EXPECT_EQ(&succ, referrer.successor());
  EXPECT_EQ(BasicBlock::kNoOffset, referrer.offset());
  EXPECT_TRUE(referrer.IsValid());
}

TEST_F(BasicBlockTest, CompareBasicBlockRefererrs) {
  BasicBlockReferrer r1(&basic_data_block_, 4);
  BasicBlockReferrer r2(&basic_data_block_, 4);
  BasicBlockReferrer r3(&macro_block_, 8);

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
  EXPECT_EQ(-1, s.bb_target_offset());
  EXPECT_EQ(BasicBlockReference(), s.reference());
  EXPECT_EQ(-1, s.instruction_offset());
  EXPECT_EQ(0, s.instruction_size());
}

TEST(Successor, OffsetConstructor) {
  const Successor::Condition kCondition = Successor::kConditionAbove;
  const Successor::Offset kTargetOffset(0x12345678);
  const Successor::Offset kInstructinOffset = 32;
  const Successor::Size kInstructionSize = 5;

  Successor s(kCondition,
              kTargetOffset,
              kInstructinOffset,
              kInstructionSize);

  EXPECT_EQ(kCondition, s.condition());
  EXPECT_EQ(kTargetOffset, s.bb_target_offset());
  EXPECT_EQ(BasicBlockReference(), s.reference());
  EXPECT_EQ(kInstructinOffset, s.instruction_offset());
  EXPECT_EQ(kInstructionSize, s.instruction_size());
}

TEST(Successor, BasicBlockConstructor) {
  const Successor::Condition kCondition = Successor::kConditionAbove;
  const Successor::Offset kSuccessorOffset = 4;
  const Successor::Size kSuccessorSize = 5;
  uint8 data[20] = {};
  BasicBlock bb(1, "bb", BasicBlock::BASIC_CODE_BLOCK, 16, sizeof(data), data);
  BasicBlockReference bb_ref(BlockGraph::ABSOLUTE_REF, 4, &bb);

  Successor s(kCondition,
              bb_ref,
              kSuccessorOffset,
              kSuccessorSize);

  EXPECT_EQ(kCondition, s.condition());
  EXPECT_EQ(-1, s.bb_target_offset());
  EXPECT_EQ(bb_ref, s.reference());
  EXPECT_EQ(kSuccessorOffset, s.instruction_offset());
  EXPECT_EQ(kSuccessorSize, s.instruction_size());
}

TEST(Successor, SetBranchTarget) {
  uint8 data[20] = {};
  BasicBlock bb(1, "bb", BasicBlock::BASIC_CODE_BLOCK, 16, sizeof(data), data);
  BasicBlockReference bb_ref(BlockGraph::ABSOLUTE_REF, 4, &bb);

  Successor s;
  s.SetReference(bb_ref);
  EXPECT_EQ(bb_ref, s.reference());
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
  // expect is two less than the total number of branch types.
  COMPILE_ASSERT(
      arraysize(kOpCodeToConditionTable) == Successor::kMaxCondition - 2,
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

TEST(InstructionTest, CallsNonReturningFunction) {
  // Create a returning code block.
  BlockGraph::Block returning(0, BlockGraph::CODE_BLOCK, 1, "return");

  // Create a non-returning code block.
  BlockGraph::Block non_returning(1, BlockGraph::CODE_BLOCK, 1, "non-return");
  non_returning.set_attribute(BlockGraph::NON_RETURN_FUNCTION);

  _DInst repr = {};
  repr.opcode = I_CALL;
  repr.meta = FC_CALL;
  repr.ops[0].type = O_PC;
  const uint8 kCallRelative[] = { 0xE8, 0xDE, 0xAD, 0xBE, 0xEF };
  Instruction call_relative(repr, 0, sizeof(kCallRelative), kCallRelative);

  // Call the returning function directly.
  call_relative.SetReference(
      1, BasicBlockReference(BlockGraph::RELATIVE_REF,
                             BlockGraph::Reference::kMaximumSize,
                             &returning, 0, 0));
  EXPECT_FALSE(call_relative.CallsNonReturningFunction());

  // Call the non-returning function directly.
  call_relative.SetReference(
      1, BasicBlockReference(BlockGraph::RELATIVE_REF,
                             BlockGraph::Reference::kMaximumSize,
                             &non_returning, 0, 0));
  EXPECT_TRUE(call_relative.CallsNonReturningFunction());

  // Setup an indirect call via a static function pointer (for example, an
  // import table).
  repr.ops[0].type = O_DISP;
  BlockGraph::Block function_pointer(
      2, BlockGraph::DATA_BLOCK, BlockGraph::Reference::kMaximumSize, "ptr");
  const uint8 kCallIndirect[] = { 0xFF, 0x15, 0xDE, 0xAD, 0xBE, 0xEF };
  Instruction call_indirect(repr, 0, sizeof(kCallIndirect), kCallIndirect);
  call_indirect.SetReference(
      2, BasicBlockReference(BlockGraph::RELATIVE_REF,
                             BlockGraph::Reference::kMaximumSize,
                             &function_pointer, 0, 0));

  // Call the returning function via the pointer.
  function_pointer.SetReference(
      0, BlockGraph::Reference(BlockGraph::ABSOLUTE_REF,
                                BlockGraph::Reference::kMaximumSize,
                                &returning, 0, 0));
  EXPECT_FALSE(call_indirect.CallsNonReturningFunction());

  // Call the returning function via the pointer.
  function_pointer.SetReference(
      0, BlockGraph::Reference(BlockGraph::ABSOLUTE_REF,
                                BlockGraph::Reference::kMaximumSize,
                                &non_returning, 0, 0));
  EXPECT_TRUE(call_indirect.CallsNonReturningFunction());
}

}  // namespace block_graph
