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
// Tests for the basic block classes.

#include "syzygy/block_graph/basic_block.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/block_graph/basic_block_assembler.h"
#include "syzygy/block_graph/basic_block_subgraph.h"

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
      : basic_code_block_(NULL),
        basic_data_block_(NULL),
        macro_block_(NULL) {
    macro_block_ = block_graph_.AddBlock(
        kMacroBlockType, kBlockSize, kBlockName);
    basic_code_block_ = subgraph_.AddBasicCodeBlock(kBlockName);
    basic_data_block_ =
        subgraph_.AddBasicDataBlock(kBlockName, kBlockSize, kBlockData);
    basic_data_block_->set_label(BlockGraph::Label(
        "data", BlockGraph::DATA_LABEL | BlockGraph::CASE_TABLE_LABEL));
    basic_end_block_ =
        subgraph_.AddBasicEndBlock();
    basic_end_block_->set_label(BlockGraph::Label(
        "end", BlockGraph::DEBUG_END_LABEL));
  }

  // Convert @p opcode to a branch type.
  //
  // @returns FC_CND_BRANCH on conditional branch opcodes; FC_UNC_BRANCH on
  //     unconditional branch opcodes; or FC_NONE if the opcode is not a
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
      case I_JL:   // Equivalent to JNGE.
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
    Instruction temp;
    EXPECT_TRUE(Instruction::FromBuffer(data, sizeof(data), &temp));
    EXPECT_TRUE(temp.IsReturn());
    return temp;
  }

  // Helper function to create a CALL instruction.
  Instruction CreateCall(BasicBlockReference ref) {
    static const uint8 data[] = { 0xE8, 0x00, 0x00, 0x00, 0x00 };
    Instruction call_inst;
    EXPECT_TRUE(Instruction::FromBuffer(data, sizeof(data), &call_inst));
    EXPECT_TRUE(call_inst.IsCall());
    call_inst.SetReference(1, ref);
    EXPECT_FALSE(call_inst.has_label());
    call_inst.set_label(BlockGraph::Label("call", BlockGraph::CALL_SITE_LABEL));
    EXPECT_TRUE(call_inst.has_label());
    EXPECT_TRUE(call_inst.label().has_attributes(BlockGraph::CALL_SITE_LABEL));
    return call_inst;
  }

  // Helper function to create a successor branch.
  Successor CreateBranch(uint16 opcode, Successor::Offset target) {
    BasicBlockReference ref(BlockGraph::PC_RELATIVE_REF,
                            1,  // Size is immaterial in successors.
                            macro_block_,
                            target,
                            target);
    return Successor(Successor::OpCodeToCondition(opcode), ref, 0);
  }

  // Some handy constants we'll use throughout the tests.
  // @{
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
  BlockGraph block_graph_;
  BasicBlockSubGraph subgraph_;
  BasicCodeBlock* basic_code_block_;
  BasicDataBlock* basic_data_block_;
  BasicEndBlock* basic_end_block_;
  BlockGraph::Block* macro_block_;
};

const BasicBlock::BasicBlockType BasicBlockTest::kBasicBlockType =
    BasicBlock::BASIC_CODE_BLOCK;
const BlockGraph::BlockType BasicBlockTest::kMacroBlockType =
    BlockGraph::CODE_BLOCK;
const char BasicBlockTest::kBlockName[] = "test block";
const BasicBlock::Offset BasicBlockTest::kBlockOffset = 0;
const BasicBlock::Size BasicBlockTest::kBlockSize = 32;
const uint8 BasicBlockTest::kBlockData[BasicBlockTest::kBlockSize] = {};
const size_t BasicBlockTest::kRefSize = BlockGraph::Reference::kMaximumSize;
const Successor::Offset BasicBlockTest::kOffset1(kBlockSize / 3);
const Successor::Offset BasicBlockTest::kOffset2(kBlockSize / 2);

}  // namespace

TEST_F(BasicBlockTest, InstructionConstructor) {
  // This also tests Instruction::FromBuffer via CreateRet and CreateCall.
  Instruction nop;
  EXPECT_TRUE(nop.IsNop());
  EXPECT_EQ(1, nop.size());
  EXPECT_EQ(0x90, nop.data()[0]);

  Instruction ret_instr(CreateRet());

  ASSERT_TRUE(ret_instr.IsReturn());
  {
    // This should copy the references.
    BasicBlockReference r1(
        BlockGraph::RELATIVE_REF, kRefSize, basic_code_block_);
    Instruction call_instr = CreateCall(r1);
    ASSERT_EQ(1, call_instr.references().size());
    Instruction call_temp(call_instr);
    ASSERT_EQ(call_instr.references(), call_temp.references());
  }
}

TEST_F(BasicBlockTest, Cast) {
  // Declare pointer variables to let us select between the const/non-const
  // versions of the Cast method.
  BasicBlock* bb_ptr = NULL;
  const BasicBlock* const_bb_ptr = NULL;

  // Should gracefully handle NULL.
  EXPECT_EQ(NULL, BasicCodeBlock::Cast(bb_ptr));
  EXPECT_EQ(NULL, BasicCodeBlock::Cast(const_bb_ptr));
  EXPECT_EQ(NULL, BasicDataBlock::Cast(bb_ptr));
  EXPECT_EQ(NULL, BasicDataBlock::Cast(const_bb_ptr));
  EXPECT_EQ(NULL, BasicEndBlock::Cast(bb_ptr));
  EXPECT_EQ(NULL, BasicEndBlock::Cast(const_bb_ptr));

  // Cast an underlying basic code block.
  bb_ptr = basic_code_block_;
  const_bb_ptr = basic_code_block_;
  EXPECT_EQ(basic_code_block_, BasicCodeBlock::Cast(bb_ptr));
  EXPECT_EQ(basic_code_block_, BasicCodeBlock::Cast(const_bb_ptr));
  EXPECT_EQ(NULL, BasicDataBlock::Cast(bb_ptr));
  EXPECT_EQ(NULL, BasicDataBlock::Cast(const_bb_ptr));
  EXPECT_EQ(NULL, BasicEndBlock::Cast(bb_ptr));
  EXPECT_EQ(NULL, BasicEndBlock::Cast(const_bb_ptr));

  // Should gracefully handle NULL.
  bb_ptr = basic_data_block_;
  const_bb_ptr = basic_data_block_;
  EXPECT_EQ(NULL, BasicCodeBlock::Cast(bb_ptr));
  EXPECT_EQ(NULL, BasicCodeBlock::Cast(const_bb_ptr));
  EXPECT_EQ(basic_data_block_, BasicDataBlock::Cast(bb_ptr));
  EXPECT_EQ(basic_data_block_, BasicDataBlock::Cast(const_bb_ptr));
  EXPECT_EQ(NULL, BasicEndBlock::Cast(bb_ptr));
  EXPECT_EQ(NULL, BasicEndBlock::Cast(const_bb_ptr));

  bb_ptr = basic_end_block_;
  const_bb_ptr = basic_end_block_;
  EXPECT_EQ(NULL, BasicCodeBlock::Cast(bb_ptr));
  EXPECT_EQ(NULL, BasicCodeBlock::Cast(bb_ptr));
  EXPECT_EQ(NULL, BasicDataBlock::Cast(bb_ptr));
  EXPECT_EQ(NULL, BasicDataBlock::Cast(const_bb_ptr));
  EXPECT_EQ(basic_end_block_, BasicEndBlock::Cast(bb_ptr));
  EXPECT_EQ(basic_end_block_, BasicEndBlock::Cast(const_bb_ptr));
}

TEST_F(BasicBlockTest, BasicCodeBlockAccessors) {
  EXPECT_EQ(BasicBlock::BASIC_CODE_BLOCK, basic_code_block_->type());
  EXPECT_STREQ(kBlockName, basic_code_block_->name().c_str());
  EXPECT_TRUE(basic_code_block_->referrers().empty());

  basic_code_block_->set_offset(kBlockSize);
  EXPECT_EQ(kBlockSize, basic_code_block_->offset());
}

TEST_F(BasicBlockTest, BasicDataBlockAccessors) {
  EXPECT_EQ(BasicBlock::BASIC_DATA_BLOCK, basic_data_block_->type());
  EXPECT_STREQ(kBlockName, basic_data_block_->name().c_str());
  EXPECT_EQ(&kBlockData[0], basic_data_block_->data());
  EXPECT_EQ(kBlockSize, basic_data_block_->size());
  EXPECT_EQ(BasicDataBlock::SourceRange(),
            basic_data_block_->source_range());
  EXPECT_TRUE(basic_data_block_->references().empty());
  EXPECT_TRUE(basic_data_block_->referrers().empty());
  EXPECT_TRUE(basic_data_block_->has_label());
  EXPECT_TRUE(basic_data_block_->label().has_attributes(
      BlockGraph::DATA_LABEL | BlockGraph::CASE_TABLE_LABEL));

  const BasicDataBlock::SourceRange
      kTestRange(core::RelativeAddress(0xF00D), 13);
  basic_data_block_->set_source_range(kTestRange);
  EXPECT_EQ(kTestRange, basic_data_block_->source_range());
}

TEST_F(BasicBlockTest, BasicEndBlockAccessors) {
  EXPECT_EQ(BasicBlock::BASIC_END_BLOCK, basic_end_block_->type());
  EXPECT_EQ("<end>", basic_end_block_->name());
  EXPECT_TRUE(basic_end_block_->references().empty());
  EXPECT_TRUE(basic_end_block_->referrers().empty());
  EXPECT_TRUE(basic_end_block_->has_label());
  EXPECT_TRUE(basic_end_block_->label().has_attributes(
      BlockGraph::DEBUG_END_LABEL));
}

TEST_F(BasicBlockTest, GetInstructionSize) {
  basic_code_block_->instructions().push_back(CreateRet());
  basic_code_block_->instructions().push_back(CreateRet());
  basic_code_block_->instructions().push_back(CreateRet());
  basic_code_block_->instructions().push_back(CreateRet());
  basic_code_block_->successors().push_back(CreateBranch(I_JZ, kOffset1));

  ASSERT_EQ(4 * CreateRet().size(), basic_code_block_->GetInstructionSize());
}

TEST_F(BasicBlockTest, EmptyBasicBlockIsNotValid) {
  // Upon creation the code block has neither instructions nor successors,
  // which we consider to be an invalid state.
  ASSERT_FALSE(basic_code_block_->IsValid());
}

TEST_F(BasicBlockTest, BasicBlockWithOnlyConditionalSuccessorIsNotValid) {
  basic_code_block_->successors().push_back(CreateBranch(I_JNZ, kOffset1));
  ASSERT_FALSE(basic_code_block_->IsValid());
}

TEST_F(BasicBlockTest,
       BasicBlockWithConditionalAndFallThroughSuccessorsIsValid) {
  basic_code_block_->successors().push_back(CreateBranch(I_JNZ, kOffset1));
  basic_code_block_->successors().push_back(CreateBranch(I_JZ, kOffset2));
  ASSERT_TRUE(basic_code_block_->IsValid());
}

TEST_F(BasicBlockTest,
       BasicBlockWithFallThroughSuccessorIsValid) {
  basic_code_block_->successors().push_back(CreateBranch(I_JMP, kOffset2));
  ASSERT_TRUE(basic_code_block_->IsValid());
}

TEST_F(BasicBlockTest,
       BasicBlockWithTerminalInstructionNoSuccessorsIsValid) {
  basic_code_block_->instructions().push_back(CreateRet());
  ASSERT_TRUE(basic_code_block_->IsValid());
}

namespace {

void TestReferenceCopy(const BasicBlockReference& input) {
  BasicBlockReference copy(input);

  EXPECT_EQ(input.referred_type(), copy.referred_type());
  EXPECT_EQ(input.block(), copy.block());
  EXPECT_EQ(input.basic_block(), copy.basic_block());
  EXPECT_EQ(input.offset(), copy.offset());
  EXPECT_EQ(input.size(), copy.size());
  EXPECT_EQ(input.IsValid(), copy.IsValid());
  EXPECT_EQ(input.tags(), copy.tags());
}

}  // namespace

TEST_F(BasicBlockTest, InvalidBasicBlockReference) {
  // Validate that a ref that points to nothing is not valid and doesn't claim
  // to point to anything.
  BasicBlockReference ref;
  TestReferenceCopy(ref);

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
                          basic_code_block_);

  EXPECT_EQ(BasicBlockReference::REFERRED_TYPE_BASIC_BLOCK,
            ref.referred_type());
  ref.tags().insert(&ref);
  TestReferenceCopy(ref);

  EXPECT_EQ(NULL, ref.block());
  EXPECT_EQ(basic_code_block_, ref.basic_block());
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
                          macro_block_,
                          kOffset,
                          kBase);
  TestReferenceCopy(ref);

  EXPECT_EQ(BasicBlockReference::REFERRED_TYPE_BLOCK, ref.referred_type());
  EXPECT_EQ(NULL, ref.basic_block());
  EXPECT_EQ(macro_block_, ref.block());
  EXPECT_EQ(kRefSize, ref.size());
  EXPECT_EQ(kOffset, ref.offset());
  EXPECT_EQ(kBase, ref.base());
  EXPECT_TRUE(ref.IsValid());

  BasicBlockReference retyped(BlockGraph::PC_RELATIVE_REF, 1, ref);
  EXPECT_EQ(BlockGraph::PC_RELATIVE_REF, retyped.reference_type());
  EXPECT_EQ(BasicBlockReference::REFERRED_TYPE_BLOCK, retyped.referred_type());
  EXPECT_EQ(NULL, retyped.basic_block());
  EXPECT_EQ(macro_block_, retyped.block());
  EXPECT_EQ(1, retyped.size());
  EXPECT_EQ(kOffset, retyped.offset());
  EXPECT_EQ(kBase, retyped.base());
  EXPECT_TRUE(retyped.IsValid());
}

TEST_F(BasicBlockTest, CompareBasicBlockReferences) {
  BasicBlockReference r1(
      BlockGraph::RELATIVE_REF, kRefSize, basic_code_block_);
  BasicBlockReference r2(
      BlockGraph::RELATIVE_REF, kRefSize, basic_code_block_);
  BasicBlockReference r3(
      BlockGraph::RELATIVE_REF, kRefSize, macro_block_, 8, 8);

  EXPECT_TRUE(r1 == r2);
  EXPECT_TRUE(r2 == r1);
  EXPECT_FALSE(r2 == r3);
  EXPECT_FALSE(r3 == r1);
}

TEST_F(BasicBlockTest, InvalidBasicBlockReferrer) {
  // Validate that an empty referrer is not valid.
  BasicBlockReferrer referrer;
  EXPECT_EQ(NULL, referrer.block());
  EXPECT_EQ(-1, referrer.offset());
  EXPECT_FALSE(referrer.IsValid());
}

TEST_F(BasicBlockTest, BlockReferrer) {
  static const BasicBlockReference::Offset kOffset = kBlockSize / 2;

  BasicBlockReferrer referrer(macro_block_, kOffset);

  EXPECT_EQ(macro_block_, referrer.block());
  EXPECT_EQ(kOffset, referrer.offset());
  EXPECT_TRUE(referrer.IsValid());
}

TEST_F(BasicBlockTest, CompareBasicBlockRefererrs) {
  BlockGraph block_graph;
  BlockGraph::Block* b2 = block_graph.AddBlock(kMacroBlockType, kBlockSize,
      kBlockName);

  BasicBlockReferrer r1(b2, 4);
  BasicBlockReferrer r2(b2, 4);
  BasicBlockReferrer r3(macro_block_, 8);

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

typedef BasicBlockTest SuccessorTest;

namespace {

void TestSuccessorCopy(const Successor& input) {
  Successor copy(input);

  EXPECT_EQ(input.condition(), copy.condition());
  EXPECT_EQ(input.reference(), copy.reference());
  EXPECT_EQ(input.label(), copy.label());
  EXPECT_EQ(input.has_label(), copy.has_label());
  EXPECT_EQ(input.source_range(), copy.source_range());
  EXPECT_EQ(input.instruction_size(), copy.instruction_size());
  EXPECT_EQ(input.tags(), copy.tags());
}

}  // namespace


TEST_F(SuccessorTest, DefaultConstructor) {
  Successor s;

  TestSuccessorCopy(s);
  EXPECT_EQ(Successor::kInvalidCondition, s.condition());
  EXPECT_EQ(BasicBlockReference(), s.reference());
  EXPECT_EQ(0, s.instruction_size());
  EXPECT_FALSE(s.has_label());
}

TEST_F(SuccessorTest, BasicCodeBlockConstructor) {
  const Successor::Condition kCondition = Successor::kConditionAbove;
  const Successor::Size kSuccessorSize = 5;
  BasicCodeBlock* bb = subgraph_.AddBasicCodeBlock("bb");
  BasicBlockReference bb_ref(BlockGraph::ABSOLUTE_REF, 4, bb);

  Successor s(kCondition,
              bb_ref,
              kSuccessorSize);

  TestSuccessorCopy(s);
  EXPECT_EQ(kCondition, s.condition());
  EXPECT_EQ(bb_ref, s.reference());
  EXPECT_EQ(kSuccessorSize, s.instruction_size());
}

TEST_F(SuccessorTest, SetBranchTarget) {
  BasicCodeBlock* bb = subgraph_.AddBasicCodeBlock("bb");
  BasicBlockReference bb_ref(BlockGraph::ABSOLUTE_REF, 4, bb);

  Successor s;
  s.SetReference(bb_ref);
  TestSuccessorCopy(s);

  EXPECT_EQ(bb_ref, s.reference());
}

TEST_F(SuccessorTest, LabelsAndTags) {
  Successor successor;
  EXPECT_FALSE(successor.has_label());

  BlockGraph::Label label("Foo", BlockGraph::CODE_LABEL);
  successor.set_label(label);
  successor.tags().insert(&successor);

  TestSuccessorCopy(successor);
  EXPECT_TRUE(successor.has_label());
  EXPECT_TRUE(successor.label() == label);
  EXPECT_EQ(1u, successor.tags().size());
  EXPECT_NE(successor.tags().end(), successor.tags().find(&successor));
}

TEST_F(SuccessorTest, OpCodeToCondition) {
  struct TableEntry {
    uint16 op_code;
    Successor::Condition condition;
  };

  const TableEntry kOpCodeToConditionTable[] = {
      { I_JA, Successor::kConditionAbove },
      { I_JAE, Successor::kConditionAboveOrEqual },
      { I_JB, Successor::kConditionBelow },
      { I_JBE, Successor::kConditionBelowOrEqual },
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
  };


  COMPILE_ASSERT(
      arraysize(kOpCodeToConditionTable) ==
          Successor::kMaxConditionalBranch + 1,
      unexpected_number_of_map_entries);

  for (size_t i = 0; i < arraysize(kOpCodeToConditionTable); ++i) {
    const TableEntry& entry = kOpCodeToConditionTable[i];
    EXPECT_EQ(entry.condition, Successor::OpCodeToCondition(entry.op_code));
  }

  // These two are non-conditional exceptions.
  EXPECT_EQ(Successor::kInvalidCondition, Successor::OpCodeToCondition(I_MOV));
  EXPECT_EQ(Successor::kConditionTrue, Successor::OpCodeToCondition(I_JMP));
}

TEST_F(SuccessorTest, InvertCondition) {
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
  };

  COMPILE_ASSERT(
      arraysize(kConditionInversionTable) == Successor::kMaxCondition,
      unexpected_number_of_inversion_table_entries);

  for (size_t i = 0; i < arraysize(kConditionInversionTable); ++i) {
    const TableEntry& entry = kConditionInversionTable[i];
    EXPECT_EQ(entry.inverse, Successor::InvertCondition(entry.original));
  }
}

typedef BasicBlockTest InstructionTest;

namespace {

void TestInstructionCopy(const Instruction& input) {
  Instruction copy(input);

  EXPECT_EQ(input.references(), copy.references());
  EXPECT_EQ(input.label(), copy.label());
  EXPECT_EQ(input.has_label(), copy.has_label());
  EXPECT_EQ(input.source_range(), copy.source_range());
  EXPECT_EQ(0, memcmp(input.data(), copy.data(), copy.size()));
  EXPECT_EQ(input.size(), copy.size());
}

const uint8 kCallRelative[] = { 0xE8, 0xDE, 0xAD, 0xBE, 0xEF };

}  // namespace

TEST_F(InstructionTest, ConstructionFromData) {
  const uint8 kCallRelative[] = { 0xE8, 0xDE, 0xAD, 0xBE, 0xEF };
  Instruction call;
  ASSERT_TRUE(
      Instruction::FromBuffer(kCallRelative, arraysize(kCallRelative), &call));

  _DInst& repr = call.representation();
  EXPECT_EQ(I_CALL, repr.opcode);
  EXPECT_EQ(FC_CALL, META_GET_FC(repr.meta));
  EXPECT_EQ(O_PC, repr.ops[0].type);
  TestInstructionCopy(call);

  BlockGraph::Label label("Foo", BlockGraph::CODE_LABEL);
  call.set_label(label);
  EXPECT_EQ(label, call.label());
  TestInstructionCopy(call);
}

TEST_F(InstructionTest, Copy) {
  const uint8 kCallRelative[] = { 0xE8, 0xDE, 0xAD, 0xBE, 0xEF };
  Instruction call;
  ASSERT_TRUE(
      Instruction::FromBuffer(kCallRelative, arraysize(kCallRelative), &call));
  call.set_source_range(Instruction::SourceRange(core::RelativeAddress(0), 5));
  call.set_label(BlockGraph::Label("foo", 0));
  call.tags().insert(&call);

  Instruction copy(call);
  EXPECT_EQ(call.opcode(), copy.opcode());
  EXPECT_EQ(call.size(), copy.size());
  EXPECT_EQ(call.references(), copy.references());
  EXPECT_EQ(call.source_range(), copy.source_range());
  EXPECT_EQ(call.label(), copy.label());
  EXPECT_EQ(call.tags(), copy.tags());
}

TEST_F(InstructionTest, ToString) {
  Instruction nop;
  std::string buffer;
  EXPECT_TRUE(nop.ToString(&buffer));
  ASSERT_THAT(buffer, testing::HasSubstr("90"));
  ASSERT_THAT(buffer, testing::HasSubstr("NOP"));
}

TEST_F(InstructionTest, CallsNonReturningFunction) {
  BlockGraph block_graph;

  // Create a returning code block.
  BlockGraph::Block* returning =
      block_graph.AddBlock(BlockGraph::CODE_BLOCK, 1, "return");

  // Create a non-returning code block.
  BlockGraph::Block* non_returning =
       block_graph.AddBlock(BlockGraph::CODE_BLOCK, 1, "non-return");
  non_returning->set_attribute(BlockGraph::NON_RETURN_FUNCTION);

  Instruction call_relative;
  ASSERT_TRUE(Instruction::FromBuffer(kCallRelative,
                                      sizeof(kCallRelative),
                                      &call_relative));

  TestInstructionCopy(call_relative);

  // Call the returning function directly.
  call_relative.SetReference(
      1, BasicBlockReference(BlockGraph::RELATIVE_REF,
                             BlockGraph::Reference::kMaximumSize,
                             returning, 0, 0));
  EXPECT_FALSE(call_relative.CallsNonReturningFunction());

  // Call the non-returning function directly.
  call_relative.SetReference(
      1, BasicBlockReference(BlockGraph::RELATIVE_REF,
                             BlockGraph::Reference::kMaximumSize,
                             non_returning, 0, 0));
  EXPECT_TRUE(call_relative.CallsNonReturningFunction());

  // Setup an indirect call via a static function pointer (for example, an
  // import table).
  BlockGraph::Block* function_pointer =
      block_graph.AddBlock(BlockGraph::DATA_BLOCK,
          BlockGraph::Reference::kMaximumSize, "ptr");
  const uint8 kCallIndirect[] = { 0xFF, 0x15, 0xDE, 0xAD, 0xBE, 0xEF };
  Instruction call_indirect;
  ASSERT_TRUE(Instruction::FromBuffer(kCallIndirect,
                                      sizeof(kCallIndirect),
                                      &call_indirect));
  call_indirect.SetReference(
      2, BasicBlockReference(BlockGraph::RELATIVE_REF,
                             BlockGraph::Reference::kMaximumSize,
                             function_pointer, 0, 0));
  TestInstructionCopy(call_indirect);

  // Call the returning function via the pointer.
  function_pointer->SetReference(
      0, BlockGraph::Reference(BlockGraph::ABSOLUTE_REF,
                                BlockGraph::Reference::kMaximumSize,
                                returning, 0, 0));
  EXPECT_FALSE(call_indirect.CallsNonReturningFunction());

  // Call the returning function via the pointer.
  function_pointer->SetReference(
      0, BlockGraph::Reference(BlockGraph::ABSOLUTE_REF,
                                BlockGraph::Reference::kMaximumSize,
                                non_returning, 0, 0));
  EXPECT_TRUE(call_indirect.CallsNonReturningFunction());
}

TEST_F(InstructionTest, FindOperandReference) {
  BasicBlock::Instructions instructions;
  BasicBlockAssembler assm(instructions.begin(), &instructions);

  {
    // Generate a dual-reference instruction.
    assm.mov(Operand(core::eax, core::ebx, core::kTimes4,
                     Displacement(basic_code_block_)),
             Immediate(macro_block_, 30));
    const Instruction& inst = instructions.back();

    BasicBlockReference ref0;
    EXPECT_TRUE(inst.FindOperandReference(0, &ref0));
    EXPECT_EQ(BasicBlockReference::REFERRED_TYPE_BASIC_BLOCK,
              ref0.referred_type());
    EXPECT_EQ(basic_code_block_, ref0.basic_block());

    BasicBlockReference ref1;
    EXPECT_TRUE(inst.FindOperandReference(1, &ref1));
    EXPECT_EQ(BasicBlockReference::REFERRED_TYPE_BLOCK, ref1.referred_type());
    EXPECT_EQ(macro_block_, ref1.block());

    BasicBlockReference ignore;
    EXPECT_FALSE(inst.FindOperandReference(2, &ignore));
    EXPECT_FALSE(inst.FindOperandReference(3, &ignore));
  }

  {
    // Generate a singe-reference instruction with an 8-bit immediate.
    assm.mov(Operand(core::eax, core::ebx, core::kTimes4,
                     Displacement(basic_code_block_)),
             Immediate(0x10, core::kSize8Bit));

    const Instruction& inst = instructions.back();

    BasicBlockReference ref0;
    EXPECT_TRUE(inst.FindOperandReference(0, &ref0));
    EXPECT_EQ(BasicBlockReference::REFERRED_TYPE_BASIC_BLOCK,
              ref0.referred_type());
    EXPECT_EQ(basic_code_block_, ref0.basic_block());

    BasicBlockReference ignore;
    EXPECT_FALSE(inst.FindOperandReference(1, &ignore));
    EXPECT_FALSE(inst.FindOperandReference(2, &ignore));
    EXPECT_FALSE(inst.FindOperandReference(3, &ignore));
  }
}

}  // namespace block_graph
