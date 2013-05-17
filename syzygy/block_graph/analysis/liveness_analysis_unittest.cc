// Copyright 2013 Google Inc. All Rights Reserved.
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
// Unittests for liveness analysis.

#include "syzygy/block_graph/analysis/liveness_analysis.h"

#include "base/bind.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/block_graph/basic_block_assembler.h"
#include "syzygy/block_graph/analysis/liveness_analysis_internal.h"

#include "mnemonics.h"  // NOLINT

namespace block_graph {
namespace analysis {

namespace {

typedef BasicBlockSubGraph::BBCollection BBCollection;
typedef block_graph::analysis::LivenessAnalysis::State State;
typedef block_graph::analysis::LivenessAnalysis::StateHelper StateHelper;
typedef block_graph::BasicBlockSubGraph::BasicBlock BasicBlock;
typedef block_graph::BasicBlockSubGraph::BasicBlock::Instructions Instructions;
typedef block_graph::BasicBlockSubGraph::BasicBlock::Successors Successors;
typedef block_graph::BasicBlockSubGraph::BasicCodeBlock BasicCodeBlock;

// _asm mov eax, 0
const uint8 kMovEaxZero[5] = { 0xB8, 0x00, 0x00, 0x00, 0x00 };
// _asm mov ebx, 0
const uint8 kMovEbxZero[5] = { 0xBB, 0x00, 0x00, 0x00, 0x00 };
// _asm mov ecx, 0
const uint8 kMovEcxZero[5] = { 0xB9, 0x00, 0x00, 0x00, 0x00 };
// _asm mov edx, 0
const uint8 kMovEdxZero[5] = { 0xBA, 0x00, 0x00, 0x00, 0x00 };
// _asm mov esi, 0
const uint8 kMovEsiZero[5] = { 0xBE, 0x00, 0x00, 0x00, 0x00 };
// _asm mov edi, 0
const uint8 kMovEdiZero[5] = { 0xBF, 0x00, 0x00, 0x00, 0x00 };
// _asm mov esp, 0
const uint8 kMovEspZero[5] = { 0xBC, 0x00, 0x00, 0x00, 0x00 };
// _asm mov ebp, 0
const uint8 kMovEbpZero[5] = { 0xBD, 0x00, 0x00, 0x00, 0x00 };
// _asm cmp eax, ebx
const uint8 kCmpEaxEbx[2] = { 0x3B, 0xC3 };

class LivenessAnalysisTest : public testing::Test {
 public:
  LivenessAnalysisTest();

  inline bool is_live(core::Register reg) const { return state_.IsLive(reg); }
  inline bool are_arithmetic_flags_live() const {
    return state_.AreArithmeticFlagsLive();
  }

  void AddInstructionFromBuffer(const uint8* data, size_t length);
  void DefineAllRegisters();
  void AnalyzeInstructions();
  void AnalyzeSingleInstructionFromBuffer(const uint8* data, size_t length);

  void AddSuccessorBetween(Successor::Condition condition,
                           BasicCodeBlock* from,
                           BasicCodeBlock* to);

 protected:
  BlockGraph::Block test_block_;
  BasicCodeBlock test_bb_;
  BasicBlock::Instructions instructions_;
  BasicBlockAssembler asm_;
  LivenessAnalysis liveness_;
  LivenessAnalysis::State state_;
};

LivenessAnalysisTest::LivenessAnalysisTest()
    : testing::Test(),
      test_block_(99, BlockGraph::CODE_BLOCK, 10, "test block"),
      test_bb_("foo"),
      instructions_(),
      asm_(instructions_.end(), &instructions_),
      liveness_(),
      state_() {
}

void LivenessAnalysisTest::AddInstructionFromBuffer(const uint8* data,
                                                    size_t length) {
  // Decode an instruction and append it to basicblock_.
  DCHECK(data != NULL);
  DCHECK_GT(core::AssemblerImpl::kMaxInstructionLength, length);

  block_graph::Instruction temp;
  ASSERT_TRUE(block_graph::Instruction::FromBuffer(data, length, &temp));

  // Append this instruction to the basic block.
  instructions_.push_back(temp);
}

void LivenessAnalysisTest::DefineAllRegisters() {
  // Inserts instructions into basicblock_ so all registers are defined.
  AddInstructionFromBuffer(kMovEaxZero, sizeof(kMovEaxZero));
  AddInstructionFromBuffer(kMovEbxZero, sizeof(kMovEbxZero));
  AddInstructionFromBuffer(kMovEcxZero, sizeof(kMovEcxZero));
  AddInstructionFromBuffer(kMovEdxZero, sizeof(kMovEdxZero));
  AddInstructionFromBuffer(kMovEsiZero, sizeof(kMovEsiZero));
  AddInstructionFromBuffer(kMovEdiZero, sizeof(kMovEdiZero));
  AddInstructionFromBuffer(kMovEspZero, sizeof(kMovEspZero));
  AddInstructionFromBuffer(kMovEbpZero, sizeof(kMovEbpZero));

  // Define arithmetic flags.
  AddInstructionFromBuffer(kCmpEaxEbx, sizeof(kCmpEaxEbx));
}

void LivenessAnalysisTest::AnalyzeInstructions() {
  // Perform a backward liveness analysis on instructions in basicblock_.
  // Results are kept in 'state_' and may be accessed through IsLive and
  // AreArithmeticFlagsLive.
  LivenessAnalysis::StateHelper::SetAll(&state_);
  Instructions::reverse_iterator instr_iter = instructions_.rbegin();
  for (; instr_iter != instructions_.rend(); ++instr_iter) {
    const Instruction& instr = *instr_iter;
    liveness_.PropagateBackward(instr, &state_);
  }
}

void LivenessAnalysisTest::AnalyzeSingleInstructionFromBuffer(
    const uint8* data, size_t length) {
  // This function creates a basic block with an instruction under test,
  // followed by instructions to define all registers and flags. This way, the
  // analysis may assume everything was dead before the instruction.
  instructions_.clear();
  StateHelper::SetAll(&state_);

  AddInstructionFromBuffer(data, length);
  DefineAllRegisters();
  AnalyzeInstructions();
}

void LivenessAnalysisTest::AddSuccessorBetween(Successor::Condition condition,
                                               BasicCodeBlock* from,
                                               BasicCodeBlock* to) {
  from->successors().push_back(
      Successor(condition,
                BasicBlockReference(BlockGraph::RELATIVE_REF,
                                    BlockGraph::Reference::kMaximumSize,
                                    to),
                0));
}

TEST(LivenessAnalysisStateTest, StateRegisterMaskOperations) {
  // On creation, a state assumes all registers are alive.
  State state_full;
  EXPECT_TRUE(StateHelper::IsSet(state_full, StateHelper::REGBITS_ALL));
  EXPECT_TRUE(StateHelper::IsSet(state_full, StateHelper::REGBITS_AX));

  // The Clear operation should not keep any register partially defined.
  State state_empty;
  StateHelper::Clear(&state_empty);
  EXPECT_FALSE(
    StateHelper::IsPartiallySet(state_empty, StateHelper::REGBITS_ALL));
  EXPECT_FALSE(
    StateHelper::IsPartiallySet(state_empty, StateHelper::REGBITS_AX));

  // Test sub-registers definition.
  State state_ax;
  State state_cx;
  StateHelper::Clear(&state_ax);
  StateHelper::Clear(&state_cx);
  StateHelper::Set(StateHelper::REGBITS_AX, &state_ax);
  StateHelper::Set(StateHelper::REGBITS_CX, &state_cx);
  EXPECT_TRUE(StateHelper::IsPartiallySet(state_ax, StateHelper::REGBITS_EAX));
  EXPECT_TRUE(StateHelper::IsSet(state_ax, StateHelper::REGBITS_AL));
  EXPECT_TRUE(StateHelper::IsSet(state_ax, StateHelper::REGBITS_AH));
  EXPECT_TRUE(StateHelper::IsSet(state_ax, StateHelper::REGBITS_AX));
  EXPECT_TRUE(StateHelper::IsPartiallySet(state_cx, StateHelper::REGBITS_ECX));
  EXPECT_TRUE(StateHelper::IsSet(state_cx, StateHelper::REGBITS_CL));
  EXPECT_TRUE(StateHelper::IsSet(state_cx, StateHelper::REGBITS_CH));
  EXPECT_TRUE(StateHelper::IsSet(state_cx, StateHelper::REGBITS_CX));

  // Test IsLive operation.
  EXPECT_TRUE(state_full.IsLive(core::eax));
  EXPECT_TRUE(state_full.IsLive(core::ecx));
  EXPECT_FALSE(state_empty.IsLive(core::eax));
  EXPECT_FALSE(state_empty.IsLive(core::ecx));
  EXPECT_TRUE(state_ax.IsLive(core::eax));
  EXPECT_FALSE(state_ax.IsLive(core::ecx));
  EXPECT_FALSE(state_cx.IsLive(core::eax));
  EXPECT_TRUE(state_cx.IsLive(core::ecx));

  // Test copy constructor.
  State state_copy(state_ax);
  EXPECT_TRUE(
    StateHelper::IsPartiallySet(state_copy, StateHelper::REGBITS_EAX));
  EXPECT_TRUE(StateHelper::IsSet(state_copy, StateHelper::REGBITS_AL));
  EXPECT_TRUE(StateHelper::IsSet(state_copy, StateHelper::REGBITS_AH));
  EXPECT_TRUE(StateHelper::IsSet(state_copy, StateHelper::REGBITS_AX));

  // Test Copy operation.
  State state_copy_ax;
  StateHelper::Copy(state_ax, &state_copy_ax);
  EXPECT_TRUE(
    StateHelper::IsPartiallySet(state_copy_ax, StateHelper::REGBITS_EAX));
  EXPECT_TRUE(StateHelper::IsSet(state_copy_ax, StateHelper::REGBITS_AL));
  EXPECT_TRUE(StateHelper::IsSet(state_copy_ax, StateHelper::REGBITS_AH));
  EXPECT_TRUE(StateHelper::IsSet(state_copy_ax, StateHelper::REGBITS_AX));

  // Test Union operation.
  State state_merged;
  StateHelper::Clear(&state_merged);
  EXPECT_FALSE(
    StateHelper::IsPartiallySet(state_merged, StateHelper::REGBITS_AX));
  EXPECT_FALSE(
    StateHelper::IsPartiallySet(state_merged, StateHelper::REGBITS_CX));
  StateHelper::Union(state_ax, &state_merged);
  EXPECT_TRUE(
    StateHelper::IsPartiallySet(state_merged, StateHelper::REGBITS_AX));
  EXPECT_FALSE(
    StateHelper::IsPartiallySet(state_merged, StateHelper::REGBITS_CX));
  StateHelper::Union(state_cx, &state_merged);
  EXPECT_TRUE(
    StateHelper::IsPartiallySet(state_merged, StateHelper::REGBITS_AX));
  EXPECT_TRUE(
    StateHelper::IsPartiallySet(state_merged, StateHelper::REGBITS_CX));

  // Test Subtract operation
  StateHelper::Subtract(state_ax, &state_merged);
  EXPECT_FALSE(
    StateHelper::IsPartiallySet(state_merged, StateHelper::REGBITS_AX));
  EXPECT_TRUE(
    StateHelper::IsPartiallySet(state_merged, StateHelper::REGBITS_CX));
  StateHelper::Subtract(state_cx, &state_merged);
  EXPECT_FALSE(
    StateHelper::IsPartiallySet(state_merged, StateHelper::REGBITS_AX));
  EXPECT_FALSE(
    StateHelper::IsPartiallySet(state_merged, StateHelper::REGBITS_CX));
}

TEST(LivenessAnalysisStateTest, StateFlagsMaskOperations) {
  // On creation, a state assumes all flags are alive.
  State state_full;
  EXPECT_TRUE(state_full.AreArithmeticFlagsLive());

  // The Clear operation should not keep any flags alive.
  State state_empty;
  StateHelper::Clear(&state_empty);
  EXPECT_FALSE(state_empty.AreArithmeticFlagsLive());

  // Partially defined flags must be considered alive.
  State state_flagA;
  State state_flagB;
  State state_flagC;
  StateHelper::Clear(&state_flagA);
  StateHelper::Clear(&state_flagB);
  StateHelper::SetFlags(0xF0F0, &state_flagA);
  StateHelper::SetFlags(0xFFFF, &state_flagB);

  EXPECT_TRUE(state_flagA.AreArithmeticFlagsLive());
  EXPECT_TRUE(state_flagB.AreArithmeticFlagsLive());

  // Test Subtract operation.
  State state_flag_ari1;
  State state_flag_ari2;
  StateHelper::Clear(&state_flag_ari1);
  StateHelper::Clear(&state_flag_ari2);
  StateHelper::SetFlags(D_ZF | D_SF | D_CF, &state_flag_ari1);
  StateHelper::SetFlags(D_OF | D_PF | D_AF, &state_flag_ari2);

  EXPECT_TRUE(state_flag_ari1.AreArithmeticFlagsLive());
  EXPECT_TRUE(state_flag_ari2.AreArithmeticFlagsLive());

  State state_merged;
  EXPECT_TRUE(state_merged.AreArithmeticFlagsLive());
  StateHelper::Subtract(state_flag_ari1, &state_merged);
  EXPECT_TRUE(state_merged.AreArithmeticFlagsLive());
  StateHelper::Subtract(state_flag_ari2, &state_merged);
  EXPECT_FALSE(state_merged.AreArithmeticFlagsLive());
}

TEST_F(LivenessAnalysisTest, Mov1Analysis) {
  asm_.mov(core::eax, Immediate(10));
  asm_.mov(core::ecx, core::ebx);
  AnalyzeInstructions();
  EXPECT_FALSE(is_live(core::eax));
  EXPECT_TRUE(is_live(core::ebx));
  EXPECT_FALSE(is_live(core::ecx));
}

TEST_F(LivenessAnalysisTest, Mov2Analysis) {
  asm_.mov(core::eax, core::ebx);
  asm_.mov(core::edx, Immediate(10));
  asm_.mov(core::ecx, Immediate(&test_block_, 0));
  AnalyzeInstructions();
  EXPECT_FALSE(is_live(core::eax));
  EXPECT_TRUE(is_live(core::ebx));
  EXPECT_FALSE(is_live(core::ecx));
  EXPECT_FALSE(is_live(core::edx));
}

TEST_F(LivenessAnalysisTest, DefineAllRegisters) {
  // Validate the tester by defining all registers and using none.
  DefineAllRegisters();
  AnalyzeInstructions();
  EXPECT_FALSE(is_live(core::eax));
  EXPECT_FALSE(is_live(core::ebx));
  EXPECT_FALSE(is_live(core::ecx));
  EXPECT_FALSE(is_live(core::edx));
  EXPECT_FALSE(is_live(core::esi));
  EXPECT_FALSE(is_live(core::edi));
  EXPECT_FALSE(are_arithmetic_flags_live());
}

TEST_F(LivenessAnalysisTest, Defs1Analysis) {
  // Validate the tester by defining all registers and using some of them.
  AddInstructionFromBuffer(kMovEaxZero, sizeof(kMovEaxZero));
  AddInstructionFromBuffer(kMovEcxZero, sizeof(kMovEcxZero));
  AddInstructionFromBuffer(kMovEsiZero, sizeof(kMovEsiZero));
  AnalyzeInstructions();
  EXPECT_FALSE(is_live(core::eax));
  EXPECT_TRUE(is_live(core::ebx));
  EXPECT_FALSE(is_live(core::ecx));
  EXPECT_TRUE(is_live(core::edx));
  EXPECT_FALSE(is_live(core::esi));
  EXPECT_TRUE(is_live(core::edi));
}

TEST_F(LivenessAnalysisTest, Defs2Analysis) {
  // Validate the tester by defining all registers and using some of them.
  AddInstructionFromBuffer(kMovEbxZero, sizeof(kMovEbxZero));
  AddInstructionFromBuffer(kMovEdxZero, sizeof(kMovEdxZero));
  AddInstructionFromBuffer(kMovEdiZero, sizeof(kMovEdiZero));
  AnalyzeInstructions();
  EXPECT_TRUE(is_live(core::eax));
  EXPECT_FALSE(is_live(core::ebx));
  EXPECT_TRUE(is_live(core::ecx));
  EXPECT_FALSE(is_live(core::edx));
  EXPECT_TRUE(is_live(core::esi));
  EXPECT_FALSE(is_live(core::edi));
}

TEST_F(LivenessAnalysisTest, OperandTypeLeft) {
  // Validate the support of all DiStorm operand types (as first operand).
  // _asm add eax, ecx
  static const uint8 kOpReg1[2] = { 0x03, 0xC1 };
  AnalyzeSingleInstructionFromBuffer(kOpReg1, sizeof(kOpReg1));
  EXPECT_TRUE(is_live(core::eax));
  EXPECT_FALSE(is_live(core::ebx));
  EXPECT_TRUE(is_live(core::ecx));
  EXPECT_FALSE(is_live(core::edx));

  // _asm add [eax], ecx
  static const uint8 kOpSmem[2] = { 0x01, 0x08 };
  AnalyzeSingleInstructionFromBuffer(kOpSmem, sizeof(kOpSmem));
  EXPECT_TRUE(is_live(core::eax));
  EXPECT_FALSE(is_live(core::ebx));
  EXPECT_TRUE(is_live(core::ecx));
  EXPECT_FALSE(is_live(core::edx));

  // _asm add [eax + 42], ecx
  static const uint8 kOpSmemOffet[3] = { 0x01, 0x48, 0x2A };
  AnalyzeSingleInstructionFromBuffer(kOpSmemOffet, sizeof(kOpSmemOffet));
  EXPECT_TRUE(is_live(core::eax));
  EXPECT_FALSE(is_live(core::ebx));
  EXPECT_TRUE(is_live(core::ecx));
  EXPECT_FALSE(is_live(core::edx));

  // _asm add [eax + ebx*2 + 42], ecx
  static const uint8 kOpMemOffset[4] = { 0x01, 0x4C, 0x58, 0x2A };
  AnalyzeSingleInstructionFromBuffer(kOpMemOffset, sizeof(kOpMemOffset));
  EXPECT_TRUE(is_live(core::eax));
  EXPECT_TRUE(is_live(core::ebx));
  EXPECT_TRUE(is_live(core::ecx));
  EXPECT_FALSE(is_live(core::edx));

  // _asm add DWORD PTR [X], ecx
  static const uint8 kOpDispl[6] = { 0x01, 0x0D, 0x80, 0x1E, 0xF2, 0x00 };
  AnalyzeSingleInstructionFromBuffer(kOpDispl, sizeof(kOpDispl));
  EXPECT_FALSE(is_live(core::eax));
  EXPECT_FALSE(is_live(core::ebx));
  EXPECT_TRUE(is_live(core::ecx));
  EXPECT_FALSE(is_live(core::edx));
}

TEST_F(LivenessAnalysisTest, OperandTypeRight) {
  // Validate the support of all DiStorm operand types (as second operand).
  // _asm add ecx, 1
  static const uint8 kOpReg1[3] = { 0x83, 0xC1, 0x01 };
  AnalyzeSingleInstructionFromBuffer(kOpReg1, sizeof(kOpReg1));
  EXPECT_FALSE(is_live(core::eax));
  EXPECT_FALSE(is_live(core::ebx));
  EXPECT_TRUE(is_live(core::ecx));
  EXPECT_FALSE(is_live(core::edx));

  // _asm add ecx, eax
  static const uint8 kOpReg2[2] = { 0x03, 0xC8 };
  AnalyzeSingleInstructionFromBuffer(kOpReg2, sizeof(kOpReg2));
  EXPECT_TRUE(is_live(core::eax));
  EXPECT_FALSE(is_live(core::ebx));
  EXPECT_TRUE(is_live(core::ecx));
  EXPECT_FALSE(is_live(core::edx));

  // _asm add ecx, [eax]
  static const uint8 kOpSmem[2] = { 0x03, 0x08 };
  AnalyzeSingleInstructionFromBuffer(kOpSmem, sizeof(kOpSmem));
  EXPECT_TRUE(is_live(core::eax));
  EXPECT_FALSE(is_live(core::ebx));
  EXPECT_TRUE(is_live(core::ecx));
  EXPECT_FALSE(is_live(core::edx));

  // _asm add ecx, [eax + 42]
  static const uint8 kOpSmemOffet[3] = { 0x03, 0x48, 0x2A };
  AnalyzeSingleInstructionFromBuffer(kOpSmemOffet, sizeof(kOpSmemOffet));
  EXPECT_TRUE(is_live(core::eax));
  EXPECT_FALSE(is_live(core::ebx));
  EXPECT_TRUE(is_live(core::ecx));
  EXPECT_FALSE(is_live(core::edx));

  // _asm add ecx, [eax + ebx*2 + 42]
  static const uint8 kOpMemOffset[] = { 0x03, 0x4C, 0x58, 0x2A };
  AnalyzeSingleInstructionFromBuffer(kOpMemOffset, sizeof(kOpMemOffset));
  EXPECT_TRUE(is_live(core::eax));
  EXPECT_TRUE(is_live(core::ebx));
  EXPECT_TRUE(is_live(core::ecx));
  EXPECT_FALSE(is_live(core::edx));

  // _asm add ecx, DWORD PTR [X]
  static const uint8 kOpDispl[6] = { 0x03, 0x0D, 0x80, 0x1E, 0x27, 0x00 };
  AnalyzeSingleInstructionFromBuffer(kOpDispl, sizeof(kOpDispl));
  EXPECT_FALSE(is_live(core::eax));
  EXPECT_FALSE(is_live(core::ebx));
  EXPECT_TRUE(is_live(core::ecx));
  EXPECT_FALSE(is_live(core::edx));
}

TEST_F(LivenessAnalysisTest, InstructionWithoutDefine) {
  // Validate instructions that fully overwrite and use the destination.
  // _asm cmp eax, [ecx]
  static const uint8 kCmp[2] = { 0x3B, 0x01 };
  AnalyzeSingleInstructionFromBuffer(kCmp, sizeof(kCmp));
  EXPECT_TRUE(is_live(core::eax));
  EXPECT_TRUE(is_live(core::ecx));

  // _asm test ebx, [edx+12]
  static const uint8 kTest[3] = { 0x85, 0x5A, 0x0C };
  AnalyzeSingleInstructionFromBuffer(kTest, sizeof(kTest));
  EXPECT_TRUE(is_live(core::ebx));
  EXPECT_TRUE(is_live(core::edx));
}

TEST_F(LivenessAnalysisTest, InstructionsWithDefine) {
  // Validate instructions that fully overwrite the destination.
  // _asm mov ebx, [edx+12]
  static const uint8 kCmp[3] = { 0x8B, 0x5A, 0x0C };
  AnalyzeSingleInstructionFromBuffer(kCmp, sizeof(kCmp));
  EXPECT_FALSE(is_live(core::ebx));
  EXPECT_TRUE(is_live(core::edx));

  // _asm lea ebx, [edx+12]
  static const uint8 kTest[3] = { 0x8D, 0x5A, 0x0C };
  AnalyzeSingleInstructionFromBuffer(kTest, sizeof(kTest));
  EXPECT_FALSE(is_live(core::ebx));
  EXPECT_TRUE(is_live(core::edx));
}

TEST_F(LivenessAnalysisTest, InstructionsWithPartialDefine) {
  // Registers partially defined must be considered alive.
  // _asm mov bl, dl
  static const uint8 kCmp[3] = { 0xB3, 0x0C };
  // _asm mov DWORD PTR [X], ebx
  static const uint8 kStore[6] = { 0x89, 0x1D, 0x80, 0x1E, 0x10, 0x01 };
  AddInstructionFromBuffer(kCmp, sizeof(kCmp));
  AddInstructionFromBuffer(kStore, sizeof(kStore));
  AnalyzeInstructions();
  EXPECT_TRUE(is_live(core::ebx));
  EXPECT_TRUE(is_live(core::edx));
}

TEST_F(LivenessAnalysisTest, ArithmeticUnaryInstructions) {
  // _asm dec eax
  static const uint8 kDec1[1] = { 0x48 };
  AnalyzeSingleInstructionFromBuffer(kDec1, sizeof(kDec1));
  EXPECT_TRUE(is_live(core::eax));

  // _asm dec [ebx + 1]
  static const uint8 kDec2[3] = { 0xFE, 0x4B, 0x01 };
  AnalyzeSingleInstructionFromBuffer(kDec2, sizeof(kDec2));
  EXPECT_TRUE(is_live(core::ebx));

  // _asm dec [esi + ebx*2 + 1]
  static const uint8 kDec3[4] = { 0xFE, 0x4C, 0x5E, 0x01 };
  AnalyzeSingleInstructionFromBuffer(kDec3, sizeof(kDec3));
  EXPECT_TRUE(is_live(core::esi));
  EXPECT_TRUE(is_live(core::ebx));

  // _asm dec WORD PTR [X]
  static const uint8 kDec4[7] = { 0x66, 0xFF, 0x0D, 0x80, 0x1E, 0x92, 0x00 };
  AnalyzeSingleInstructionFromBuffer(kDec4, sizeof(kDec4));
  EXPECT_FALSE(is_live(core::eax));
  EXPECT_FALSE(is_live(core::ebx));
  EXPECT_FALSE(is_live(core::ecx));
  EXPECT_FALSE(is_live(core::edx));

  // _asm not ebx
  static const uint8 kNot1[2] = { 0xF7, 0xD3 };
  AnalyzeSingleInstructionFromBuffer(kNot1, sizeof(kNot1));
  EXPECT_TRUE(is_live(core::ebx));

  // _asm not [ebx]
  static const uint8 kNot2[2] = { 0xF6, 0x13 };
  AnalyzeSingleInstructionFromBuffer(kNot2, sizeof(kNot2));
  EXPECT_TRUE(is_live(core::ebx));

  // _asm neg ebx
  static const uint8 kNeg1[2] = { 0xF7, 0xDB };
  AnalyzeSingleInstructionFromBuffer(kNeg1, sizeof(kNeg1));
  EXPECT_TRUE(is_live(core::ebx));

  // _asm neg [ebx]
  static const uint8 kNeg2[2] = { 0xF6, 0x1B };
  AnalyzeSingleInstructionFromBuffer(kNeg2, sizeof(kNeg2));
  EXPECT_TRUE(is_live(core::ebx));

  // _asm inc edx
  static const uint8 kInc[2] = { 0x42 };
  AnalyzeSingleInstructionFromBuffer(kInc, sizeof(kInc));
  EXPECT_TRUE(is_live(core::edx));
}

TEST_F(LivenessAnalysisTest, ArithmeticBinaryInstructions) {
  // _asm add ebx, ecx
  static const uint8 kAdd[2] = { 0x03, 0xD9 };
  AnalyzeSingleInstructionFromBuffer(kAdd, sizeof(kAdd));
  EXPECT_TRUE(is_live(core::ebx));
  EXPECT_TRUE(is_live(core::ecx));

  // _asm sub esi, edi
  static const uint8 kSub[2] = { 0x2B, 0xF7 };
  AnalyzeSingleInstructionFromBuffer(kSub, sizeof(kSub));
  EXPECT_TRUE(is_live(core::esi));
  EXPECT_TRUE(is_live(core::edi));

  // _asm sbb ebx, [eax + edx + 12]
  static const uint8 KSbb[4] = { 0x1B, 0x5C, 0x10, 0x0C };
  AnalyzeSingleInstructionFromBuffer(KSbb, sizeof(KSbb));
  EXPECT_TRUE(is_live(core::eax));
  EXPECT_TRUE(is_live(core::ebx));
  EXPECT_TRUE(is_live(core::edx));

  // _asm and ebx, ecx
  static const uint8 kAnd[2] = { 0x23, 0xD9 };
  AnalyzeSingleInstructionFromBuffer(kAnd, sizeof(kAnd));
  EXPECT_TRUE(is_live(core::ebx));
  EXPECT_TRUE(is_live(core::ecx));

  // _asm or esi, [edi]
  static const uint8 kOr[2] = { 0x0B, 0x37 };
  AnalyzeSingleInstructionFromBuffer(kOr, sizeof(kOr));
  EXPECT_TRUE(is_live(core::esi));
  EXPECT_TRUE(is_live(core::edi));

  // _asm xor [esi], edi
  static const uint8 kXor[2] = { 0x31, 0x3E };
  AnalyzeSingleInstructionFromBuffer(kXor, sizeof(kXor));
  EXPECT_TRUE(is_live(core::esi));
  EXPECT_TRUE(is_live(core::edi));

  // _asm shl ebx, 1
  static const uint8 kShl1[2] = { 0xD1, 0xE3 };
  AnalyzeSingleInstructionFromBuffer(kShl1, sizeof(kShl1));
  EXPECT_TRUE(is_live(core::ebx));

  // _asm shr esi, 2
  static const uint8 kShr1[3] = { 0xC1, 0xEE, 0x02 };
  AnalyzeSingleInstructionFromBuffer(kShr1, sizeof(kShr1));
  EXPECT_TRUE(is_live(core::esi));

  // _asm sar ecx, 3
  static const uint8 kSar1[3] = { 0xC1, 0xF9, 0x03 };
  AnalyzeSingleInstructionFromBuffer(kSar1, sizeof(kSar1));
  EXPECT_TRUE(is_live(core::ecx));

  // _asm rol ebx, 1
  static const uint8 kRol1[2] = { 0xD1, 0xC3 };
  AnalyzeSingleInstructionFromBuffer(kRol1, sizeof(kRol1));
  EXPECT_TRUE(is_live(core::ebx));

  // _asm ror esi, 2
  static const uint8 kRor1[3] = { 0xC1, 0xCE, 0x02 };
  AnalyzeSingleInstructionFromBuffer(kRor1, sizeof(kRor1));
  EXPECT_TRUE(is_live(core::esi));

  // _asm shl ebx, cl
  static const uint8 kShl2[2] = { 0xD3, 0xE3 };
  AnalyzeSingleInstructionFromBuffer(kShl2, sizeof(kShl2));
  EXPECT_TRUE(is_live(core::ebx));
  EXPECT_TRUE(is_live(core::ecx));

  // _asm shr esi, cl
  static const uint8 kShr2[2] = { 0xD3, 0xEE };
  AnalyzeSingleInstructionFromBuffer(kShr2, sizeof(kShr2));
  EXPECT_TRUE(is_live(core::esi));
  EXPECT_TRUE(is_live(core::ecx));

  // _asm sar edx, cl
  static const uint8 kSar2[2] = { 0xD3, 0xFA };
  AnalyzeSingleInstructionFromBuffer(kSar2, sizeof(kSar2));
  EXPECT_TRUE(is_live(core::edx));
  EXPECT_TRUE(is_live(core::ecx));

  // _asm rol ebx, cl
  static const uint8 kRol2[2] = { 0xD3, 0xC3 };
  AnalyzeSingleInstructionFromBuffer(kRol2, sizeof(kRol2));
  EXPECT_TRUE(is_live(core::ebx));
  EXPECT_TRUE(is_live(core::ecx));

  // _asm ror esi, cl
  static const uint8 kRor2[2] = { 0xD3, 0xCE };
  AnalyzeSingleInstructionFromBuffer(kRor2, sizeof(kRor2));
  EXPECT_TRUE(is_live(core::esi));
  EXPECT_TRUE(is_live(core::ecx));
}

TEST_F(LivenessAnalysisTest, StackInstructions) {
  // Validate instructions that push/pop on the stack.
  // _asm push eax
  static const uint8 kPushd[1] = { 0x50 };
  AnalyzeSingleInstructionFromBuffer(kPushd, sizeof(kPushd));
  EXPECT_TRUE(is_live(core::esp));
  EXPECT_TRUE(is_live(core::eax));

  // _asm pop eax
  static const uint8 kPopd[1] = { 0x58 };
  AnalyzeSingleInstructionFromBuffer(kPopd, sizeof(kPopd));
  EXPECT_TRUE(is_live(core::esp));
  EXPECT_FALSE(is_live(core::eax));

  // _asm push ax
  static const uint8 kPush[2] = { 0x66, 0x50 };
  AnalyzeSingleInstructionFromBuffer(kPush, sizeof(kPush));
  EXPECT_TRUE(is_live(core::esp));
  EXPECT_TRUE(is_live(core::eax));

  // _asm pop ax
  static const uint8 kPop[2] = { 0x66, 0x58 };
  AnalyzeSingleInstructionFromBuffer(kPop, sizeof(kPop));
  EXPECT_TRUE(is_live(core::esp));
  EXPECT_FALSE(is_live(core::eax));

  static const uint8 kPopSMem[3] = { 0x66, 0x8F, 0x00 };
  AnalyzeSingleInstructionFromBuffer(kPopSMem, sizeof(kPopSMem));
  EXPECT_TRUE(is_live(core::esp));
  EXPECT_TRUE(is_live(core::eax));
}

TEST_F(LivenessAnalysisTest, SetFlagInstructions) {
  // Validate instructions that consume flags. Ensure flags are used.

  // _asm seta al
  static const uint8 kSetA[3] = { 0x0F, 0x97, 0xC0 };
  AnalyzeSingleInstructionFromBuffer(kSetA, sizeof(kSetA));
  EXPECT_TRUE(are_arithmetic_flags_live());

  // _asm setae al
  static const uint8 kSetAE[3] = { 0x0F, 0x93, 0xC0 };
  AnalyzeSingleInstructionFromBuffer(kSetAE, sizeof(kSetAE));
  EXPECT_TRUE(are_arithmetic_flags_live());

  // _asm setb al
  static const uint8 kSetB[3] = { 0x0F, 0x92, 0xC0 };
  AnalyzeSingleInstructionFromBuffer(kSetB, sizeof(kSetB));
  EXPECT_TRUE(are_arithmetic_flags_live());

  // _asm setbe al
  static const uint8 kSetBE[3] = { 0x0F, 0x96, 0xC0 };
  AnalyzeSingleInstructionFromBuffer(kSetBE, sizeof(kSetBE));
  EXPECT_TRUE(are_arithmetic_flags_live());

  // _asm setg al
  static const uint8 kSetG[3] = { 0x0F, 0x9F, 0xC0 };
  AnalyzeSingleInstructionFromBuffer(kSetG, sizeof(kSetG));
  EXPECT_TRUE(are_arithmetic_flags_live());

  // _asm setge al
  static const uint8 kSetGE[3] = { 0x0F, 0x9D, 0xC0 };
  AnalyzeSingleInstructionFromBuffer(kSetGE, sizeof(kSetGE));
  EXPECT_TRUE(are_arithmetic_flags_live());

  // _asm setl al
  static const uint8 kSetL[3] = { 0x0F, 0x9C, 0xC0 };
  AnalyzeSingleInstructionFromBuffer(kSetL, sizeof(kSetL));
  EXPECT_TRUE(are_arithmetic_flags_live());

  // _asm setle al
  static const uint8 kSetLE[3] = { 0x0F, 0x9E, 0xC0 };
  AnalyzeSingleInstructionFromBuffer(kSetLE, sizeof(kSetLE));
  EXPECT_TRUE(are_arithmetic_flags_live());

  // _asm setno al
  static const uint8 kSetNO[3] = { 0x0F, 0x91, 0xC0 };
  AnalyzeSingleInstructionFromBuffer(kSetNO, sizeof(kSetNO));
  EXPECT_TRUE(are_arithmetic_flags_live());

  // _asm setnp al
  static const uint8 kSetNP[3] = { 0x0F, 0x9B, 0xC0 };
  AnalyzeSingleInstructionFromBuffer(kSetNP, sizeof(kSetNP));
  EXPECT_TRUE(are_arithmetic_flags_live());

  // _asm setns al
  static const uint8 kSetNS[3] = { 0x0F, 0x99, 0xC0 };
  AnalyzeSingleInstructionFromBuffer(kSetNS, sizeof(kSetNS));
  EXPECT_TRUE(are_arithmetic_flags_live());

  // _asm setnz al
  static const uint8 kSetNZ[3] = { 0x0F, 0x95, 0xC0 };
  AnalyzeSingleInstructionFromBuffer(kSetNZ, sizeof(kSetNZ));
  EXPECT_TRUE(are_arithmetic_flags_live());

  // _asm seto al
  static const uint8 kSetO[3] = { 0x0F, 0x90, 0xC0 };
  AnalyzeSingleInstructionFromBuffer(kSetO, sizeof(kSetO));
  EXPECT_TRUE(are_arithmetic_flags_live());

  // _asm setp al
  static const uint8 kSetP[3] = { 0x0F, 0x9A, 0xC0 };
  AnalyzeSingleInstructionFromBuffer(kSetP, sizeof(kSetP));
  EXPECT_TRUE(are_arithmetic_flags_live());

  // _asm sets al
  static const uint8 kSetS[3] = { 0x0F, 0x98, 0xC0 };
  AnalyzeSingleInstructionFromBuffer(kSetS, sizeof(kSetS));
  EXPECT_TRUE(are_arithmetic_flags_live());

  // _asm setz al
  static const uint8 kSetZ[3] = { 0x0F, 0x94, 0xC0 };
  AnalyzeSingleInstructionFromBuffer(kSetZ, sizeof(kSetZ));
  EXPECT_TRUE(are_arithmetic_flags_live());
}

TEST_F(LivenessAnalysisTest, PushPopFlagsInstructions) {
  // Validate instructions that push/pop flags. Ensure flags are used, and stack
  // pointer is modified.

  // _asm pushfd
  static const uint8 kPushfd[1] = { 0x9C };
  AnalyzeSingleInstructionFromBuffer(kPushfd, sizeof(kPushfd));
  EXPECT_TRUE(are_arithmetic_flags_live());
  EXPECT_TRUE(is_live(core::esp));

  // _asm popfd
  static const uint8 kPopfd[1] = { 0x9D };
  AnalyzeSingleInstructionFromBuffer(kPopfd, sizeof(kPopfd));
  EXPECT_FALSE(are_arithmetic_flags_live());
  EXPECT_TRUE(is_live(core::esp));

  // _asm pushf
  static const uint8 kPushf[2] = { 0x66, 0x9C };
  AnalyzeSingleInstructionFromBuffer(kPushf, sizeof(kPushf));
  EXPECT_TRUE(are_arithmetic_flags_live());
  EXPECT_TRUE(is_live(core::esp));

  // _asm popf
  static const uint8 kPopf[2] = { 0x66, 0x9D };
  AnalyzeSingleInstructionFromBuffer(kPopf, sizeof(kPopf));
  EXPECT_FALSE(are_arithmetic_flags_live());
  EXPECT_TRUE(is_live(core::esp));
}

TEST_F(LivenessAnalysisTest, LoadStoreFlagsInstructions) {
  // Validate instructions that load/store flags. Ensure flags are defined or
  // used, and stack pointer is not modified.

  // _asm sahf
  static const uint8 kSahf[1] = { 0x9E };
  AnalyzeSingleInstructionFromBuffer(kSahf, sizeof(kSahf));
  EXPECT_FALSE(are_arithmetic_flags_live());
  EXPECT_FALSE(is_live(core::esp));
  EXPECT_TRUE(is_live(core::eax));

  // _asm lahf
  static const uint8 kLahf[1] = { 0x9F };
  AnalyzeSingleInstructionFromBuffer(kLahf, sizeof(kLahf));
  EXPECT_TRUE(are_arithmetic_flags_live());
  EXPECT_FALSE(is_live(core::esp));
  EXPECT_FALSE(is_live(core::eax));
}

TEST_F(LivenessAnalysisTest, XorInitializationSpecialCase) {
  // Validate an initialization pattern used by x86 compiler.
  // Ensure the flags are assumed modified, and the register is unused.

  // _asm xor eax, eax
  static const uint8 kXor1[2] = { 0x33, 0xC0 };
  AnalyzeSingleInstructionFromBuffer(kXor1, sizeof(kXor1));
  EXPECT_FALSE(is_live(core::eax));
  EXPECT_FALSE(are_arithmetic_flags_live());

  // _asm xor ebx, ebx
  static const uint8 kXor2[2] = { 0x33, 0xDB };
  AnalyzeSingleInstructionFromBuffer(kXor2, sizeof(kXor2));
  EXPECT_FALSE(is_live(core::eax));
  EXPECT_FALSE(are_arithmetic_flags_live());

  // _asm xor ecx, ecx
  static const uint8 kXor3[2] = { 0x33, 0xC9 };
  AnalyzeSingleInstructionFromBuffer(kXor3, sizeof(kXor3));
  EXPECT_FALSE(is_live(core::eax));
  EXPECT_FALSE(are_arithmetic_flags_live());
}

TEST_F(LivenessAnalysisTest, NopInstructionSpecialCase) {
  // Nop should be ignored by the analysis.
  asm_.mov(core::eax, core::eax);
  asm_.mov(core::eax, Immediate(10));
  AnalyzeInstructions();
  EXPECT_FALSE(is_live(core::eax));
}

TEST_F(LivenessAnalysisTest, LivenessAnalysisOverControlFlow) {
  BasicBlockSubGraph subgraph;

  // Build and analyze this flow graph:
  //               [if1]
  //            /          \
  //           /            \
  //      [true1]          [false1]
  //      mov esi, 1       mov esi, 2
  //                       mov edi, 2
  //           \             /
  //            \           /
  //                [if2]     <-----------
  //            /          \               \
  //           /            \               \
  //      [true2]          [false2]          \
  //      mov eax, ebx     mov ebp, esi       |
  //                       mov esi, edi       |
  //                       mov edi, ebp       |
  //                       mov eax, [esi]     |
  //           \             /                |
  //            \           /                 |
  //                [end2]                   /
  //                mov ecx, eax            /
  //                    \                  /
  //                     -----------------/

  // Create the control flow graph.
  BasicCodeBlock* if1 = subgraph.AddBasicCodeBlock("if1");
  BasicCodeBlock* true1 = subgraph.AddBasicCodeBlock("true1");
  BasicCodeBlock* false1 = subgraph.AddBasicCodeBlock("false1");
  BasicCodeBlock* if2 = subgraph.AddBasicCodeBlock("if2");
  BasicCodeBlock* true2 = subgraph.AddBasicCodeBlock("true2");
  BasicCodeBlock* false2 = subgraph.AddBasicCodeBlock("false2");
  BasicCodeBlock* end2 = subgraph.AddBasicCodeBlock("end2");

  ASSERT_TRUE(if1 != NULL);
  ASSERT_TRUE(true1 != NULL);
  ASSERT_TRUE(false1 != NULL);
  ASSERT_TRUE(if2 != NULL);
  ASSERT_TRUE(true2 != NULL);
  ASSERT_TRUE(false2 != NULL);
  ASSERT_TRUE(end2 != NULL);

  AddSuccessorBetween(Successor::kConditionEqual, if1, true1);
  AddSuccessorBetween(Successor::kConditionNotEqual, if1, false1);
  AddSuccessorBetween(Successor::kConditionTrue, true1, if2);
  AddSuccessorBetween(Successor::kConditionTrue, false1, if2);

  AddSuccessorBetween(Successor::kConditionEqual, if2, true2);
  AddSuccessorBetween(Successor::kConditionNotEqual, if2, false2);
  AddSuccessorBetween(Successor::kConditionLess, true2, end2);
  AddSuccessorBetween(Successor::kConditionLess, false2, end2);

  AddSuccessorBetween(Successor::kConditionTrue, end2, if2);

  // Insert instructions into basic blocks.
  BasicBlockAssembler asm_end2(end2->instructions().end(),
                               &end2->instructions());
  asm_end2.mov(core::ecx, core::eax);

  BasicBlockAssembler asm_true2(true2->instructions().end(),
                                &true2->instructions());
  asm_true2.mov(core::eax, core::ebx);

  BasicBlockAssembler asm_false2(false2->instructions().end(),
                                 &false2->instructions());
  asm_false2.mov(core::ebp, core::esi);
  asm_false2.mov(core::esi, core::edi);
  asm_false2.mov(core::edi, core::ebp);
  asm_false2.mov(core::eax, Operand(core::esi));

  BasicBlockAssembler asm_true1(true1->instructions().end(),
                                &true1->instructions());
  asm_true1.mov(core::esi, Immediate(1));

  BasicBlockAssembler asm_false1(false1->instructions().end(),
                                 &false1->instructions());
  asm_false1.mov(core::esi, Immediate(2));
  asm_false1.mov(core::edi, Immediate(2));

  // Perform global liveness analysis.
  liveness_.Analyze(&subgraph);

  // Validate fix-point propagation.
  liveness_.GetStateAtEntryOf(end2, &state_);
  EXPECT_TRUE(is_live(core::eax));
  EXPECT_TRUE(is_live(core::ebx));
  EXPECT_FALSE(is_live(core::ecx));
  EXPECT_TRUE(is_live(core::esi));
  EXPECT_TRUE(is_live(core::edi));
  EXPECT_FALSE(is_live(core::ebp));

  liveness_.GetStateAtEntryOf(true2, &state_);
  EXPECT_FALSE(is_live(core::eax));
  EXPECT_TRUE(is_live(core::ebx));
  EXPECT_FALSE(is_live(core::ecx));
  EXPECT_TRUE(is_live(core::esi));
  EXPECT_TRUE(is_live(core::edi));
  EXPECT_FALSE(is_live(core::ebp));

  liveness_.GetStateAtEntryOf(false2, &state_);
  EXPECT_FALSE(is_live(core::eax));
  EXPECT_TRUE(is_live(core::ebx));
  EXPECT_FALSE(is_live(core::ecx));
  EXPECT_TRUE(is_live(core::esi));
  EXPECT_TRUE(is_live(core::edi));
  EXPECT_FALSE(is_live(core::ebp));

  liveness_.GetStateAtEntryOf(if2, &state_);
  EXPECT_FALSE(is_live(core::eax));
  EXPECT_TRUE(is_live(core::ebx));
  EXPECT_FALSE(is_live(core::ecx));
  EXPECT_TRUE(is_live(core::esi));
  EXPECT_TRUE(is_live(core::edi));
  EXPECT_FALSE(is_live(core::ebp));

  liveness_.GetStateAtEntryOf(true1, &state_);
  EXPECT_FALSE(is_live(core::eax));
  EXPECT_TRUE(is_live(core::ebx));
  EXPECT_FALSE(is_live(core::ecx));
  EXPECT_FALSE(is_live(core::esi));
  EXPECT_TRUE(is_live(core::edi));
  EXPECT_FALSE(is_live(core::ebp));

  liveness_.GetStateAtEntryOf(false1, &state_);
  EXPECT_FALSE(is_live(core::eax));
  EXPECT_TRUE(is_live(core::ebx));
  EXPECT_FALSE(is_live(core::ecx));
  EXPECT_FALSE(is_live(core::esi));
  EXPECT_FALSE(is_live(core::edi));
  EXPECT_FALSE(is_live(core::ebp));

  liveness_.GetStateAtEntryOf(if1, &state_);
  EXPECT_FALSE(is_live(core::eax));
  EXPECT_TRUE(is_live(core::ebx));
  EXPECT_FALSE(is_live(core::ecx));
  EXPECT_FALSE(is_live(core::esi));
  EXPECT_TRUE(is_live(core::edi));
  EXPECT_FALSE(is_live(core::ebp));
}

}  // namespace

}  // namespace analysis
}  // namespace block_graph
