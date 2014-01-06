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
typedef block_graph::BasicBlockSubGraph::BlockDescription BlockDescription;

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
// _asm mov ax, 0
const uint8 kMovAxZero[4] = { 0x66, 0xB8, 0x00, 0x00 };
// _asm mov al, 0
const uint8 kMovAlZero[2] =  { 0xB0, 0x00 };

class LivenessAnalysisTest : public testing::Test {
 public:
  LivenessAnalysisTest();

  inline bool is_def(const core::Register& reg) const {
    return defs_.IsLive(reg);
  }

  inline bool is_use(const core::Register& reg) const {
    return uses_.IsLive(reg);
  }

  inline bool is_live(const core::Register& reg) const {
    return state_.IsLive(reg);
  }

  inline bool are_arithmetic_flags_live() const {
    return state_.AreArithmeticFlagsLive();
  }

  template<size_t N>
  void AddInstructionFromBuffer(const uint8 (& data)[N]);
  void DefineAllRegisters();
  void AnalyzeInstructionsWithoutReset();
  void AnalyzeInstructions();

  template<size_t N>
  void UpdateDefsUsesFromBuffer(const uint8 (& data)[N]);

  template<size_t N>
  void AnalyzeSingleInstructionFromBuffer(const uint8 (& data)[N]);

  bool CheckCarryFlagInstruction(bool expect_on, bool expect_off);

  void AddSuccessorBetween(Successor::Condition condition,
                           BasicCodeBlock* from,
                           BasicCodeBlock* to);

 protected:
  BlockGraph block_graph_;
  BlockGraph::Block* test_block_;
  BasicBlock::Instructions instructions_;
  BasicBlockAssembler asm_;
  LivenessAnalysis liveness_;
  LivenessAnalysis::State state_;
  LivenessAnalysis::State defs_;
  LivenessAnalysis::State uses_;
};

LivenessAnalysisTest::LivenessAnalysisTest()
    : testing::Test(),
      test_block_(NULL),
      instructions_(),
      asm_(instructions_.end(), &instructions_),
      liveness_(),
      state_() {
  test_block_ = block_graph_.AddBlock(BlockGraph::CODE_BLOCK, 10, "test block");
}

template<size_t N>
void LivenessAnalysisTest::UpdateDefsUsesFromBuffer(const uint8 (& data)[N]) {
  // Decode an instruction.
  DCHECK_GT(core::AssemblerImpl::kMaxInstructionLength, N);

  block_graph::Instruction temp;
  ASSERT_TRUE(block_graph::Instruction::FromBuffer(&data[0], N, &temp));

  // Expect to decode the entire buffer.
  ASSERT_TRUE(temp.size() == N);

  // Analyze the defs/uses of this instruction.
  StateHelper::GetDefsOf(temp, &defs_);
  StateHelper::GetUsesOf(temp, &uses_);
}

template<size_t N>
void LivenessAnalysisTest::AddInstructionFromBuffer(const uint8 (& data)[N]) {
  // Decode an instruction and append it to basicblock_.
  DCHECK_GT(core::AssemblerImpl::kMaxInstructionLength, N);

  block_graph::Instruction temp;
  ASSERT_TRUE(block_graph::Instruction::FromBuffer(&data[0], N, &temp));

  // Expect to decode the entire buffer.
  ASSERT_TRUE(temp.size() == N);

  // Append this instruction to the basic block.
  instructions_.push_back(temp);
}

void LivenessAnalysisTest::DefineAllRegisters() {
  // Inserts instructions into basicblock_ so all registers are defined.
  AddInstructionFromBuffer(kMovEaxZero);
  AddInstructionFromBuffer(kMovEbxZero);
  AddInstructionFromBuffer(kMovEcxZero);
  AddInstructionFromBuffer(kMovEdxZero);
  AddInstructionFromBuffer(kMovEsiZero);
  AddInstructionFromBuffer(kMovEdiZero);
  AddInstructionFromBuffer(kMovEspZero);
  AddInstructionFromBuffer(kMovEbpZero);

  // Define arithmetic flags.
  AddInstructionFromBuffer(kCmpEaxEbx);
}

void LivenessAnalysisTest::AnalyzeInstructionsWithoutReset() {
  // Perform a backward liveness analysis on instructions in basicblock_.
  // Results are kept in 'state_' and may be accessed through IsLive and
  // AreArithmeticFlagsLive.
  Instructions::reverse_iterator instr_iter = instructions_.rbegin();
  for (; instr_iter != instructions_.rend(); ++instr_iter) {
    const Instruction& instr = *instr_iter;
    liveness_.PropagateBackward(instr, &state_);
  }
}

void LivenessAnalysisTest::AnalyzeInstructions() {
  LivenessAnalysis::StateHelper::SetAll(&state_);
  AnalyzeInstructionsWithoutReset();
}

template<size_t N>
void LivenessAnalysisTest::AnalyzeSingleInstructionFromBuffer(
    const uint8 (& data)[N]) {
  // This function creates a basic block with an instruction under test,
  // followed by instructions to define all registers and flags. This way, the
  // analysis may assume everything was dead before the instruction.
  instructions_.clear();
  StateHelper::SetAll(&state_);

  AddInstructionFromBuffer(data);
  DefineAllRegisters();
  AnalyzeInstructions();

  // Retrieve defs/uses of this instruction.
  UpdateDefsUsesFromBuffer(data);
}

bool LivenessAnalysisTest::CheckCarryFlagInstruction(
    bool expect_on, bool expect_off) {
  LivenessAnalysis::State flags;
  StateHelper::Clear(&flags);
  StateHelper::SetFlags(~(D_CF), &state_);

  // Try with the carry flag on.
  StateHelper::Clear(&state_);
  StateHelper::SetFlags(D_CF, &state_);
  AnalyzeInstructionsWithoutReset();
  StateHelper::Subtract(flags, &state_);
  if (are_arithmetic_flags_live() != expect_on)
    return false;

  // Try with the carry flag off.
  StateHelper::Clear(&state_);
  AnalyzeInstructionsWithoutReset();
  StateHelper::Subtract(flags, &state_);
  if (are_arithmetic_flags_live() != expect_off)
    return false;

  return true;
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
  EXPECT_FALSE(is_live(core::ax));
  EXPECT_FALSE(is_live(core::ah));
  EXPECT_TRUE(is_live(core::ebx));
  EXPECT_TRUE(is_live(core::bx));
  EXPECT_TRUE(is_live(core::bl));
  EXPECT_FALSE(is_live(core::ecx));
}

TEST_F(LivenessAnalysisTest, Mov2Analysis) {
  asm_.mov(core::eax, core::ebx);
  asm_.mov(core::edx, Immediate(10));
  asm_.mov(core::ecx, Immediate(test_block_, 0));
  AnalyzeInstructions();
  EXPECT_FALSE(is_live(core::eax));
  EXPECT_FALSE(is_live(core::ax));
  EXPECT_FALSE(is_live(core::ah));
  EXPECT_TRUE(is_live(core::ebx));
  EXPECT_TRUE(is_live(core::bx));
  EXPECT_TRUE(is_live(core::bl));
  EXPECT_FALSE(is_live(core::ecx));
  EXPECT_FALSE(is_live(core::edx));
}

TEST_F(LivenessAnalysisTest, DefineAllRegisters) {
  // Validate the tester by defining all registers and using none.
  DefineAllRegisters();
  AnalyzeInstructions();
  EXPECT_FALSE(is_live(core::eax));
  EXPECT_FALSE(is_live(core::ax));
  EXPECT_FALSE(is_live(core::al));
  EXPECT_FALSE(is_live(core::ah));
  EXPECT_FALSE(is_live(core::ebx));
  EXPECT_FALSE(is_live(core::bx));
  EXPECT_FALSE(is_live(core::bl));
  EXPECT_FALSE(is_live(core::bh));
  EXPECT_FALSE(is_live(core::ecx));
  EXPECT_FALSE(is_live(core::cx));
  EXPECT_FALSE(is_live(core::cl));
  EXPECT_FALSE(is_live(core::ch));
  EXPECT_FALSE(is_live(core::edx));
  EXPECT_FALSE(is_live(core::dx));
  EXPECT_FALSE(is_live(core::dl));
  EXPECT_FALSE(is_live(core::dh));
  EXPECT_FALSE(is_live(core::esi));
  EXPECT_FALSE(is_live(core::si));
  EXPECT_FALSE(is_live(core::edi));
  EXPECT_FALSE(is_live(core::di));
  EXPECT_FALSE(are_arithmetic_flags_live());
}

TEST_F(LivenessAnalysisTest, Defs1Analysis) {
  // Validate the tester by defining all registers and using some of them.
  AddInstructionFromBuffer(kMovEaxZero);
  AddInstructionFromBuffer(kMovEcxZero);
  AddInstructionFromBuffer(kMovEsiZero);
  AnalyzeInstructions();
  EXPECT_FALSE(is_live(core::eax));
  EXPECT_FALSE(is_live(core::ax));
  EXPECT_FALSE(is_live(core::ah));
  EXPECT_TRUE(is_live(core::ebx));
  EXPECT_TRUE(is_live(core::bx));
  EXPECT_TRUE(is_live(core::bl));
  EXPECT_FALSE(is_live(core::ecx));
  EXPECT_FALSE(is_live(core::cx));
  EXPECT_FALSE(is_live(core::cl));
  EXPECT_TRUE(is_live(core::edx));
  EXPECT_TRUE(is_live(core::dx));
  EXPECT_TRUE(is_live(core::dl));
  EXPECT_FALSE(is_live(core::esi));
  EXPECT_FALSE(is_live(core::si));
  EXPECT_TRUE(is_live(core::edi));
  EXPECT_TRUE(is_live(core::di));
}

TEST_F(LivenessAnalysisTest, Defs2Analysis) {
  // Validate the tester by defining all registers and using some of them.
  AddInstructionFromBuffer(kMovEbxZero);
  AddInstructionFromBuffer(kMovEdxZero);
  AddInstructionFromBuffer(kMovEdiZero);
  AnalyzeInstructions();
  EXPECT_TRUE(is_live(core::eax));
  EXPECT_TRUE(is_live(core::ax));
  EXPECT_TRUE(is_live(core::al));
  EXPECT_FALSE(is_live(core::ebx));
  EXPECT_FALSE(is_live(core::bx));
  EXPECT_FALSE(is_live(core::bh));
  EXPECT_TRUE(is_live(core::ecx));
  EXPECT_TRUE(is_live(core::cx));
  EXPECT_TRUE(is_live(core::cl));
  EXPECT_FALSE(is_live(core::edx));
  EXPECT_FALSE(is_live(core::dx));
  EXPECT_FALSE(is_live(core::dl));
  EXPECT_TRUE(is_live(core::esi));
  EXPECT_TRUE(is_live(core::si));
  EXPECT_FALSE(is_live(core::edi));
  EXPECT_FALSE(is_live(core::di));
}

TEST_F(LivenessAnalysisTest, Analysis16Bit) {
  AddInstructionFromBuffer(kMovAxZero);
  AnalyzeInstructions();
  EXPECT_TRUE(is_live(core::eax));
  EXPECT_FALSE(is_live(core::ax));
  EXPECT_FALSE(is_live(core::al));
  EXPECT_FALSE(is_live(core::ah));
}

TEST_F(LivenessAnalysisTest, Analysis8Bit) {
  AddInstructionFromBuffer(kMovAlZero);
  AnalyzeInstructions();
  EXPECT_TRUE(is_live(core::eax));
  EXPECT_TRUE(is_live(core::ax));
  EXPECT_FALSE(is_live(core::al));
  EXPECT_TRUE(is_live(core::ah));
}

TEST_F(LivenessAnalysisTest, OperandTypeLeft) {
  // Validate the support of all DiStorm operand types (as first operand).
  // _asm add eax, ecx
  static const uint8 kOpReg1[] = { 0x03, 0xC1 };
  AnalyzeSingleInstructionFromBuffer(kOpReg1);
  EXPECT_TRUE(is_live(core::eax));
  EXPECT_FALSE(is_live(core::ebx));
  EXPECT_TRUE(is_live(core::ecx));
  EXPECT_FALSE(is_live(core::edx));

  // _asm add [eax], ecx
  static const uint8 kOpSmem[] = { 0x01, 0x08 };
  AnalyzeSingleInstructionFromBuffer(kOpSmem);
  EXPECT_TRUE(is_live(core::eax));
  EXPECT_FALSE(is_live(core::ebx));
  EXPECT_TRUE(is_live(core::ecx));
  EXPECT_FALSE(is_live(core::edx));

  // _asm add [eax + 42], ecx
  static const uint8 kOpSmemOffet[] = { 0x01, 0x48, 0x2A };
  AnalyzeSingleInstructionFromBuffer(kOpSmemOffet);
  EXPECT_TRUE(is_live(core::eax));
  EXPECT_FALSE(is_live(core::ebx));
  EXPECT_TRUE(is_live(core::ecx));
  EXPECT_FALSE(is_live(core::edx));

  // _asm add [eax + ebx*2 + 42], ecx
  static const uint8 kOpMemOffset[] = { 0x01, 0x4C, 0x58, 0x2A };
  AnalyzeSingleInstructionFromBuffer(kOpMemOffset);
  EXPECT_TRUE(is_live(core::eax));
  EXPECT_TRUE(is_live(core::ebx));
  EXPECT_TRUE(is_live(core::ecx));
  EXPECT_FALSE(is_live(core::edx));

  // _asm add DWORD PTR [X], ecx
  static const uint8 kOpDispl[] = { 0x01, 0x0D, 0x80, 0x1E, 0xF2, 0x00 };
  AnalyzeSingleInstructionFromBuffer(kOpDispl);
  EXPECT_FALSE(is_live(core::eax));
  EXPECT_FALSE(is_live(core::ebx));
  EXPECT_TRUE(is_live(core::ecx));
  EXPECT_FALSE(is_live(core::edx));
}

TEST_F(LivenessAnalysisTest, OperandTypeRight) {
  // Validate the support of all DiStorm operand types (as second operand).
  // _asm add ecx, 1
  static const uint8 kOpReg1[] = { 0x83, 0xC1, 0x01 };
  AnalyzeSingleInstructionFromBuffer(kOpReg1);
  EXPECT_FALSE(is_live(core::eax));
  EXPECT_FALSE(is_live(core::ebx));
  EXPECT_TRUE(is_live(core::ecx));
  EXPECT_FALSE(is_live(core::edx));

  // _asm add ecx, eax
  static const uint8 kOpReg2[] = { 0x03, 0xC8 };
  AnalyzeSingleInstructionFromBuffer(kOpReg2);
  EXPECT_TRUE(is_live(core::eax));
  EXPECT_FALSE(is_live(core::ebx));
  EXPECT_TRUE(is_live(core::ecx));
  EXPECT_FALSE(is_live(core::edx));

  // _asm add ecx, [eax]
  static const uint8 kOpSmem[] = { 0x03, 0x08 };
  AnalyzeSingleInstructionFromBuffer(kOpSmem);
  EXPECT_TRUE(is_live(core::eax));
  EXPECT_FALSE(is_live(core::ebx));
  EXPECT_TRUE(is_live(core::ecx));
  EXPECT_FALSE(is_live(core::edx));

  // _asm add ecx, [eax + 42]
  static const uint8 kOpSmemOffet[] = { 0x03, 0x48, 0x2A };
  AnalyzeSingleInstructionFromBuffer(kOpSmemOffet);
  EXPECT_TRUE(is_live(core::eax));
  EXPECT_FALSE(is_live(core::ebx));
  EXPECT_TRUE(is_live(core::ecx));
  EXPECT_FALSE(is_live(core::edx));

  // _asm add ecx, [eax + ebx*2 + 42]
  static const uint8 kOpMemOffset[] = { 0x03, 0x4C, 0x58, 0x2A };
  AnalyzeSingleInstructionFromBuffer(kOpMemOffset);
  EXPECT_TRUE(is_live(core::eax));
  EXPECT_TRUE(is_live(core::ebx));
  EXPECT_TRUE(is_live(core::ecx));
  EXPECT_FALSE(is_live(core::edx));

  // _asm add ecx, DWORD PTR [X]
  static const uint8 kOpDispl[] = { 0x03, 0x0D, 0x80, 0x1E, 0x27, 0x00 };
  AnalyzeSingleInstructionFromBuffer(kOpDispl);
  EXPECT_FALSE(is_live(core::eax));
  EXPECT_FALSE(is_live(core::ebx));
  EXPECT_TRUE(is_live(core::ecx));
  EXPECT_FALSE(is_live(core::edx));
}

TEST_F(LivenessAnalysisTest, InstructionWithoutDefine) {
  // Validate instructions that fully overwrite and use the destination.
  // _asm cmp eax, [ecx]
  static const uint8 kCmp[] = { 0x3B, 0x01 };
  AnalyzeSingleInstructionFromBuffer(kCmp);
  EXPECT_TRUE(is_live(core::eax));
  EXPECT_TRUE(is_live(core::ecx));

  // _asm test ebx, [edx+12]
  static const uint8 kTest[] = { 0x85, 0x5A, 0x0C };
  AnalyzeSingleInstructionFromBuffer(kTest);
  EXPECT_TRUE(is_live(core::ebx));
  EXPECT_TRUE(is_live(core::edx));
}

TEST_F(LivenessAnalysisTest, InstructionsWithDefine) {
  // Validate instructions that fully overwrite the destination.
  // _asm mov ebx, [edx+12]
  static const uint8 kCmp[] = { 0x8B, 0x5A, 0x0C };
  AnalyzeSingleInstructionFromBuffer(kCmp);
  EXPECT_FALSE(is_live(core::ebx));
  EXPECT_TRUE(is_live(core::edx));

  // _asm lea ebx, [edx+12]
  static const uint8 kTest[] = { 0x8D, 0x5A, 0x0C };
  AnalyzeSingleInstructionFromBuffer(kTest);
  EXPECT_FALSE(is_live(core::ebx));
  EXPECT_TRUE(is_live(core::edx));
}

TEST_F(LivenessAnalysisTest, InstructionsWithPartialDefine) {
  // Registers partially defined must be considered alive.
  // _asm mov bl, dl
  static const uint8 kCmp[] = { 0xB3, 0x0C };
  // _asm mov DWORD PTR [X], ebx
  static const uint8 kStore[] = { 0x89, 0x1D, 0x80, 0x1E, 0x10, 0x01 };
  AddInstructionFromBuffer(kCmp);
  AddInstructionFromBuffer(kStore);
  AnalyzeInstructions();

  EXPECT_TRUE(is_live(core::ebx));
  EXPECT_TRUE(is_live(core::bx));
  EXPECT_FALSE(is_live(core::bl));
  EXPECT_TRUE(is_live(core::bh));

  EXPECT_TRUE(is_live(core::edx));
  EXPECT_TRUE(is_live(core::dx));
  EXPECT_TRUE(is_live(core::dl));
  EXPECT_TRUE(is_live(core::dh));
}

TEST_F(LivenessAnalysisTest, InstructionsWithPartialDefineAll) {
  static const uint8 kMovAl[] = { 0xB0, 0x00 };
  static const uint8 kMovBl[] = { 0xB1, 0x00 };
  static const uint8 kMovCl[] = { 0xB2, 0x00 };
  static const uint8 kMovDl[] = { 0xB3, 0x00 };
  static const uint8 kMovAh[] = { 0xB4, 0x00 };
  static const uint8 kMovBh[] = { 0xB7, 0x00 };
  static const uint8 kMovCh[] = { 0xB5, 0x00 };
  static const uint8 kMovDh[] = { 0xB6, 0x00 };
  static const uint8 kMovAx[] = { 0x66, 0xB8, 0x00, 0x00 };
  static const uint8 kMovBx[] = { 0x66, 0xBB, 0x00, 0x00 };
  static const uint8 kMovCx[] = { 0x66, 0xB9, 0x00, 0x00 };
  static const uint8 kMovDx[] = { 0x66, 0xBA, 0x00, 0x00 };
  static const uint8 kMovSi[] = { 0x66, 0xBE, 0x00, 0x00 };
  static const uint8 kMovDi[] = { 0x66, 0xBF, 0x00, 0x00 };
  static const uint8 kMovSp[] = { 0x66, 0xBC, 0x00, 0x00 };
  static const uint8 kMovBp[] = { 0x66, 0xBD, 0x00, 0x00 };

  // 8-bit partial registers.
  AddInstructionFromBuffer(kMovAl);
  AddInstructionFromBuffer(kMovBl);
  AddInstructionFromBuffer(kMovCl);
  AddInstructionFromBuffer(kMovDl);

  AddInstructionFromBuffer(kMovAh);
  AddInstructionFromBuffer(kMovBh);
  AddInstructionFromBuffer(kMovCh);
  AddInstructionFromBuffer(kMovDh);

  // 16-bit partial registers.
  AddInstructionFromBuffer(kMovAx);
  AddInstructionFromBuffer(kMovBx);
  AddInstructionFromBuffer(kMovCx);
  AddInstructionFromBuffer(kMovDx);

  AddInstructionFromBuffer(kMovSi);
  AddInstructionFromBuffer(kMovDi);
  AddInstructionFromBuffer(kMovSp);
  AddInstructionFromBuffer(kMovBp);

  AnalyzeInstructions();

  EXPECT_TRUE(is_live(core::eax));
  EXPECT_TRUE(is_live(core::ecx));
  EXPECT_TRUE(is_live(core::edx));
  EXPECT_TRUE(is_live(core::eax));
  EXPECT_TRUE(is_live(core::esi));
  EXPECT_TRUE(is_live(core::edi));
  EXPECT_TRUE(is_live(core::esp));
  EXPECT_TRUE(is_live(core::ebp));
}

TEST_F(LivenessAnalysisTest, ArithmeticUnaryInstructions) {
  // _asm dec eax
  static const uint8 kDec1[] = { 0x48 };
  AnalyzeSingleInstructionFromBuffer(kDec1);
  EXPECT_TRUE(is_live(core::eax));

  // _asm dec [ebx + 1]
  static const uint8 kDec2[] = { 0xFE, 0x4B, 0x01 };
  AnalyzeSingleInstructionFromBuffer(kDec2);
  EXPECT_TRUE(is_live(core::ebx));

  // _asm dec [esi + ebx*2 + 1]
  static const uint8 kDec3[] = { 0xFE, 0x4C, 0x5E, 0x01 };
  AnalyzeSingleInstructionFromBuffer(kDec3);
  EXPECT_TRUE(is_live(core::esi));
  EXPECT_TRUE(is_live(core::ebx));

  // _asm dec WORD PTR [X]
  static const uint8 kDec4[] = { 0x66, 0xFF, 0x0D, 0x80, 0x1E, 0x92, 0x00 };
  AnalyzeSingleInstructionFromBuffer(kDec4);
  EXPECT_FALSE(is_live(core::eax));
  EXPECT_FALSE(is_live(core::ebx));
  EXPECT_FALSE(is_live(core::ecx));
  EXPECT_FALSE(is_live(core::edx));

  // _asm not ebx
  static const uint8 kNot1[] = { 0xF7, 0xD3 };
  AnalyzeSingleInstructionFromBuffer(kNot1);
  EXPECT_TRUE(is_live(core::ebx));

  // _asm not [ebx]
  static const uint8 kNot2[] = { 0xF6, 0x13 };
  AnalyzeSingleInstructionFromBuffer(kNot2);
  EXPECT_TRUE(is_live(core::ebx));

  // _asm neg ebx
  static const uint8 kNeg1[] = { 0xF7, 0xDB };
  AnalyzeSingleInstructionFromBuffer(kNeg1);
  EXPECT_TRUE(is_live(core::ebx));

  // _asm neg [ebx]
  static const uint8 kNeg2[] = { 0xF6, 0x1B };
  AnalyzeSingleInstructionFromBuffer(kNeg2);
  EXPECT_TRUE(is_live(core::ebx));

  // _asm inc edx
  static const uint8 kInc[] = { 0x42 };
  AnalyzeSingleInstructionFromBuffer(kInc);
  EXPECT_TRUE(is_live(core::edx));

  // _asm inc dh
  static const uint8 kIncHalf[] = { 0xFE, 0xC6 };
  AnalyzeSingleInstructionFromBuffer(kIncHalf);
  EXPECT_TRUE(is_live(core::edx));
  EXPECT_TRUE(is_def(core::dh));
  EXPECT_FALSE(is_def(core::dl));
  EXPECT_TRUE(is_use(core::dh));
  EXPECT_FALSE(is_use(core::dl));
}

TEST_F(LivenessAnalysisTest, DecIncFlagsInstructions) {
  // NOTE: inc/dec do not touch the carry flag.
  // _asm inc edx
  static const uint8 kInc[] = { 0x42 };
  AddInstructionFromBuffer(kInc);
  EXPECT_TRUE(CheckCarryFlagInstruction(true, false));
  instructions_.clear();

  // _asm dec eax
  static const uint8 kDec1[] = { 0x48 };
  AddInstructionFromBuffer(kDec1);
  EXPECT_TRUE(CheckCarryFlagInstruction(true, false));
  instructions_.clear();
}

TEST_F(LivenessAnalysisTest, ArithmeticBinaryInstructions) {
  // _asm add ebx, ecx
  static const uint8 kAdd[] = { 0x03, 0xD9 };
  AnalyzeSingleInstructionFromBuffer(kAdd);
  EXPECT_TRUE(is_live(core::ebx));
  EXPECT_TRUE(is_live(core::ecx));
  EXPECT_TRUE(is_def(core::ebx));
  EXPECT_TRUE(is_use(core::ebx));
  EXPECT_TRUE(is_use(core::ecx));

  // _asm adc ebx, edx
  static const uint8 kAdc[] = { 0x13, 0xDA };
  AnalyzeSingleInstructionFromBuffer(kAdc);
  EXPECT_TRUE(is_live(core::ebx));
  EXPECT_TRUE(is_live(core::edx));

  // _asm sub esi, edi
  static const uint8 kSub[] = { 0x2B, 0xF7 };
  AnalyzeSingleInstructionFromBuffer(kSub);
  EXPECT_TRUE(is_live(core::esi));
  EXPECT_TRUE(is_live(core::edi));

  // _asm sbb ebx, [eax + edx + 12]
  static const uint8 KSbb[] = { 0x1B, 0x5C, 0x10, 0x0C };
  AnalyzeSingleInstructionFromBuffer(KSbb);
  EXPECT_TRUE(is_live(core::eax));
  EXPECT_TRUE(is_live(core::ebx));
  EXPECT_TRUE(is_live(core::edx));

  // _asm and ebx, ecx
  static const uint8 kAnd[] = { 0x23, 0xD9 };
  AnalyzeSingleInstructionFromBuffer(kAnd);
  EXPECT_TRUE(is_live(core::ebx));
  EXPECT_TRUE(is_live(core::ecx));

  // _asm or esi, [edi]
  static const uint8 kOr[] = { 0x0B, 0x37 };
  AnalyzeSingleInstructionFromBuffer(kOr);
  EXPECT_TRUE(is_live(core::esi));
  EXPECT_TRUE(is_live(core::edi));

  // _asm xor [esi], edi
  static const uint8 kXor[] = { 0x31, 0x3E };
  AnalyzeSingleInstructionFromBuffer(kXor);
  EXPECT_TRUE(is_live(core::esi));
  EXPECT_TRUE(is_live(core::edi));

  // _asm shl ebx, 1
  static const uint8 kShl1[] = { 0xD1, 0xE3 };
  AnalyzeSingleInstructionFromBuffer(kShl1);
  EXPECT_TRUE(is_live(core::ebx));

  // _asm shr esi, 2
  static const uint8 kShr1[] = { 0xC1, 0xEE, 0x02 };
  AnalyzeSingleInstructionFromBuffer(kShr1);
  EXPECT_TRUE(is_live(core::esi));

  // _asm sar ecx, 3
  static const uint8 kSar1[] = { 0xC1, 0xF9, 0x03 };
  AnalyzeSingleInstructionFromBuffer(kSar1);
  EXPECT_TRUE(is_live(core::ecx));

  // _asm rol ebx, 1
  static const uint8 kRol1[] = { 0xD1, 0xC3 };
  AnalyzeSingleInstructionFromBuffer(kRol1);
  EXPECT_TRUE(is_live(core::ebx));

  // _asm ror esi, 2
  static const uint8 kRor1[] = { 0xC1, 0xCE, 0x02 };
  AnalyzeSingleInstructionFromBuffer(kRor1);
  EXPECT_TRUE(is_live(core::esi));

  // _asm shl ebx, cl
  static const uint8 kShl2[] = { 0xD3, 0xE3 };
  AnalyzeSingleInstructionFromBuffer(kShl2);
  EXPECT_TRUE(is_live(core::ebx));
  EXPECT_TRUE(is_live(core::ecx));

  // _asm shr esi, cl
  static const uint8 kShr2[] = { 0xD3, 0xEE };
  AnalyzeSingleInstructionFromBuffer(kShr2);
  EXPECT_TRUE(is_live(core::esi));
  EXPECT_TRUE(is_live(core::ecx));

  // _asm sar edx, cl
  static const uint8 kSar2[] = { 0xD3, 0xFA };
  AnalyzeSingleInstructionFromBuffer(kSar2);
  EXPECT_TRUE(is_live(core::edx));
  EXPECT_TRUE(is_live(core::ecx));

  // _asm rol ebx, cl
  static const uint8 kRol2[] = { 0xD3, 0xC3 };
  AnalyzeSingleInstructionFromBuffer(kRol2);
  EXPECT_TRUE(is_live(core::ebx));
  EXPECT_TRUE(is_live(core::ecx));

  // _asm ror esi, cl
  static const uint8 kRor2[] = { 0xD3, 0xCE };
  AnalyzeSingleInstructionFromBuffer(kRor2);
  EXPECT_TRUE(is_live(core::esi));
  EXPECT_TRUE(is_live(core::ecx));
}

TEST_F(LivenessAnalysisTest, ArithmeticFlagsInstructions) {
  // _asm adc ebx, edx
  static const uint8 kAdc[] = { 0x13, 0xDA };
  AnalyzeSingleInstructionFromBuffer(kAdc);
  EXPECT_TRUE(CheckCarryFlagInstruction(true, true));

  // _asm sbb ebx, [eax + edx + 12]
  static const uint8 KSbb[] = { 0x1B, 0x5C, 0x10, 0x0C };
  AnalyzeSingleInstructionFromBuffer(KSbb);
  EXPECT_TRUE(CheckCarryFlagInstruction(true, true));
}

TEST_F(LivenessAnalysisTest, MultiplicationInstructions) {
  // _asm mul ecx
  static const uint8 kMul32[] = { 0xF7, 0xE1 };
  AnalyzeSingleInstructionFromBuffer(kMul32);
  EXPECT_FALSE(are_arithmetic_flags_live());
  EXPECT_TRUE(is_live(core::eax));
  EXPECT_FALSE(is_live(core::ebx));
  EXPECT_TRUE(is_live(core::ecx));
  EXPECT_FALSE(is_live(core::edx));
  EXPECT_TRUE(is_def(core::eax));
  EXPECT_FALSE(is_def(core::ecx));
  EXPECT_TRUE(is_def(core::edx));
  EXPECT_TRUE(is_use(core::eax));
  EXPECT_TRUE(is_use(core::ecx));
  EXPECT_FALSE(is_use(core::edx));

  // _asm mul cx
  static const uint8 kMul16[] = { 0x66, 0xF7, 0xE1 };
  AnalyzeSingleInstructionFromBuffer(kMul16);
  EXPECT_FALSE(are_arithmetic_flags_live());
  EXPECT_TRUE(is_live(core::eax));
  EXPECT_FALSE(is_live(core::ebx));
  EXPECT_TRUE(is_live(core::ecx));
  EXPECT_FALSE(is_live(core::edx));
  EXPECT_TRUE(is_def(core::eax));
  EXPECT_FALSE(is_def(core::ecx));
  EXPECT_TRUE(is_use(core::eax));
  EXPECT_TRUE(is_use(core::ecx));

  // _asm mul cl
  static const uint8 kMul8[] = { 0xF6, 0xE1 };
  AnalyzeSingleInstructionFromBuffer(kMul8);
  EXPECT_FALSE(are_arithmetic_flags_live());
  EXPECT_TRUE(is_live(core::eax));
  EXPECT_FALSE(is_live(core::ebx));
  EXPECT_TRUE(is_live(core::ecx));
  EXPECT_FALSE(is_live(core::edx));
  EXPECT_FALSE(is_live(core::ah));
  EXPECT_TRUE(is_def(core::eax));
  EXPECT_TRUE(is_def(core::ah));
  EXPECT_FALSE(is_def(core::ecx));
  EXPECT_FALSE(is_def(core::cl));
  EXPECT_TRUE(is_use(core::eax));
  EXPECT_FALSE(is_use(core::ah));
  EXPECT_TRUE(is_use(core::al));
  EXPECT_TRUE(is_use(core::ecx));
  EXPECT_FALSE(is_use(core::ch));
  EXPECT_TRUE(is_use(core::cl));

  // _asm mul ah
  static const uint8 kMul16High[] = { 0xF6, 0xE4 };
  AnalyzeSingleInstructionFromBuffer(kMul16High);
  EXPECT_FALSE(are_arithmetic_flags_live());
  EXPECT_TRUE(is_live(core::eax));
  EXPECT_FALSE(is_live(core::ebx));
  EXPECT_FALSE(is_live(core::ecx));
  EXPECT_FALSE(is_live(core::edx));
  EXPECT_TRUE(is_live(core::ah));
  EXPECT_TRUE(is_def(core::eax));
  EXPECT_TRUE(is_def(core::ah));
  EXPECT_TRUE(is_def(core::al));
  EXPECT_FALSE(is_def(core::dl));
  EXPECT_TRUE(is_use(core::ah));
  EXPECT_TRUE(is_use(core::al));
  EXPECT_FALSE(is_use(core::dl));

  // _asm imul ecx
  static const uint8 kIMul32[] = { 0xF7, 0xE9 };
  AnalyzeSingleInstructionFromBuffer(kIMul32);
  EXPECT_FALSE(are_arithmetic_flags_live());
  EXPECT_TRUE(is_live(core::eax));
  EXPECT_FALSE(is_live(core::ebx));
  EXPECT_TRUE(is_live(core::ecx));
  EXPECT_FALSE(is_live(core::edx));
  EXPECT_TRUE(is_def(core::al));
  EXPECT_TRUE(is_def(core::dl));
  EXPECT_TRUE(is_use(core::ecx));

  // _asm imul cx
  static const uint8 kIMul16[] = { 0xF7, 0xE9 };
  AnalyzeSingleInstructionFromBuffer(kIMul16);
  EXPECT_FALSE(are_arithmetic_flags_live());
  EXPECT_TRUE(is_live(core::eax));
  EXPECT_FALSE(is_live(core::ebx));
  EXPECT_TRUE(is_live(core::ecx));
  EXPECT_FALSE(is_live(core::edx));
  EXPECT_TRUE(is_def(core::al));
  EXPECT_TRUE(is_def(core::dl));
  EXPECT_TRUE(is_use(core::ecx));

  // _asm imul cl
  static const uint8 kIMul8[] = { 0xF6, 0xE9 };
  AnalyzeSingleInstructionFromBuffer(kIMul8);
  EXPECT_FALSE(are_arithmetic_flags_live());
  EXPECT_TRUE(is_live(core::eax));
  EXPECT_FALSE(is_live(core::ebx));
  EXPECT_TRUE(is_live(core::ecx));
  EXPECT_FALSE(is_live(core::edx));
  EXPECT_FALSE(is_live(core::ch));
  EXPECT_TRUE(is_def(core::al));
  EXPECT_FALSE(is_def(core::dl));
  EXPECT_TRUE(is_use(core::ecx));

  // _asm imul ah
  static const uint8 kIMul16High[] = { 0xF6, 0xEC };
  AnalyzeSingleInstructionFromBuffer(kIMul16High);
  EXPECT_FALSE(are_arithmetic_flags_live());
  EXPECT_TRUE(is_live(core::eax));
  EXPECT_FALSE(is_live(core::ebx));
  EXPECT_FALSE(is_live(core::ecx));
  EXPECT_FALSE(is_live(core::edx));
  EXPECT_TRUE(is_live(core::ah));
  EXPECT_TRUE(is_def(core::al));
  EXPECT_TRUE(is_def(core::ah));
  EXPECT_TRUE(is_use(core::al));
  EXPECT_TRUE(is_use(core::ah));
  EXPECT_FALSE(is_def(core::dl));

  // _asm imul eax, 3
  static const uint8 kIMul32ByCst[] = { 0x6B, 0xC0, 0x03 };
  AnalyzeSingleInstructionFromBuffer(kIMul32ByCst);
  EXPECT_FALSE(are_arithmetic_flags_live());
  EXPECT_TRUE(is_live(core::eax));
  EXPECT_FALSE(is_live(core::ebx));
  EXPECT_FALSE(is_live(core::ecx));
  EXPECT_FALSE(is_live(core::edx));
  EXPECT_TRUE(is_def(core::eax));
  EXPECT_TRUE(is_use(core::eax));
  EXPECT_FALSE(is_def(core::dl));

  // _asm imul ecx, 3
  static const uint8 kIMul32EcxByCst[] = { 0x6B, 0xC9, 0x03 };
  AnalyzeSingleInstructionFromBuffer(kIMul32EcxByCst);
  EXPECT_FALSE(are_arithmetic_flags_live());
  EXPECT_FALSE(are_arithmetic_flags_live());
  EXPECT_FALSE(is_live(core::eax));
  EXPECT_FALSE(is_live(core::ebx));
  EXPECT_TRUE(is_live(core::ecx));
  EXPECT_FALSE(is_live(core::edx));
  EXPECT_FALSE(is_def(core::eax));
  EXPECT_TRUE(is_def(core::ecx));
  EXPECT_FALSE(is_def(core::dl));
  EXPECT_FALSE(is_use(core::eax));
  EXPECT_TRUE(is_use(core::ecx));
}

TEST_F(LivenessAnalysisTest, ConversionInstructions) {
  static const uint8 kCdq[] = { 0x99 };
  AnalyzeSingleInstructionFromBuffer(kCdq);
  EXPECT_TRUE(is_live(core::eax));
  EXPECT_FALSE(is_live(core::edx));
  EXPECT_FALSE(are_arithmetic_flags_live());
  EXPECT_TRUE(is_def(core::eax));
  EXPECT_TRUE(is_def(core::edx));
  EXPECT_TRUE(is_use(core::eax));
  EXPECT_FALSE(is_use(core::edx));

  static const uint8 kCwd[] = { 0x66, 0x99 };
  AnalyzeSingleInstructionFromBuffer(kCwd);
  EXPECT_TRUE(is_live(core::eax));
  EXPECT_FALSE(is_live(core::edx));
  EXPECT_FALSE(are_arithmetic_flags_live());
  EXPECT_TRUE(is_def(core::eax));
  EXPECT_FALSE(is_def(core::edx));
  EXPECT_TRUE(is_use(core::eax));
  EXPECT_FALSE(is_use(core::edx));
}

TEST_F(LivenessAnalysisTest, EpilogueInstructions) {
  static const uint8 kLeave[] = { 0xC9 };
  AnalyzeSingleInstructionFromBuffer(kLeave);
  EXPECT_TRUE(is_live(core::ebp));
  EXPECT_TRUE(is_live(core::esp));
  EXPECT_FALSE(are_arithmetic_flags_live());
  EXPECT_TRUE(is_def(core::esp));
  EXPECT_TRUE(is_def(core::ebp));
  EXPECT_TRUE(is_use(core::esp));
  EXPECT_TRUE(is_use(core::esp));
}

TEST_F(LivenessAnalysisTest, StackInstructions) {
  // Validate instructions that push/pop on the stack.
  // _asm push eax
  static const uint8 kPushd[] = { 0x50 };
  AnalyzeSingleInstructionFromBuffer(kPushd);
  EXPECT_TRUE(is_live(core::esp));
  EXPECT_TRUE(is_live(core::eax));
  EXPECT_TRUE(is_def(core::esp));
  EXPECT_TRUE(is_use(core::esp));

  // _asm pop eax
  static const uint8 kPopd[] = { 0x58 };
  AnalyzeSingleInstructionFromBuffer(kPopd);
  EXPECT_TRUE(is_live(core::esp));
  EXPECT_FALSE(is_live(core::eax));
  EXPECT_TRUE(is_def(core::esp));
  EXPECT_TRUE(is_use(core::esp));

  // _asm push ax
  static const uint8 kPush[] = { 0x66, 0x50 };
  AnalyzeSingleInstructionFromBuffer(kPush);
  EXPECT_TRUE(is_live(core::esp));
  EXPECT_TRUE(is_live(core::eax));
  EXPECT_TRUE(is_def(core::esp));
  EXPECT_TRUE(is_use(core::esp));

  // _asm pop ax
  static const uint8 kPop[] = { 0x66, 0x58 };
  AnalyzeSingleInstructionFromBuffer(kPop);
  EXPECT_TRUE(is_live(core::esp));
  EXPECT_FALSE(is_live(core::eax));
  EXPECT_TRUE(is_def(core::esp));
  EXPECT_TRUE(is_use(core::esp));

  static const uint8 kPopSMem[] = { 0x66, 0x8F, 0x00 };
  AnalyzeSingleInstructionFromBuffer(kPopSMem);
  EXPECT_TRUE(is_live(core::esp));
  EXPECT_TRUE(is_live(core::eax));
  EXPECT_TRUE(is_def(core::esp));
  EXPECT_TRUE(is_use(core::esp));
}

TEST_F(LivenessAnalysisTest, SetFlagInstructions) {
  // Validate instructions that consume flags. Ensure flags are used.

  // _asm seta al
  static const uint8 kSetA[] = { 0x0F, 0x97, 0xC0 };
  AnalyzeSingleInstructionFromBuffer(kSetA);
  EXPECT_TRUE(are_arithmetic_flags_live());
  EXPECT_TRUE(is_def(core::al));
  EXPECT_FALSE(is_use(core::al));

  // _asm setae al
  static const uint8 kSetAE[] = { 0x0F, 0x93, 0xC0 };
  AnalyzeSingleInstructionFromBuffer(kSetAE);
  EXPECT_TRUE(are_arithmetic_flags_live());

  // _asm setb al
  static const uint8 kSetB[] = { 0x0F, 0x92, 0xC0 };
  AnalyzeSingleInstructionFromBuffer(kSetB);
  EXPECT_TRUE(are_arithmetic_flags_live());

  // _asm setbe al
  static const uint8 kSetBE[] = { 0x0F, 0x96, 0xC0 };
  AnalyzeSingleInstructionFromBuffer(kSetBE);
  EXPECT_TRUE(are_arithmetic_flags_live());

  // _asm setg al
  static const uint8 kSetG[] = { 0x0F, 0x9F, 0xC0 };
  AnalyzeSingleInstructionFromBuffer(kSetG);
  EXPECT_TRUE(are_arithmetic_flags_live());

  // _asm setge al
  static const uint8 kSetGE[] = { 0x0F, 0x9D, 0xC0 };
  AnalyzeSingleInstructionFromBuffer(kSetGE);
  EXPECT_TRUE(are_arithmetic_flags_live());

  // _asm setl al
  static const uint8 kSetL[] = { 0x0F, 0x9C, 0xC0 };
  AnalyzeSingleInstructionFromBuffer(kSetL);
  EXPECT_TRUE(are_arithmetic_flags_live());

  // _asm setle al
  static const uint8 kSetLE[] = { 0x0F, 0x9E, 0xC0 };
  AnalyzeSingleInstructionFromBuffer(kSetLE);
  EXPECT_TRUE(are_arithmetic_flags_live());

  // _asm setno al
  static const uint8 kSetNO[] = { 0x0F, 0x91, 0xC0 };
  AnalyzeSingleInstructionFromBuffer(kSetNO);
  EXPECT_TRUE(are_arithmetic_flags_live());

  // _asm setnp al
  static const uint8 kSetNP[] = { 0x0F, 0x9B, 0xC0 };
  AnalyzeSingleInstructionFromBuffer(kSetNP);
  EXPECT_TRUE(are_arithmetic_flags_live());

  // _asm setns al
  static const uint8 kSetNS[] = { 0x0F, 0x99, 0xC0 };
  AnalyzeSingleInstructionFromBuffer(kSetNS);
  EXPECT_TRUE(are_arithmetic_flags_live());

  // _asm setnz al
  static const uint8 kSetNZ[] = { 0x0F, 0x95, 0xC0 };
  AnalyzeSingleInstructionFromBuffer(kSetNZ);
  EXPECT_TRUE(are_arithmetic_flags_live());

  // _asm seto al
  static const uint8 kSetO[] = { 0x0F, 0x90, 0xC0 };
  AnalyzeSingleInstructionFromBuffer(kSetO);
  EXPECT_TRUE(are_arithmetic_flags_live());

  // _asm setp al
  static const uint8 kSetP[] = { 0x0F, 0x9A, 0xC0 };
  AnalyzeSingleInstructionFromBuffer(kSetP);
  EXPECT_TRUE(are_arithmetic_flags_live());

  // _asm sets al
  static const uint8 kSetS[] = { 0x0F, 0x98, 0xC0 };
  AnalyzeSingleInstructionFromBuffer(kSetS);
  EXPECT_TRUE(are_arithmetic_flags_live());

  // _asm setz al
  static const uint8 kSetZ[] = { 0x0F, 0x94, 0xC0 };
  AnalyzeSingleInstructionFromBuffer(kSetZ);
  EXPECT_TRUE(are_arithmetic_flags_live());
}

TEST_F(LivenessAnalysisTest, PushPopFlagsInstructions) {
  // Validate instructions that push/pop flags. Ensure flags are used, and stack
  // pointer is modified.

  // _asm pushfd
  static const uint8 kPushfd[] = { 0x9C };
  AnalyzeSingleInstructionFromBuffer(kPushfd);
  EXPECT_TRUE(are_arithmetic_flags_live());
  EXPECT_TRUE(is_live(core::esp));
  EXPECT_TRUE(is_def(core::esp));
  EXPECT_TRUE(is_use(core::esp));

  // _asm popfd
  static const uint8 kPopfd[] = { 0x9D };
  AnalyzeSingleInstructionFromBuffer(kPopfd);
  EXPECT_FALSE(are_arithmetic_flags_live());
  EXPECT_TRUE(is_live(core::esp));
  EXPECT_TRUE(is_def(core::esp));
  EXPECT_TRUE(is_use(core::esp));

  // _asm pushf
  static const uint8 kPushf[] = { 0x66, 0x9C };
  AnalyzeSingleInstructionFromBuffer(kPushf);
  EXPECT_TRUE(are_arithmetic_flags_live());
  EXPECT_TRUE(is_live(core::esp));
  EXPECT_TRUE(is_def(core::esp));
  EXPECT_TRUE(is_use(core::esp));

  // _asm popf
  static const uint8 kPopf[] = { 0x66, 0x9D };
  AnalyzeSingleInstructionFromBuffer(kPopf);
  EXPECT_FALSE(are_arithmetic_flags_live());
  EXPECT_TRUE(is_live(core::esp));
  EXPECT_TRUE(is_def(core::esp));
  EXPECT_TRUE(is_use(core::esp));
}

TEST_F(LivenessAnalysisTest, LoadStoreFlagsInstructions) {
  // Validate instructions that load/store flags. Ensure flags are defined or
  // used, and stack pointer is not modified.

  // _asm sahf
  static const uint8 kSahf[] = { 0x9E };
  AnalyzeSingleInstructionFromBuffer(kSahf);
  EXPECT_FALSE(are_arithmetic_flags_live());
  EXPECT_FALSE(is_live(core::esp));
  EXPECT_TRUE(is_live(core::eax));
  EXPECT_FALSE(is_def(core::ah));
  EXPECT_TRUE(is_use(core::ah));

  // _asm lahf
  static const uint8 kLahf[] = { 0x9F };
  AnalyzeSingleInstructionFromBuffer(kLahf);
  EXPECT_TRUE(are_arithmetic_flags_live());
  EXPECT_FALSE(is_live(core::esp));
  EXPECT_FALSE(is_live(core::eax));
  EXPECT_TRUE(is_def(core::ah));
  EXPECT_FALSE(is_use(core::ah));
}

TEST_F(LivenessAnalysisTest, ExtendMovInstructions) {
  // _asm movsx eax, cl
  static const uint8 kMovsx1[] = { 0x0F, 0xBE, 0xC1 };
  AnalyzeSingleInstructionFromBuffer(kMovsx1);
  EXPECT_FALSE(are_arithmetic_flags_live());
  EXPECT_FALSE(is_live(core::eax));
  EXPECT_TRUE(is_live(core::ecx));
  EXPECT_TRUE(is_def(core::ah));
  EXPECT_FALSE(is_use(core::ch));

  // _asm movsx eax, BYTE PTR [ecx]
  static const uint8 kMovsx2[] = { 0x0F, 0xBE, 0x01 };
  AnalyzeSingleInstructionFromBuffer(kMovsx2);
  EXPECT_FALSE(are_arithmetic_flags_live());
  EXPECT_FALSE(is_live(core::eax));
  EXPECT_TRUE(is_live(core::ecx));

  // _asm movzx eax, cl
  static const uint8 kMovzx1[] = { 0x0F, 0xB6, 0xC1 };
  AnalyzeSingleInstructionFromBuffer(kMovzx1);
  EXPECT_FALSE(are_arithmetic_flags_live());
  EXPECT_FALSE(is_live(core::eax));
  EXPECT_TRUE(is_live(core::ecx));

  // _asm movzx eax, BYTE PTR [ecx]
  static const uint8 kMovzx2[] = { 0x0F, 0xB6, 0x01 };
  AnalyzeSingleInstructionFromBuffer(kMovzx2);
  EXPECT_FALSE(are_arithmetic_flags_live());
  EXPECT_FALSE(is_live(core::eax));
  EXPECT_TRUE(is_live(core::ecx));
}

TEST_F(LivenessAnalysisTest, StringInstructions) {
  // movs dword ptr es:[edi], dword ptr [esi]
  static const uint8 kMovsl[] = { 0xA5 };
  AnalyzeSingleInstructionFromBuffer(kMovsl);
  EXPECT_TRUE(is_live(core::esi));
  EXPECT_TRUE(is_live(core::edi));
  EXPECT_FALSE(is_live(core::ecx));
  EXPECT_FALSE(are_arithmetic_flags_live());
  EXPECT_TRUE(is_def(core::esi));
  EXPECT_TRUE(is_def(core::edi));
  EXPECT_TRUE(is_use(core::esi));
  EXPECT_TRUE(is_use(core::edi));

  // movs byte ptr es:[edi], byte ptr [esi]
  static const uint8 kMovsb[] = { 0xA4 };
  AnalyzeSingleInstructionFromBuffer(kMovsb);
  EXPECT_TRUE(is_live(core::esi));
  EXPECT_TRUE(is_live(core::edi));
  EXPECT_FALSE(is_live(core::ecx));
  EXPECT_FALSE(are_arithmetic_flags_live());

  // stos dword ptr es:[edi]
  static const uint8 kStosl[] = { 0xAB };
  AnalyzeSingleInstructionFromBuffer(kStosl);
  EXPECT_FALSE(is_live(core::esi));
  EXPECT_TRUE(is_live(core::edi));
  EXPECT_FALSE(is_live(core::ecx));
  EXPECT_FALSE(are_arithmetic_flags_live());
  EXPECT_FALSE(is_def(core::esi));
  EXPECT_TRUE(is_def(core::edi));
  EXPECT_FALSE(is_use(core::esi));
  EXPECT_TRUE(is_use(core::edi));

  // stos byte ptr es:[edi]
  static const uint8 Stosb[] = { 0xAA };
  AnalyzeSingleInstructionFromBuffer(Stosb);
  EXPECT_FALSE(is_live(core::esi));
  EXPECT_TRUE(is_live(core::edi));
  EXPECT_FALSE(is_live(core::ecx));
  EXPECT_FALSE(are_arithmetic_flags_live());
}

TEST_F(LivenessAnalysisTest, PrefixedStringInstructions) {
  // repne movs dword ptr es:[edi], dword ptr [esi]
  static const uint8 kMovsl[] = { 0xF2, 0xA5 };
  AnalyzeSingleInstructionFromBuffer(kMovsl);
  EXPECT_TRUE(is_live(core::esi));
  EXPECT_TRUE(is_live(core::edi));
  EXPECT_TRUE(is_live(core::ecx));
  EXPECT_FALSE(are_arithmetic_flags_live());

  // repne movs byte ptr es:[edi], byte ptr [esi]
  static const uint8 kMovsb[] = { 0xF2, 0xA4 };
  AnalyzeSingleInstructionFromBuffer(kMovsb);
  EXPECT_TRUE(is_live(core::esi));
  EXPECT_TRUE(is_live(core::edi));
  EXPECT_TRUE(is_live(core::ecx));
  EXPECT_FALSE(are_arithmetic_flags_live());

  // repne stos dword ptr es:[edi]
  static const uint8 kStosl[] = { 0xF2, 0xAB };
  AnalyzeSingleInstructionFromBuffer(kStosl);
  EXPECT_FALSE(is_live(core::esi));
  EXPECT_TRUE(is_live(core::edi));
  EXPECT_TRUE(is_live(core::ecx));
  EXPECT_FALSE(are_arithmetic_flags_live());

  // repne stos byte ptr es:[edi]
  static const uint8 Stosb[] = { 0xF2, 0xAA };
  AnalyzeSingleInstructionFromBuffer(Stosb);
  EXPECT_FALSE(is_live(core::esi));
  EXPECT_TRUE(is_live(core::edi));
  EXPECT_TRUE(is_live(core::ecx));
  EXPECT_FALSE(are_arithmetic_flags_live());
}

TEST_F(LivenessAnalysisTest, FloatingPointInstructions) {
  // _asm fld1
  static const uint8 kFld1[] = { 0xD9, 0xE8 };
  // _asm fldz
  static const uint8 kFldz[] = { 0xD9, 0xEE };
  // _asm fadd
  static const uint8 kFadd[] = { 0xDE, 0xC1 };
  // _asm faddp st(3), st(0)
  static const uint8 kFaddp[] = { 0xDE, 0xC3 };
  // _asm fsub
  static const uint8 kFsub[] = { 0xDE, 0xE9 };
  // _asm fsubp st(3), st(0)
  static const uint8 kFsubp[] = { 0xDE, 0xEB };
  // _asm fmul
  static const uint8 kFmul[] = { 0xDE, 0xC9 };
  // _asm fmulp st(3), st(0)
  static const uint8 kFmulp[] = { 0xDE, 0xCB };

  // Floating point instructions don't touch any register nor general registers.
  AddInstructionFromBuffer(kFld1);
  AddInstructionFromBuffer(kFldz);
  AddInstructionFromBuffer(kFadd);
  AddInstructionFromBuffer(kFaddp);
  AddInstructionFromBuffer(kFsub);
  AddInstructionFromBuffer(kFsubp);
  AddInstructionFromBuffer(kFmul);
  AddInstructionFromBuffer(kFmulp);
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

TEST_F(LivenessAnalysisTest, FloatingPointMemoryInstructions) {
  // _asm fld DWORD PTR [eax + ecx]
  static const uint8 kFld[] = { 0xD9, 0x04, 0x08 };
  AnalyzeSingleInstructionFromBuffer(kFld);
  EXPECT_TRUE(is_live(core::eax));
  EXPECT_FALSE(is_live(core::ebx));
  EXPECT_TRUE(is_live(core::ecx));
  EXPECT_FALSE(are_arithmetic_flags_live());

  // _asm fst DWORD PTR [eax + ecx]
  static const uint8 kFst[] = { 0xD9, 0x14, 0x08 };
  AnalyzeSingleInstructionFromBuffer(kFst);
  EXPECT_TRUE(is_live(core::eax));
  EXPECT_FALSE(is_live(core::ebx));
  EXPECT_TRUE(is_live(core::ecx));
  EXPECT_FALSE(are_arithmetic_flags_live());

  // _asm fstp DWORD PTR [eax + ecx]
  static const uint8 kFstp[] = { 0xD9, 0x1C, 0x08 };
  AnalyzeSingleInstructionFromBuffer(kFstp);
  EXPECT_TRUE(is_live(core::eax));
  EXPECT_FALSE(is_live(core::ebx));
  EXPECT_TRUE(is_live(core::ecx));
  EXPECT_FALSE(are_arithmetic_flags_live());

  // _asm fadd DWORD PTR [eax]
  static const uint8 kFadd[] = { 0xD8, 0x00 };
  AnalyzeSingleInstructionFromBuffer(kFadd);
  EXPECT_TRUE(is_live(core::eax));
  EXPECT_FALSE(are_arithmetic_flags_live());

  // _asm fsub DWORD PTR [ecx]
  static const uint8 kFsub[] = { 0xD8, 0x21 };
  AnalyzeSingleInstructionFromBuffer(kFsub);
  EXPECT_TRUE(is_live(core::ecx));
  EXPECT_FALSE(are_arithmetic_flags_live());

  // _asm fmul DWORD PTR [esi]
  static const uint8 kFmul[] = { 0xD8, 0x0E };
  AnalyzeSingleInstructionFromBuffer(kFmul);
  EXPECT_TRUE(is_live(core::esi));
  EXPECT_FALSE(are_arithmetic_flags_live());

  // _asm fild DWORD PTR [eax]
  static const uint8 kFild[] = { 0xDB, 0x00 };
  AnalyzeSingleInstructionFromBuffer(kFild);
  EXPECT_TRUE(is_live(core::eax));
  EXPECT_FALSE(are_arithmetic_flags_live());

  // _asm fist DWORD PTR [eax]
  static const uint8 kFist[] = { 0xDB, 0x10 };
  AnalyzeSingleInstructionFromBuffer(kFist);
  EXPECT_TRUE(is_live(core::eax));
  EXPECT_FALSE(are_arithmetic_flags_live());

  // _asm fistp DWORD PTR [eax]
  static const uint8 kFistp[] = { 0xDB, 0x18 };
  AnalyzeSingleInstructionFromBuffer(kFistp);
  EXPECT_TRUE(is_live(core::eax));
  EXPECT_FALSE(are_arithmetic_flags_live());
}

TEST_F(LivenessAnalysisTest, FloatingPointCompareInstructions) {
  // _asm fcom
  static const uint8 kFcom[] = { 0xD8, 0xD1 };
  AnalyzeSingleInstructionFromBuffer(kFcom);
  EXPECT_FALSE(are_arithmetic_flags_live());

  // _asm fcomp
  static const uint8 kFcomp[] = { 0xD8, 0xD9 };
  AnalyzeSingleInstructionFromBuffer(kFcomp);
  EXPECT_FALSE(are_arithmetic_flags_live());

  // _asm fcompp
  static const uint8 kFcompp[] = { 0xDE, 0xD9 };
  AnalyzeSingleInstructionFromBuffer(kFcompp);
  EXPECT_FALSE(are_arithmetic_flags_live());

  // _asm fcomi
  static const uint8 kFcomi[] = { 0xDB, 0xF1 };
  AnalyzeSingleInstructionFromBuffer(kFcomi);
  EXPECT_FALSE(are_arithmetic_flags_live());

  // _asm fcomip
  static const uint8 fcomip[] = { 0xDF, 0xF1 };
  AnalyzeSingleInstructionFromBuffer(fcomip);
  EXPECT_FALSE(are_arithmetic_flags_live());
}

TEST_F(LivenessAnalysisTest, FloatingPointCompareMemoryInstructions) {
  // _asm fcom qword ptr [edx+ecx*8]
  static const uint8 kFcom[] = { 0xDC, 0x14, 0xCA };
  AnalyzeSingleInstructionFromBuffer(kFcom);
  EXPECT_FALSE(is_live(core::eax));
  EXPECT_FALSE(is_live(core::ebx));
  EXPECT_TRUE(is_live(core::ecx));
  EXPECT_TRUE(is_live(core::edx));
  EXPECT_FALSE(are_arithmetic_flags_live());

  // _asm fcomp word ptr [edx+ecx*8]
  static const uint8 kFcomp[] = { 0xDC, 0x1C, 0xCA };
  AnalyzeSingleInstructionFromBuffer(kFcomp);
  EXPECT_FALSE(is_live(core::eax));
  EXPECT_FALSE(is_live(core::ebx));
  EXPECT_TRUE(is_live(core::ecx));
  EXPECT_TRUE(is_live(core::edx));
  EXPECT_FALSE(are_arithmetic_flags_live());

  // _asm ficom qword ptr [edx+ecx*8]
  static const uint8 kFicom[] = { 0xDE, 0x14, 0xCA };
  AnalyzeSingleInstructionFromBuffer(kFicom);
  EXPECT_FALSE(is_live(core::eax));
  EXPECT_FALSE(is_live(core::ebx));
  EXPECT_TRUE(is_live(core::ecx));
  EXPECT_TRUE(is_live(core::edx));
  EXPECT_FALSE(are_arithmetic_flags_live());

  // _asm ficomp word ptr [edx+ecx*8]
  static const uint8 kFicomp[] = { 0xDE, 0x1C, 0xCA };
  AnalyzeSingleInstructionFromBuffer(kFicomp);
  EXPECT_FALSE(is_live(core::eax));
  EXPECT_FALSE(is_live(core::ebx));
  EXPECT_TRUE(is_live(core::ecx));
  EXPECT_TRUE(is_live(core::edx));
  EXPECT_FALSE(are_arithmetic_flags_live());

  // _asm ficom dword ptr [eax]
  static const uint8 kFicom2[] = { 0xDA, 0x10 };
  AnalyzeSingleInstructionFromBuffer(kFicom2);
  EXPECT_TRUE(is_live(core::eax));
  EXPECT_FALSE(is_live(core::edx));
  EXPECT_FALSE(are_arithmetic_flags_live());

  // _asm ficomp dword ptr [eax]
  static const uint8 ficomp2[] = { 0xDA, 0x18 };
  AnalyzeSingleInstructionFromBuffer(ficomp2);
  EXPECT_TRUE(is_live(core::eax));
  EXPECT_FALSE(is_live(core::edx));
  EXPECT_FALSE(are_arithmetic_flags_live());
}

TEST_F(LivenessAnalysisTest, FloatingPointCompareWithFlagsInstructions) {
  // Some floating point operations modify eflags.

  // _asm fcomi
  static const uint8 kFcomi[] = { 0xDB, 0xF1 };
  AddInstructionFromBuffer(kFcomi);
  EXPECT_TRUE(CheckCarryFlagInstruction(false, false));
  instructions_.clear();

  // _asm fcomip
  static const uint8 fcomip[] = { 0xDF, 0xF1 };
  AddInstructionFromBuffer(fcomip);
  EXPECT_TRUE(CheckCarryFlagInstruction(false, false));
  instructions_.clear();
}

TEST_F(LivenessAnalysisTest, UnknownInstruction) {
  // Ensure unknown instructions are processed correctly.
  static const uint8 kRdtsc[] = { 0x0F, 0x31 };
  AnalyzeSingleInstructionFromBuffer(kRdtsc);
  EXPECT_TRUE(is_live(core::eax));
  EXPECT_TRUE(is_live(core::ecx));
  EXPECT_TRUE(is_live(core::esi));
  EXPECT_TRUE(is_live(core::ebp));
  EXPECT_TRUE(are_arithmetic_flags_live());
}

TEST_F(LivenessAnalysisTest, XorInitializationSpecialCase) {
  // Validate an initialization pattern used by x86 compiler.
  // Ensure the flags are assumed modified, and the register is unused.

  // _asm xor eax, eax
  static const uint8 kXor1[] = { 0x33, 0xC0 };
  AnalyzeSingleInstructionFromBuffer(kXor1);
  EXPECT_FALSE(is_live(core::eax));
  EXPECT_FALSE(are_arithmetic_flags_live());
  EXPECT_TRUE(is_def(core::eax));
  EXPECT_FALSE(is_use(core::eax));

  // _asm xor ebx, ebx
  static const uint8 kXor2[] = { 0x33, 0xDB };
  AnalyzeSingleInstructionFromBuffer(kXor2);
  EXPECT_FALSE(is_live(core::eax));
  EXPECT_FALSE(are_arithmetic_flags_live());
  EXPECT_TRUE(is_def(core::ebx));
  EXPECT_FALSE(is_use(core::ebx));

  // _asm xor ecx, ecx
  static const uint8 kXor3[] = { 0x33, 0xC9 };
  AnalyzeSingleInstructionFromBuffer(kXor3);
  EXPECT_FALSE(is_live(core::eax));
  EXPECT_FALSE(are_arithmetic_flags_live());
  EXPECT_TRUE(is_def(core::ecx));
  EXPECT_FALSE(is_use(core::ecx));
}

TEST_F(LivenessAnalysisTest, NopInstructionSpecialCase) {
  // Nop should be ignored by the analysis.
  asm_.mov(core::eax, core::eax);
  asm_.mov(core::eax, Immediate(10));
  AnalyzeInstructions();
  EXPECT_FALSE(is_live(core::eax));
}

TEST_F(LivenessAnalysisTest, GetStateAtEntryOfWithNull) {
  // It is valid to pass a NULL pointer to get a state.
  liveness_.GetStateAtEntryOf(NULL, &state_);
  EXPECT_TRUE(is_live(core::eax));
  EXPECT_TRUE(is_live(core::esi));
  EXPECT_TRUE(are_arithmetic_flags_live());
}

TEST_F(LivenessAnalysisTest, GetStateAtExitOfWithNull) {
  // It is valid to pass a NULL pointer to get a state.
  liveness_.GetStateAtExitOf(NULL, &state_);
  EXPECT_TRUE(is_live(core::eax));
  EXPECT_TRUE(is_live(core::esi));
  EXPECT_TRUE(are_arithmetic_flags_live());
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

  AddSuccessorBetween(Successor::kConditionOverflow, if2, true2);
  AddSuccessorBetween(Successor::kConditionNotOverflow, if2, false2);
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

TEST_F(LivenessAnalysisTest, AnalyzeWithData) {
  BasicBlockSubGraph subgraph;
  const uint8 raw_data[] = { 0, 1, 2, 3, 4 };

  BlockDescription* block = subgraph.AddBlockDescription(
      "b1", "b1.obj", BlockGraph::CODE_BLOCK, 7, 2, 42);

  BasicCodeBlock* bb = subgraph.AddBasicCodeBlock("bb");
  BasicDataBlock* data =
      subgraph.AddBasicDataBlock("data", sizeof(raw_data), &raw_data[0]);

  block->basic_block_order.push_back(bb);
  block->basic_block_order.push_back(data);

  BasicBlockAssembler asm_bb(bb->instructions().end(), &bb->instructions());
  asm_bb.mov(core::eax, core::ebx);
  asm_bb.ret();

  // Analyze the flow graph.
  liveness_.Analyze(&subgraph);

  liveness_.GetStateAtEntryOf(bb, &state_);
  EXPECT_FALSE(is_live(core::eax));
  EXPECT_TRUE(is_live(core::ebx));
  EXPECT_TRUE(is_live(core::esi));

  liveness_.GetStateAtEntryOf(data, &state_);
  EXPECT_TRUE(is_live(core::eax));
  EXPECT_TRUE(is_live(core::ebx));
  EXPECT_TRUE(is_live(core::esi));
}

}  // namespace

}  // namespace analysis
}  // namespace block_graph
