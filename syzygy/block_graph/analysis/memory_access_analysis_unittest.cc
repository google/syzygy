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
// Unittests for memory access analysis.

#include "syzygy/block_graph/analysis/memory_access_analysis.h"

#include "gtest/gtest.h"
#include "mnemonics.h"  // NOLINT

namespace block_graph {
namespace analysis {

namespace {

typedef block_graph::analysis::MemoryAccessAnalysis::State State;
typedef block_graph::BasicBlockSubGraph::BasicBlock BasicBlock;
typedef block_graph::BasicBlockSubGraph::BasicBlock::Instructions Instructions;
typedef BasicBlockSubGraph::BlockDescription BlockDescription;

// _asm add eax, ecx
const uint8_t kClearEax[] = {0x03, 0xC1};
// _asm add ecx, [eax]
const uint8_t kReadEax[] = {0x03, 0x08};
// _asm add ecx, [eax + 42]
const uint8_t kReadEax42[] = {0x03, 0x48, 0x2A};
// _asm add eax, ecx
const uint8_t kRegsOnly[] = {0x03, 0xC1};
// _asm add [eax + ebx*2 + 42], ecx
const uint8_t kWriteWithScale[] = {0x01, 0x4C, 0x58, 0x2A};
// _asm add DWORD PTR [X], ecx
const uint8_t kWriteDispl[] = {0x01, 0x0D, 0x80, 0x1E, 0xF2, 0x00};
// _asm add [eax + 42], ecx
const uint8_t kWriteEax42[] = {0x01, 0x48, 0x2A};
// _asm lea ecx, [eax]
const uint8_t kLeaEax[] = {0x8D, 0x08};
// _asm lea ecx, [eax + 42]
const uint8_t kLeaEax42[] = {0x8D, 0x48, 0x2A};

// _asm repnz movsb
const uint8_t kRepMovsb[] = {0xF2, 0xA4};

// _asm add ecx, [eax + C]
const uint8_t kReadEax10[] = {0x03, 0x48, 0x0A};
const uint8_t kReadEax11[] = {0x03, 0x48, 0x0B};
const uint8_t kReadEax12[] = {0x03, 0x48, 0x0C};
const uint8_t kReadEax13[] = {0x03, 0x48, 0x0D};
const uint8_t kReadEax14[] = {0x03, 0x48, 0x0E};
const uint8_t kReadEax15[] = {0x03, 0x48, 0x0F};

// _asm ret
const uint8_t kRet[] = {0xC3};
// _asm call <FFFFFFFF>
const uint8_t kCall[] = {0xE8, 0xFF, 0xD7, 0xFF, 0xFF};
// _asm rdtsc
const uint8_t kRdtsc[] = {0x0F, 0x31};

void AddSuccessorBetween(Successor::Condition condition,
                         BasicCodeBlock* from,
                         BasicCodeBlock* to) {
  from->successors().push_back(
      Successor(condition,
                BasicBlockReference(BlockGraph::RELATIVE_REF,
                                    BlockGraph::Reference::kMaximumSize,
                                    to),
                0));
}

}  // namespace

class TestMemoryAccessAnalysisState: public MemoryAccessAnalysis::State {
 public:
  bool IsEmpty(const assm::Register32& reg) const;
  bool IsEmpty() const;
  bool Contains(const assm::Register32& reg, int32_t displ) const;

  template <size_t N>
  bool HasNonRedundantAccess(const uint8_t(&data)[N]) const;

  template <size_t N>
  void Execute(const uint8_t(&data)[N]);

  using MemoryAccessAnalysis::State::Clear;
};

class TestMemoryAccessAnalysis: public MemoryAccessAnalysis {
 public:
  using MemoryAccessAnalysis::Intersect;
};

class MemoryAccessAnalysisTest : public testing::Test {
 public:
  MemoryAccessAnalysisTest() : bb_(NULL) {
    bb_ = subgraph_.AddBasicCodeBlock("Dummy");
  }

  bool Intersect(const block_graph::BasicBlock* bb, const State& state) {
    return memory_access_.Intersect(bb, state);
  }

  void GetStateAtEntryOf(const BasicBlock* bb, State* state) const {
    return memory_access_.GetStateAtEntryOf(bb, state);
  }

  template <size_t N>
  void PropagateForward(const uint8_t(&data)[N]);

 protected:
  TestMemoryAccessAnalysis memory_access_;
  TestMemoryAccessAnalysisState state_;
  BasicBlockSubGraph subgraph_;
  BasicCodeBlock* bb_;
};

bool TestMemoryAccessAnalysisState::IsEmpty(
    const assm::Register32& reg) const {
  return active_memory_accesses_[reg.id() - assm::kRegister32Min].empty();
}

bool TestMemoryAccessAnalysisState::IsEmpty() const {
  for (int r = 0; r < assm::kRegister32Count; ++r) {
    if (!IsEmpty(assm::kRegisters32[r]))
      return false;
  }
  return true;
}

bool TestMemoryAccessAnalysisState::Contains(const assm::Register32& reg,
                                             int32_t displ) const {
  const std::set<int32_t>& offsets =
      active_memory_accesses_[reg.id() - assm::kRegister32Min];
  return offsets.find(displ) != offsets.end();
}

template <size_t N>
bool TestMemoryAccessAnalysisState::HasNonRedundantAccess(
    const uint8_t(&data)[N]) const {
  // Decode an instruction.
  DCHECK_GT(assm::kMaxInstructionLength, N);

  block_graph::Instruction temp;
  bool decoded = block_graph::Instruction::FromBuffer(&data[0], N, &temp);
  DCHECK(decoded);

  // Expect to decode the entire buffer.
  DCHECK_EQ(N, temp.size());

  // Execute the decoded instruction, and modify the current state.
  return MemoryAccessAnalysis::State::HasNonRedundantAccess(temp);
}

template <size_t N>
void TestMemoryAccessAnalysisState::Execute(const uint8_t(&data)[N]) {
  // Decode an instruction.
  DCHECK_GT(assm::kMaxInstructionLength, N);

  block_graph::Instruction temp;
  bool decoded = block_graph::Instruction::FromBuffer(&data[0], N, &temp);
  DCHECK(decoded);

  // Expect to decode the entire buffer.
  DCHECK_EQ(N, temp.size());

  // Execute the decoded instruction, and modify the current state.
  MemoryAccessAnalysis::State::Execute(temp);
}

template <size_t N>
void MemoryAccessAnalysisTest::PropagateForward(const uint8_t(&data)[N]) {
  // Decode an instruction.
  DCHECK_GT(assm::kMaxInstructionLength, N);

  block_graph::Instruction temp;
  bool decoded = block_graph::Instruction::FromBuffer(&data[0], N, &temp);
  ASSERT_TRUE(decoded);

  // Expect to decode the entire buffer.
  ASSERT_EQ(N, temp.size());

  // Execute the decoded instruction, and modify the current state.
  MemoryAccessAnalysis::PropagateForward(temp, &state_);
}

TEST(MemoryAccessAnalysisStateTest, Constructor) {
  // Initial state is empty.
  TestMemoryAccessAnalysisState state;
  EXPECT_TRUE(state.IsEmpty());
}

TEST(MemoryAccessAnalysisStateTest, CopyConstructor) {
  TestMemoryAccessAnalysisState state1;

  state1.Execute(kReadEax);
  state1.Execute(kWriteEax42);

  EXPECT_TRUE(state1.Contains(assm::eax, 0));
  EXPECT_TRUE(state1.Contains(assm::eax, 42));

  // Expect memory accesses to be copied into state2.
  TestMemoryAccessAnalysisState state2(state1);
  EXPECT_TRUE(state2.Contains(assm::eax, 0));
  EXPECT_TRUE(state2.Contains(assm::eax, 42));
}

TEST(MemoryAccessAnalysisStateTest, Clear) {
  TestMemoryAccessAnalysisState state;

  state.Execute(kWriteEax42);
  EXPECT_TRUE(!state.IsEmpty());
  state.Clear();
  EXPECT_TRUE(state.IsEmpty());
}

TEST(MemoryAccessAnalysisStateTest, ExecuteOperandKind) {
  TestMemoryAccessAnalysisState state;

  state.Execute(kRegsOnly);
  EXPECT_TRUE(state.IsEmpty());

  state.Execute(kWriteWithScale);
  EXPECT_TRUE(state.IsEmpty());

  state.Execute(kWriteDispl);
  EXPECT_TRUE(state.IsEmpty());

  state.Execute(kReadEax);
  EXPECT_TRUE(state.Contains(assm::eax, 0));

  state.Execute(kReadEax42);
  EXPECT_TRUE(state.Contains(assm::eax, 42));
}

TEST(MemoryAccessAnalysisStateTest, LeaOperand) {
  TestMemoryAccessAnalysisState state;

  // LEA do not perform a memory access.
  state.Execute(kLeaEax);
  EXPECT_FALSE(state.Contains(assm::eax, 0));
  state.Execute(kLeaEax42);
  EXPECT_FALSE(state.Contains(assm::eax, 42));
}

TEST(MemoryAccessAnalysisStateTest, ExecuteWithPrefix) {
  TestMemoryAccessAnalysisState state;

  state.Execute(kRepMovsb);
  EXPECT_TRUE(state.IsEmpty());
}

TEST(MemoryAccessAnalysisStateTest, HasNonRedundantAccess) {
  TestMemoryAccessAnalysisState state;

  // Initial state is empty, and accesses are not redundant.
  bool redundant_read1 = state.HasNonRedundantAccess(kReadEax42);
  bool redundant_write1 = state.HasNonRedundantAccess(kWriteEax42);
  EXPECT_TRUE(redundant_read1);
  EXPECT_TRUE(redundant_write1);

  // Perform a read of [eax + 42].
  state.Execute(kReadEax42);
  EXPECT_TRUE(state.Contains(assm::eax, 42));

  // After the read, accesses are redundant.
  bool redundant_read2 = state.HasNonRedundantAccess(kReadEax42);
  bool redundant_write2 = state.HasNonRedundantAccess(kWriteEax42);
  EXPECT_FALSE(redundant_read2);
  EXPECT_FALSE(redundant_write2);
}

TEST(MemoryAccessAnalysisStateTest, HasNonRedundantAccessOperandKind) {
  TestMemoryAccessAnalysisState state;

  // Instructions without memory access, on empty state.
  EXPECT_FALSE(state.HasNonRedundantAccess(kRegsOnly));
  EXPECT_FALSE(state.HasNonRedundantAccess(kLeaEax));
  EXPECT_FALSE(state.HasNonRedundantAccess(kLeaEax42));

  // Initial state is empty, and accesses are not redundant.
  EXPECT_TRUE(state.HasNonRedundantAccess(kReadEax));
  EXPECT_TRUE(state.HasNonRedundantAccess(kReadEax42));
  EXPECT_TRUE(state.HasNonRedundantAccess(kWriteWithScale));
  EXPECT_TRUE(state.HasNonRedundantAccess(kWriteDispl));
  EXPECT_TRUE(state.HasNonRedundantAccess(kWriteEax42));
}

TEST(MemoryAccessAnalysisStateTest, HasNonRedundantAccessWithPrefix) {
  TestMemoryAccessAnalysisState state;
  state.Execute(kRepMovsb);
  bool redundant = state.HasNonRedundantAccess(kRepMovsb);
  EXPECT_TRUE(redundant);
}

TEST_F(MemoryAccessAnalysisTest, GetStateOf) {
  // It is valid to get the state of a NULL block.
  GetStateAtEntryOf(NULL, &state_);
  EXPECT_TRUE(state_.IsEmpty());

  // Get an non-existing basic block.
  GetStateAtEntryOf(bb_, &state_);
  EXPECT_TRUE(state_.IsEmpty());
}

TEST_F(MemoryAccessAnalysisTest, IntersectEmpty) {
  memory_access_.GetStateAtEntryOf(bb_, &state_);
  EXPECT_TRUE(state_.IsEmpty());

  // Perform an initial intersection with an empty set.
  TestMemoryAccessAnalysisState state;
  Intersect(bb_, state);

  state.Execute(kReadEax10);
  state.Execute(kReadEax11);

  // Perform an second intersection with a non empty set.
  Intersect(bb_, state_);
  GetStateAtEntryOf(bb_, &state_);

  // The results must be empty.
  EXPECT_TRUE(state_.IsEmpty());
}

TEST_F(MemoryAccessAnalysisTest, IntersectStates) {
  // Intersection with displacements [10, 11, 12, 13, 14, 15].
  TestMemoryAccessAnalysisState state1;
  state1.Execute(kReadEax10);
  state1.Execute(kReadEax11);
  state1.Execute(kReadEax12);
  state1.Execute(kReadEax13);
  state1.Execute(kReadEax14);
  state1.Execute(kReadEax15);
  Intersect(bb_, state1);

  // Intersection with displacements [10, 11, 12, 14].
  TestMemoryAccessAnalysisState state2;
  state2.Execute(kReadEax10);
  state2.Execute(kReadEax11);
  state2.Execute(kReadEax12);
  state2.Execute(kReadEax14);
  Intersect(bb_, state2);

  // Check current state [10, 11, 12, 14].
  GetStateAtEntryOf(bb_, &state_);
  EXPECT_TRUE(state_.Contains(assm::eax, 10));
  EXPECT_TRUE(state_.Contains(assm::eax, 11));
  EXPECT_TRUE(state_.Contains(assm::eax, 12));
  EXPECT_FALSE(state_.Contains(assm::eax, 13));
  EXPECT_TRUE(state_.Contains(assm::eax, 14));
  EXPECT_FALSE(state_.Contains(assm::eax, 15));

  // Intersection with displacements [10, 11, 15].
  TestMemoryAccessAnalysisState state3;
  state3.Execute(kReadEax10);
  state3.Execute(kReadEax11);
  state3.Execute(kReadEax15);
  Intersect(bb_, state3);

  // Check current state [10, 11].
  GetStateAtEntryOf(bb_, &state_);
  EXPECT_TRUE(state_.Contains(assm::eax, 10));
  EXPECT_TRUE(state_.Contains(assm::eax, 11));
  EXPECT_FALSE(state_.Contains(assm::eax, 12));
  EXPECT_FALSE(state_.Contains(assm::eax, 13));
  EXPECT_FALSE(state_.Contains(assm::eax, 14));
  EXPECT_FALSE(state_.Contains(assm::eax, 15));

  // Intersection with displacements [15].
  TestMemoryAccessAnalysisState state4;
  state4.Execute(kReadEax15);
  Intersect(bb_, state4);

  // The state must be empty.
  GetStateAtEntryOf(bb_, &state_);
  EXPECT_TRUE(state_.IsEmpty());
}

TEST_F(MemoryAccessAnalysisTest, PropagateForwardSimple) {
  ASSERT_NO_FATAL_FAILURE(PropagateForward(kReadEax10));
  EXPECT_TRUE(state_.Contains(assm::eax, 10));

  ASSERT_NO_FATAL_FAILURE(PropagateForward(kReadEax));
  EXPECT_TRUE(state_.Contains(assm::eax, 0));
  EXPECT_TRUE(state_.Contains(assm::eax, 10));

  ASSERT_NO_FATAL_FAILURE(PropagateForward(kClearEax));
  EXPECT_TRUE(state_.IsEmpty());

  ASSERT_NO_FATAL_FAILURE(PropagateForward(kLeaEax));
  EXPECT_TRUE(state_.IsEmpty());
}

TEST_F(MemoryAccessAnalysisTest, PropagateForwardWithCallRet) {
  ASSERT_NO_FATAL_FAILURE(PropagateForward(kReadEax10));
  EXPECT_TRUE(state_.Contains(assm::eax, 10));
  ASSERT_NO_FATAL_FAILURE(PropagateForward(kCall));
  EXPECT_TRUE(state_.IsEmpty());

  ASSERT_NO_FATAL_FAILURE(PropagateForward(kReadEax10));
  EXPECT_TRUE(state_.Contains(assm::eax, 10));
  ASSERT_NO_FATAL_FAILURE(PropagateForward(kRet));
  EXPECT_TRUE(state_.IsEmpty());
}

TEST_F(MemoryAccessAnalysisTest, UnknownInstruction) {
  // Ensure unknown instructions are processed correctly.
  ASSERT_NO_FATAL_FAILURE(PropagateForward(kReadEax10));
  EXPECT_TRUE(state_.Contains(assm::eax, 10));
  ASSERT_NO_FATAL_FAILURE(PropagateForward(kRdtsc));
  EXPECT_TRUE(state_.IsEmpty());
}

TEST_F(MemoryAccessAnalysisTest, Analyze) {
  BasicBlockSubGraph subgraph;

  BlockDescription* block = subgraph.AddBlockDescription(
      "b1", "b1.obj", BlockGraph::CODE_BLOCK, 7, 2, 42);

  BasicCodeBlock* bb_if = subgraph.AddBasicCodeBlock("if");
  BasicCodeBlock* bb_true = subgraph.AddBasicCodeBlock("true");
  BasicCodeBlock* bb_false = subgraph.AddBasicCodeBlock("false");
  BasicCodeBlock* bb_end = subgraph.AddBasicCodeBlock("end");

  ASSERT_TRUE(bb_if != NULL);
  ASSERT_TRUE(bb_true != NULL);
  ASSERT_TRUE(bb_false != NULL);
  ASSERT_TRUE(bb_end != NULL);

  block->basic_block_order.push_back(bb_if);
  block->basic_block_order.push_back(bb_true);
  block->basic_block_order.push_back(bb_end);
  block->basic_block_order.push_back(bb_false);

  AddSuccessorBetween(Successor::kConditionEqual, bb_if, bb_true);
  AddSuccessorBetween(Successor::kConditionNotEqual, bb_if, bb_false);
  AddSuccessorBetween(Successor::kConditionTrue, bb_true, bb_end);
  AddSuccessorBetween(Successor::kConditionTrue, bb_false, bb_end);

  BasicBlockAssembler asm_if(bb_if->instructions().end(),
                             &bb_if->instructions());
  asm_if.mov(assm::ecx, Operand(assm::eax, Displacement(1, assm::kSize32Bit)));
  asm_if.mov(assm::edx,
             Operand(assm::ecx, Displacement(12, assm::kSize32Bit)));
  asm_if.mov(assm::edx,
             Operand(assm::eax, Displacement(42, assm::kSize32Bit)));

  BasicBlockAssembler asm_true(bb_true->instructions().end(),
                               &bb_true->instructions());
  asm_true.mov(assm::ecx,
               Operand(assm::eax, Displacement(1, assm::kSize32Bit)));
  asm_true.mov(assm::edx,
               Operand(assm::eax, Displacement(12, assm::kSize32Bit)));
  asm_true.mov(assm::ecx,
               Operand(assm::eax, Displacement(24, assm::kSize32Bit)));

  BasicBlockAssembler asm_false(bb_false->instructions().end(),
                                &bb_false->instructions());
  asm_false.mov(assm::ecx,
                Operand(assm::eax, Displacement(24, assm::kSize32Bit)));
  asm_false.mov(assm::edx,
                Operand(assm::eax, Displacement(48, assm::kSize32Bit)));

  // Analyze the flow graph.
  memory_access_.Analyze(&subgraph);

  // State of first basic block is empty.
  GetStateAtEntryOf(bb_if, &state_);
  EXPECT_TRUE(state_.IsEmpty());

  // Get entry state of bb_true.
  GetStateAtEntryOf(bb_true, &state_);
  EXPECT_TRUE(state_.Contains(assm::eax, 1));
  EXPECT_TRUE(state_.Contains(assm::ecx, 12));
  EXPECT_TRUE(state_.Contains(assm::eax, 42));

  // Get entry state of bb_false.
  GetStateAtEntryOf(bb_false, &state_);
  EXPECT_TRUE(state_.Contains(assm::eax, 1));
  EXPECT_TRUE(state_.Contains(assm::ecx, 12));
  EXPECT_TRUE(state_.Contains(assm::eax, 42));

  // Get entry state of bb_end. Intersection of bb_true and bb_false.
  GetStateAtEntryOf(bb_end, &state_);
  EXPECT_TRUE(state_.Contains(assm::eax, 1));
  EXPECT_FALSE(state_.Contains(assm::eax, 12));
  EXPECT_FALSE(state_.Contains(assm::ecx, 12));
  EXPECT_TRUE(state_.Contains(assm::eax, 24));
  EXPECT_TRUE(state_.Contains(assm::eax, 42));
}

TEST_F(MemoryAccessAnalysisTest, AnalyzeWithData) {
  BasicBlockSubGraph subgraph;
  const uint8_t raw_data[] = {0, 1, 2, 3, 4};
  const size_t raw_data_len = ARRAYSIZE(raw_data);

  BlockDescription* block = subgraph.AddBlockDescription(
      "b1", "b1.obj", BlockGraph::CODE_BLOCK, 7, 2, 42);

  BasicCodeBlock* bb = subgraph.AddBasicCodeBlock("bb");
  BasicDataBlock* data =
      subgraph.AddBasicDataBlock("data", raw_data_len, &raw_data[0]);

  block->basic_block_order.push_back(bb);
  block->basic_block_order.push_back(data);

  BasicBlockAssembler asm_bb(bb->instructions().end(), &bb->instructions());
  asm_bb.ret();

  // Analyze the flow graph.
  memory_access_.Analyze(&subgraph);

  // Expect empty state.
  GetStateAtEntryOf(bb, &state_);
  EXPECT_TRUE(state_.IsEmpty());

  GetStateAtEntryOf(data, &state_);
  EXPECT_TRUE(state_.IsEmpty());
}

}  // namespace analysis
}  // namespace block_graph
