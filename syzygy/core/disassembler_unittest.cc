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
// Implementation of disassembler.
#include "syzygy/core/disassembler.h"

#include <memory>
#include <vector>

#include "base/bind.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

using testing::_;
using testing::Invoke;
using testing::Return;

extern "C" {

// functions and labels exposed from our .asm test stub.
extern int assembly_func();
extern int internal_label();
extern int assembly_func_end();

extern int assembly_switch();
extern int case_0();
extern int case_1();
extern int case_default();
extern int jump_table();
extern int lookup_table();
extern int assembly_switch_end();

// Functions invoked or referred by the .asm test stub.
int func1() {
  return 1;
}

int func2() {
  return 2;
}

int func3() {
  return 3;
}

int func4() {
  return 4;
}

}  // extern "C"

namespace core {

class DisassemblerTest: public testing::Test {
 public:
  virtual void SetUp() {
    on_instruction_ = base::Bind(&DisassemblerTest::OnInstruction,
                                 base::Unretained(this));
  }

  MOCK_METHOD2(OnInstruction,
               Disassembler::CallbackDirective(const Disassembler&,
                                               const _DInst&));

  static AbsoluteAddress AddressOf(const void* ptr) {
    return AbsoluteAddress(reinterpret_cast<size_t>(ptr));
  }

  static const uint8_t* PointerTo(const void* ptr) {
    return reinterpret_cast<const uint8_t*>(ptr);
  }

  Disassembler::CallbackDirective RecordFunctionEncounter(
      const Disassembler& disasm, const _DInst& inst) {
    switch (META_GET_FC(inst.meta)) {
      case FC_CALL:
      case FC_UNC_BRANCH:
        EXPECT_EQ(O_PC, inst.ops[0].type);
        if (inst.ops[0].size == 8) {
          EXPECT_EQ(2, inst.size);
        } else {
          EXPECT_EQ(32, inst.ops[0].size);
          EXPECT_EQ(5, inst.size);
          functions_.push_back(
              AbsoluteAddress(
                  static_cast<size_t>(inst.addr + inst.size + inst.imm.addr)));
        }
        break;
      default:
        break;
    }
    return Disassembler::kDirectiveContinue;
  }

 protected:
  std::vector<AbsoluteAddress> functions_;

  Disassembler::InstructionCallback on_instruction_;
};

TEST_F(DisassemblerTest, Terminate) {
  Disassembler disasm(PointerTo(&assembly_func),
                      PointerTo(&assembly_func_end) - PointerTo(&assembly_func),
                      AddressOf(&assembly_func),
                      on_instruction_);
  ASSERT_TRUE(disasm.Unvisited(AddressOf(&assembly_func)));

  // Terminate the walk on first visit.
  EXPECT_CALL(*this, OnInstruction(_, _)).
      WillRepeatedly(Return(Disassembler::kDirectiveTerminateWalk));

  ASSERT_EQ(Disassembler::kWalkTerminated, disasm.Walk());
}

TEST_F(DisassemblerTest, DisassemblePartial) {
  Disassembler disasm(PointerTo(&assembly_func),
                      PointerTo(&assembly_func_end) - PointerTo(&assembly_func),
                      AddressOf(&assembly_func),
                      on_instruction_);
  ASSERT_TRUE(disasm.Unvisited(AddressOf(&assembly_func)));

  // We should hit 6 instructions.
  EXPECT_CALL(*this, OnInstruction(_, _)).Times(6).
      WillRepeatedly(Return(Disassembler::kDirectiveContinue));

  ASSERT_EQ(Disassembler::kWalkSuccess, disasm.Walk());
  // We should have disassembled everything save one call to func3 and
  // the jump/lookup tables.
  ASSERT_EQ(PointerTo(&assembly_func_end) - PointerTo(&assembly_func) - 5,
      disasm.disassembled_bytes());
}

TEST_F(DisassemblerTest, DisassembleFull) {
  Disassembler disasm(PointerTo(&assembly_func),
                      PointerTo(&assembly_func_end) - PointerTo(&assembly_func),
                      AddressOf(&assembly_func),
                      on_instruction_);
  ASSERT_TRUE(disasm.Unvisited(AddressOf(&assembly_func)));
  // Mark the internal label as well.
  ASSERT_TRUE(disasm.Unvisited(AddressOf(&internal_label)));

  // We should hit 7 instructions.
  EXPECT_CALL(*this, OnInstruction(_, _)).Times(7).
      WillRepeatedly(Return(Disassembler::kDirectiveContinue));

  ASSERT_EQ(Disassembler::kWalkSuccess, disasm.Walk());

  // We should have disassembled everything.
  ASSERT_EQ(PointerTo(&assembly_func_end) - PointerTo(&assembly_func),
      disasm.disassembled_bytes());
}

TEST_F(DisassemblerTest, EncounterFunctions) {
  Disassembler disasm(PointerTo(&assembly_func),
                      PointerTo(&assembly_func_end) - PointerTo(&assembly_func),
                      AddressOf(&assembly_func),
                      on_instruction_);
  ASSERT_TRUE(disasm.Unvisited(AddressOf(&assembly_func)));
  // Mark the internal label as well.
  ASSERT_TRUE(disasm.Unvisited(AddressOf(&internal_label)));

  // Record the functions we encounter along the way.
  EXPECT_CALL(*this, OnInstruction(_, _)).
      WillRepeatedly(Invoke(this,
                             &DisassemblerTest::RecordFunctionEncounter));

  ASSERT_EQ(Disassembler::kWalkSuccess, disasm.Walk());

  std::vector<AbsoluteAddress> expected;
  expected.push_back(AddressOf(func1));
  expected.push_back(AddressOf(func2));
  expected.push_back(AddressOf(func3));
  expected.push_back(AddressOf(func4));

  EXPECT_THAT(functions_, testing::ContainerEq(expected));
}

TEST_F(DisassemblerTest, StopsAtTerminateNoReturnFunctionCall) {
  Disassembler disasm(
      PointerTo(&assembly_switch),
      PointerTo(&assembly_switch_end) - PointerTo(&assembly_switch),
      AddressOf(&assembly_switch), on_instruction_);

  // Mark the entry of the case that calls a non-returning function
  ASSERT_TRUE(disasm.Unvisited(AddressOf(&case_default)));

  // We expect to hit all the instructions in the case
  // "case_default" from disassembler_test_code.asm.
  EXPECT_CALL(*this, OnInstruction(_, _))
      .Times(2)
      .WillOnce(Return(Disassembler::kDirectiveContinue))
      .WillOnce(Return(Disassembler::kDirectiveTerminatePath));

  // We expect a complete walk from this, as there are no branches to
  // chase down
  ASSERT_EQ(Disassembler::kWalkSuccess, disasm.Walk());
}

}  // namespace core
