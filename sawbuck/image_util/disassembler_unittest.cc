// Copyright 2010 Google Inc.
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
#include "sawbuck/image_util/disassembler.h"
#include "base/scoped_ptr.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include <vector>

using testing::_;
using testing::Invoke;
using testing::SetArgumentPointee;

extern "C" {

// functions and labels exposed from our .asm test stub.
extern int assembly_start();
extern int assembly_func();
extern int internal_label();
extern int assembly_end();

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

namespace image_util {

class DisassemblerTest: public testing::Test {
 public:
  virtual void SetUp() {
    on_instruction_.reset(NewCallback(this, &DisassemblerTest::OnInstruction));
  }

  MOCK_METHOD3(OnInstruction, void(const Disassembler&, const _DInst&, bool*));

  static RelativeAddress AddressOf(const void* ptr) {
    return RelativeAddress(reinterpret_cast<size_t>(ptr));
  }

  void RecordFunctionEncounter(const Disassembler& disasm,
                               const _DInst& inst,
                               bool* continue_walk) {
    switch (META_GET_FC(inst.meta)) {
      case FC_CALL:
      case FC_BRANCH:
        ASSERT_EQ(O_PC, inst.ops[0].type);
        if (inst.ops[0].size == 8) {
          ASSERT_EQ(2, inst.size);
        } else {
          ASSERT_EQ(32, inst.ops[0].size);
          ASSERT_EQ(5, inst.size);
          functions_.push_back(
              RelativeAddress(
                  static_cast<size_t>(inst.addr + inst.size + inst.imm.addr)));
        }
        break;
      default:
        break;
    }
  }

 protected:
  static uint8 const *const kBegin;
  static uint8 const *const kEnd;
  static uint8 const *const kFunc;
  static uint8 const *const kLabel;
  static const RelativeAddress kStartAddress;

  std::vector<RelativeAddress> functions_;

  scoped_ptr<Disassembler::InstructionCallback> on_instruction_;
};

uint8 const *const DisassemblerTest::kBegin =
    reinterpret_cast<const uint8*>(&assembly_start);
uint8 const *const DisassemblerTest::kEnd =
    reinterpret_cast<const uint8*>(assembly_end);
uint8 const *const DisassemblerTest::kFunc =
    reinterpret_cast<const uint8*>(&assembly_func);
uint8 const *const DisassemblerTest::kLabel =
    reinterpret_cast<const uint8*>(&internal_label);
const RelativeAddress DisassemblerTest::kStartAddress(AddressOf(kBegin));

TEST_F(DisassemblerTest, Terminate) {
  Disassembler disasm(kBegin,
                      kEnd - kBegin,
                      kStartAddress,
                      on_instruction_.get());
  ASSERT_TRUE(disasm.Unvisited(kStartAddress));

  // Terminate the walk on first visit.
  EXPECT_CALL(*this, OnInstruction(_, _, _))
      .WillRepeatedly(SetArgumentPointee<2>(false));

  ASSERT_EQ(Disassembler::kWalkTerminated, disasm.Walk());
}

TEST_F(DisassemblerTest, DisassemblePartial) {
  Disassembler disasm(kBegin,
                      kEnd - kBegin,
                      kStartAddress,
                      on_instruction_.get());
  ASSERT_TRUE(disasm.Unvisited(kStartAddress));

  // We should hit 6 instructions.
  EXPECT_CALL(*this, OnInstruction(_, _, _)).Times(6);

  ASSERT_EQ(Disassembler::kWalkSuccess, disasm.Walk());
  // We should have disassembled everything save one call to func3.
  ASSERT_EQ(kEnd - kBegin - 5, disasm.disassembled_bytes());
}

TEST_F(DisassemblerTest, DisassembleFull) {
  Disassembler disasm(kBegin,
                      kEnd - kBegin,
                      kStartAddress,
                      on_instruction_.get());
  ASSERT_TRUE(disasm.Unvisited(kStartAddress));
  // Mark the internal label as well.
  ASSERT_TRUE(disasm.Unvisited(AddressOf(kLabel)));

  // We should hit 7 instructions.
  EXPECT_CALL(*this, OnInstruction(_, _, _)).Times(7);

  ASSERT_EQ(Disassembler::kWalkSuccess, disasm.Walk());

  // We should have disassembled everything.
  ASSERT_EQ(kEnd - kBegin, disasm.disassembled_bytes());
}

TEST_F(DisassemblerTest, EnounterFunctions) {
  Disassembler disasm(kBegin,
                      kEnd - kBegin,
                      kStartAddress,
                      on_instruction_.get());
  ASSERT_TRUE(disasm.Unvisited(kStartAddress));
  // Mark the internal label as well.
  ASSERT_TRUE(disasm.Unvisited(AddressOf(kLabel)));

  // Record the functions we encounter along the way.
  EXPECT_CALL(*this, OnInstruction(_, _, _))
      .WillRepeatedly(Invoke(this,
                             &DisassemblerTest::RecordFunctionEncounter));

  ASSERT_EQ(Disassembler::kWalkSuccess, disasm.Walk());

  std::vector<RelativeAddress> expected;
  expected.push_back(AddressOf(func1));
  expected.push_back(AddressOf(func2));
  expected.push_back(AddressOf(func3));
  expected.push_back(AddressOf(func4));

  EXPECT_THAT(functions_, testing::ContainerEq(expected));
}

}  // namespace image_util
