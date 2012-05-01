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

#include "syzygy/core/assembler.h"

#include <vector>
#include "gtest/gtest.h"

namespace core {

// using testing::StrictMock;
// using testing::_;

namespace {

class TestSerializer : public core::AssemblerImpl::InstructionSerializer {
 public:
  TestSerializer () {
  }

  virtual void AppendInstruction(uint32 location,
                                 const uint8* bytes,
                                 size_t num_bytes,
                                 const uint32 *ref_locations,
                                 const void* const* refs,
                                 size_t num_refs) {
    code.insert(code.end(), bytes, bytes + num_bytes);
  }

  std::vector<uint8> code;
};

class AssemblerTest : public testing::Test {
 public:
  AssemblerTest() : asm_(0, &serializer_) {
  }

  TestSerializer serializer_;
  AssemblerImpl asm_;
};

#define EXPECT_BYTES(...) \
do { \
  uint8 data[] = { __VA_ARGS__ }; \
  ASSERT_EQ(arraysize(data), serializer_.code.size()); \
  EXPECT_EQ(0, memcmp(data, &serializer_.code.at(0), arraysize(data))); \
  serializer_.code.clear(); \
} while (0)

}  // namespace

TEST_F(AssemblerTest, Registers) {
  EXPECT_EQ(kRegisterEax, eax.code());
  EXPECT_EQ(kRegisterEcx, ecx.code());
  EXPECT_EQ(kRegisterEdx, edx.code());
  EXPECT_EQ(kRegisterEbx, ebx.code());
  EXPECT_EQ(kRegisterEsp, esp.code());
  EXPECT_EQ(kRegisterEbp, ebp.code());
  EXPECT_EQ(kRegisterEsi, esi.code());
  EXPECT_EQ(kRegisterEdi, edi.code());
}

TEST_F(AssemblerTest, ValueImpl) {
  {
    ValueImpl imm1;

    EXPECT_EQ(0, imm1.value());
    EXPECT_EQ(NULL, imm1.reference());
    EXPECT_EQ(kSizeNone, imm1.size());
  }

  {
    ValueImpl imm2(0xCAFEBABE, kSize32Bit);

    EXPECT_EQ(0xCAFEBABE, imm2.value());
    EXPECT_EQ(NULL, imm2.reference());
    EXPECT_EQ(kSize32Bit, imm2.size());
  }

  {
    int ref2 = 0;
    ValueImpl imm3(0xCAFEBABE, kSize32Bit, &ref2);

    EXPECT_EQ(0xCAFEBABE, imm3.value());
    EXPECT_EQ(&ref2, imm3.reference());
    EXPECT_EQ(kSize32Bit, imm3.size());
  }
}

TEST_F(AssemblerTest, OperandImpl) {
  {
    OperandImpl op1(edi);
    EXPECT_EQ(kRegisterEdi, op1.base());
    EXPECT_EQ(kRegisterNone, op1.index());
    EXPECT_EQ(kTimes1, op1.scale());
    EXPECT_EQ(0, op1.displacement().value());
    EXPECT_EQ(NULL, op1.displacement().reference());
    EXPECT_EQ(kSizeNone, op1.displacement().size());
  }

  {
    int ref2 = 0;
    OperandImpl op2(ecx, DisplacementImpl(0xCAFEBABE, kSize32Bit, &ref2));
    EXPECT_EQ(kRegisterEcx, op2.base());
    EXPECT_EQ(kRegisterNone, op2.index());
    EXPECT_EQ(kTimes1, op2.scale());
    EXPECT_EQ(0xCAFEBABE, op2.displacement().value());
    EXPECT_EQ(&ref2, op2.displacement().reference());
    EXPECT_EQ(kSize32Bit, op2.displacement().size());
  }

  {
    int ref3 = 0;
    OperandImpl op3(DisplacementImpl(0xCAFEBABE, kSize32Bit, &ref3));
    EXPECT_EQ(kRegisterNone, op3.base());
    EXPECT_EQ(kRegisterNone, op3.index());
    EXPECT_EQ(kTimes1, op3.scale());
    EXPECT_EQ(0xCAFEBABE, op3.displacement().value());
    EXPECT_EQ(&ref3, op3.displacement().reference());
    EXPECT_EQ(kSize32Bit, op3.displacement().size());
  }

  {
    int ref4 = 0;
    OperandImpl
        op4(ebp, ecx, kTimes2, DisplacementImpl(0xCA, kSize8Bit, &ref4));
    EXPECT_EQ(kRegisterEbp, op4.base());
    EXPECT_EQ(kRegisterEcx, op4.index());
    EXPECT_EQ(kTimes2, op4.scale());
    EXPECT_EQ(0xCA, op4.displacement().value());
    EXPECT_EQ(&ref4, op4.displacement().reference());
    EXPECT_EQ(kSize8Bit, op4.displacement().size());
  }
}

TEST_F(AssemblerTest, MovImmediate) {
  // Immediate moves.
  asm_.mov(eax, ImmediateImpl(0xCAFEBABE, kSize32Bit));
  EXPECT_BYTES(0xB8, 0xBE, 0xBA, 0xFE, 0xCA);
  asm_.mov(ebx, ImmediateImpl(0xCAFEBABE, kSize32Bit));
  EXPECT_BYTES(0xBB, 0xBE, 0xBA, 0xFE, 0xCA);
}

TEST_F(AssemblerTest, MovRegisterToRegister) {
  // Register to register, one case each for source and dst.
  asm_.mov(eax, ebx);
  EXPECT_BYTES(0x8B, 0xC3);
  asm_.mov(ecx, eax);
  EXPECT_BYTES(0x8B, 0xC8);
  asm_.mov(ebx, eax);
  EXPECT_BYTES(0x8B, 0xD8);
  asm_.mov(edx, eax);
  EXPECT_BYTES(0x8B, 0xD0);
  asm_.mov(esp, eax);
  EXPECT_BYTES(0x8B, 0xE0);
  asm_.mov(ebp, eax);
  EXPECT_BYTES(0x8B, 0xE8);
  asm_.mov(esi, eax);
  EXPECT_BYTES(0x8B, 0xF0);
  asm_.mov(edi, eax);
  EXPECT_BYTES(0x8B, 0xF8);

  asm_.mov(ebx, eax);
  EXPECT_BYTES(0x8B, 0xD8);
  asm_.mov(eax, ecx);
  EXPECT_BYTES(0x8B, 0xC1);
  asm_.mov(eax, ebx);
  EXPECT_BYTES(0x8B, 0xC3);
  asm_.mov(eax, edx);
  EXPECT_BYTES(0x8B, 0xC2);
  asm_.mov(eax, esp);
  EXPECT_BYTES(0x8B, 0xC4);
  asm_.mov(eax, ebp);
  EXPECT_BYTES(0x8B, 0xC5);
  asm_.mov(eax, esi);
  EXPECT_BYTES(0x8B, 0xC6);
  asm_.mov(eax, edi);
  EXPECT_BYTES(0x8B, 0xC7);
}

TEST_F(AssemblerTest, MovRegisterIndirect) {
  // Indirect register only source modes.
  asm_.mov(ebx, OperandImpl(eax));
  EXPECT_BYTES(0x8B, 0x18);
  asm_.mov(eax, OperandImpl(ecx));
  EXPECT_BYTES(0x8B, 0x01);
  asm_.mov(edx, OperandImpl(ebx));
  EXPECT_BYTES(0x8B, 0x13);
  asm_.mov(ecx, OperandImpl(edx));
  EXPECT_BYTES(0x8B, 0x0A);

  // Note that EBP is a special case that always requires a displacement.
  asm_.mov(ebx, OperandImpl(ebp));
  EXPECT_BYTES(0x8B, 0x5D, 0x00);

  // Note that ESP is a special case that always requires a SIB byte.
  asm_.mov(ecx, OperandImpl(esp));
  EXPECT_BYTES(0x8B, 0x0C, 0x24);

  asm_.mov(ebx, OperandImpl(esi));
  EXPECT_BYTES(0x8B, 0x1E);
  asm_.mov(eax, OperandImpl(edi));
  EXPECT_BYTES(0x8B, 0x07);

  // Indirect register destination modes.
  asm_.mov(OperandImpl(eax), ebx);
  EXPECT_BYTES(0x89, 0x18);
  asm_.mov(OperandImpl(ecx), eax);
  EXPECT_BYTES(0x89, 0x01);
  asm_.mov(OperandImpl(ebx), edx);
  EXPECT_BYTES(0x89, 0x13);
  asm_.mov(OperandImpl(edx), ecx);
  EXPECT_BYTES(0x89, 0x0A);

  // Note that EBP is a special case that always requires a displacement.
  asm_.mov(OperandImpl(ebp), ebx);
  EXPECT_BYTES(0x89, 0x5D, 0x00);

  // Note that ESP is a special case that always requires a SIB byte.
  asm_.mov(OperandImpl(esp), ecx);
  EXPECT_BYTES(0x89, 0x0C, 0x24);

  asm_.mov(OperandImpl(esi), ebx);
  EXPECT_BYTES(0x89, 0x1E);
  asm_.mov(OperandImpl(edi), eax);
  EXPECT_BYTES(0x89, 0x07);
}

TEST_F(AssemblerTest, MovRegisterDisplacementIndirect) {
  // Register & displacement source modes.
  DisplacementImpl cafebabe(0xCAFEBABE, kSize32Bit, NULL);

  asm_.mov(ebx, OperandImpl(eax, cafebabe));
  EXPECT_BYTES(0x8B, 0x98, 0xBE, 0xBA, 0xFE, 0xCA);
  asm_.mov(eax, OperandImpl(ecx, cafebabe));
  EXPECT_BYTES(0x8B, 0x81, 0xBE, 0xBA, 0xFE, 0xCA);
  asm_.mov(eax, OperandImpl(ebx, cafebabe));
  EXPECT_BYTES(0x8B, 0x83, 0xBE, 0xBA, 0xFE, 0xCA);
  asm_.mov(eax, OperandImpl(edx, cafebabe));
  EXPECT_BYTES(0x8B, 0x82, 0xBE, 0xBA, 0xFE, 0xCA);
  asm_.mov(eax, OperandImpl(ebp, cafebabe));
  EXPECT_BYTES(0x8B, 0x85, 0xBE, 0xBA, 0xFE, 0xCA);

  // ESP requires a SIB byte and has a longer encoding.
  asm_.mov(eax, OperandImpl(esp, cafebabe));
  EXPECT_BYTES(0x8B, 0x84, 0x24, 0xBE, 0xBA, 0xFE, 0xCA);

  asm_.mov(eax, OperandImpl(esi, cafebabe));
  EXPECT_BYTES(0x8B, 0x86, 0xBE, 0xBA, 0xFE, 0xCA);
  asm_.mov(eax, OperandImpl(edi, cafebabe));
  EXPECT_BYTES(0x8B, 0x87, 0xBE, 0xBA, 0xFE, 0xCA);

  // And destination modes.
  asm_.mov(OperandImpl(eax, cafebabe), ebx);
  EXPECT_BYTES(0x89, 0x98, 0xBE, 0xBA, 0xFE, 0xCA);
  asm_.mov(OperandImpl(ecx, cafebabe), eax);
  EXPECT_BYTES(0x89, 0x81, 0xBE, 0xBA, 0xFE, 0xCA);
  asm_.mov(OperandImpl(ebx, cafebabe), eax);
  EXPECT_BYTES(0x89, 0x83, 0xBE, 0xBA, 0xFE, 0xCA);
  asm_.mov(OperandImpl(edx, cafebabe), eax);
  EXPECT_BYTES(0x89, 0x82, 0xBE, 0xBA, 0xFE, 0xCA);
  asm_.mov(OperandImpl(ebp, cafebabe), eax);
  EXPECT_BYTES(0x89, 0x85, 0xBE, 0xBA, 0xFE, 0xCA);

  // ESP requires a SIB byte and has a longer encoding.
  asm_.mov(OperandImpl(esp, cafebabe), eax);
  EXPECT_BYTES(0x89, 0x84, 0x24, 0xBE, 0xBA, 0xFE, 0xCA);

  asm_.mov(OperandImpl(esi, cafebabe), eax);
  EXPECT_BYTES(0x89, 0x86, 0xBE, 0xBA, 0xFE, 0xCA);
  asm_.mov(OperandImpl(edi, cafebabe), eax);
  EXPECT_BYTES(0x89, 0x87, 0xBE, 0xBA, 0xFE, 0xCA);

  // Test a sampling of 8 bit displacements.
  DisplacementImpl ca(0xCA, kSize8Bit, NULL);

  // Source.
  asm_.mov(ebx, OperandImpl(eax, ca));
  EXPECT_BYTES(0x8B, 0x58, 0xCA);

  // ESP requires a SIB byte and has a longer encoding.
  asm_.mov(eax, OperandImpl(esp, ca));
  EXPECT_BYTES(0x8B, 0x44, 0x24, 0xCA);

  // And destination modes.
  asm_.mov(OperandImpl(eax, ca), ebx);
  EXPECT_BYTES(0x89, 0x58, 0xCA);

  // ESP requires a SIB byte and has a longer encoding.
  asm_.mov(OperandImpl(esp, ca), eax);
  EXPECT_BYTES(0x89, 0x44, 0x24, 0xCA);
}

TEST_F(AssemblerTest, MovDisplacementIndirect) {
  // Displacement-only mode.
  DisplacementImpl cafebabe(0xCAFEBABE, kSize32Bit, NULL);

  // Source, note EAX has a shortcut encoding.
  asm_.mov(eax, OperandImpl(cafebabe));
  EXPECT_BYTES(0xA1, 0xBE, 0xBA, 0xFE, 0xCA);
  asm_.mov(ecx, OperandImpl(cafebabe));
  EXPECT_BYTES(0x8B, 0x0D, 0xBE, 0xBA, 0xFE, 0xCA);

  // Destination, again EAX is special.
  asm_.mov(OperandImpl(cafebabe), eax);
  EXPECT_BYTES(0xA3, 0xBE, 0xBA, 0xFE, 0xCA);

  asm_.mov(OperandImpl(cafebabe), ecx);
  EXPECT_BYTES(0x89, 0x0D, 0xBE, 0xBA, 0xFE, 0xCA);
}

TEST_F(AssemblerTest, MovRegisterDisplacementScaleIndirect) {
  // There are 8 base * 7 index * 4 scales = 224 combinations.
  // We don't test all of them, but rather cycle through each of base,
  // index and scale individually.
  DisplacementImpl cafebabe(0xCAFEBABE, kSize32Bit, NULL);

  // Source mode, base register.
  asm_.mov(edx, OperandImpl(ecx, eax, kTimes4, cafebabe));
  EXPECT_BYTES(0x8B, 0x94, 0x81, 0xBE, 0xBA, 0xFE, 0xCA);
  asm_.mov(eax, OperandImpl(ecx, eax, kTimes4, cafebabe));
  EXPECT_BYTES(0x8B, 0x84, 0x81, 0xBE, 0xBA, 0xFE, 0xCA);
  asm_.mov(eax, OperandImpl(edx, eax, kTimes4, cafebabe));
  EXPECT_BYTES(0x8B, 0x84, 0x82, 0xBE, 0xBA, 0xFE, 0xCA);
  asm_.mov(eax, OperandImpl(ebx, eax, kTimes4, cafebabe));
  EXPECT_BYTES(0x8B, 0x84, 0x83, 0xBE, 0xBA, 0xFE, 0xCA);
  asm_.mov(eax, OperandImpl(esp, eax, kTimes4, cafebabe));
  EXPECT_BYTES(0x8B, 0x84, 0x84, 0xBE, 0xBA, 0xFE, 0xCA);
  asm_.mov(eax, OperandImpl(ebp, eax, kTimes4, cafebabe));
  EXPECT_BYTES(0x8B, 0x84, 0x85, 0xBE, 0xBA, 0xFE, 0xCA);
  asm_.mov(eax, OperandImpl(esi, eax, kTimes4, cafebabe));
  EXPECT_BYTES(0x8B, 0x84, 0x86, 0xBE, 0xBA, 0xFE, 0xCA);
  asm_.mov(eax, OperandImpl(edi, eax, kTimes4, cafebabe));
  EXPECT_BYTES(0x8B, 0x84, 0x87, 0xBE, 0xBA, 0xFE, 0xCA);

  // Source mode, index register.
  asm_.mov(ebx, OperandImpl(ecx, eax, kTimes4, cafebabe));
  EXPECT_BYTES(0x8B, 0x9C, 0x81, 0xBE, 0xBA, 0xFE, 0xCA);
  asm_.mov(eax, OperandImpl(eax, ecx, kTimes4, cafebabe));
  EXPECT_BYTES(0x8B, 0x84, 0x88, 0xBE, 0xBA, 0xFE, 0xCA);
  asm_.mov(eax, OperandImpl(eax, edx, kTimes4, cafebabe));
  EXPECT_BYTES(0x8B, 0x84, 0x90, 0xBE, 0xBA, 0xFE, 0xCA);
  asm_.mov(eax, OperandImpl(eax, ebx, kTimes4, cafebabe));
  EXPECT_BYTES(0x8B, 0x84, 0x98, 0xBE, 0xBA, 0xFE, 0xCA);
  asm_.mov(eax, OperandImpl(eax, ebp, kTimes4, cafebabe));
  EXPECT_BYTES(0x8B, 0x84, 0xA8, 0xBE, 0xBA, 0xFE, 0xCA);
  asm_.mov(eax, OperandImpl(eax, esi, kTimes4, cafebabe));
  EXPECT_BYTES(0x8B, 0x84, 0xB0, 0xBE, 0xBA, 0xFE, 0xCA);
  asm_.mov(eax, OperandImpl(eax, edi, kTimes4, cafebabe));
  EXPECT_BYTES(0x8B, 0x84, 0xB8, 0xBE, 0xBA, 0xFE, 0xCA);

  // Source mode, Scale.
  asm_.mov(ebx, OperandImpl(ecx, eax, kTimes1, cafebabe));
  EXPECT_BYTES(0x8B, 0x9C, 0x01, 0xBE, 0xBA, 0xFE, 0xCA);
  asm_.mov(ebx, OperandImpl(ecx, eax, kTimes2, cafebabe));
  EXPECT_BYTES(0x8B, 0x9C, 0x41, 0xBE, 0xBA, 0xFE, 0xCA);
  asm_.mov(ebx, OperandImpl(ecx, eax, kTimes4, cafebabe));
  EXPECT_BYTES(0x8B, 0x9C, 0x81, 0xBE, 0xBA, 0xFE, 0xCA);
  asm_.mov(ebx, OperandImpl(ecx, eax, kTimes8, cafebabe));
  EXPECT_BYTES(0x8B, 0x9C, 0xC1, 0xBE, 0xBA, 0xFE, 0xCA);

  // Destination mode, base register.
  asm_.mov(OperandImpl(eax, eax, kTimes4, cafebabe), ecx);
  EXPECT_BYTES(0x89, 0x8C, 0x80, 0xBE, 0xBA, 0xFE, 0xCA);
  asm_.mov(OperandImpl(ecx, eax, kTimes4, cafebabe), eax);
  EXPECT_BYTES(0x89, 0x84, 0x81, 0xBE, 0xBA, 0xFE, 0xCA);
  asm_.mov(OperandImpl(edx, eax, kTimes4, cafebabe), eax);
  EXPECT_BYTES(0x89, 0x84, 0x82, 0xBE, 0xBA, 0xFE, 0xCA);
  asm_.mov(OperandImpl(ebx, eax, kTimes4, cafebabe), eax);
  EXPECT_BYTES(0x89, 0x84, 0x83, 0xBE, 0xBA, 0xFE, 0xCA);
  asm_.mov(OperandImpl(esp, eax, kTimes4, cafebabe), eax);
  EXPECT_BYTES(0x89, 0x84, 0x84, 0xBE, 0xBA, 0xFE, 0xCA);
  asm_.mov(OperandImpl(ebp, eax, kTimes4, cafebabe), eax);
  EXPECT_BYTES(0x89, 0x84, 0x85, 0xBE, 0xBA, 0xFE, 0xCA);
  asm_.mov(OperandImpl(esi, eax, kTimes4, cafebabe), eax);
  EXPECT_BYTES(0x89, 0x84, 0x86, 0xBE, 0xBA, 0xFE, 0xCA);
  asm_.mov(OperandImpl(edi, eax, kTimes4, cafebabe), eax);
  EXPECT_BYTES(0x89, 0x84, 0x87, 0xBE, 0xBA, 0xFE, 0xCA);

  // Destination mode, index register.
  asm_.mov(OperandImpl(ecx, eax, kTimes4, cafebabe), ebx);
  EXPECT_BYTES(0x89, 0x9C, 0x81, 0xBE, 0xBA, 0xFE, 0xCA);
  asm_.mov(OperandImpl(eax, ecx, kTimes4, cafebabe), eax);
  EXPECT_BYTES(0x89, 0x84, 0x88, 0xBE, 0xBA, 0xFE, 0xCA);
  asm_.mov(OperandImpl(eax, edx, kTimes4, cafebabe), eax);
  EXPECT_BYTES(0x89, 0x84, 0x90, 0xBE, 0xBA, 0xFE, 0xCA);
  asm_.mov(OperandImpl(eax, ebx, kTimes4, cafebabe), eax);
  EXPECT_BYTES(0x89, 0x84, 0x98, 0xBE, 0xBA, 0xFE, 0xCA);
  asm_.mov(OperandImpl(eax, ebp, kTimes4, cafebabe), eax);
  EXPECT_BYTES(0x89, 0x84, 0xA8, 0xBE, 0xBA, 0xFE, 0xCA);
  asm_.mov(OperandImpl(eax, esi, kTimes4, cafebabe), eax);
  EXPECT_BYTES(0x89, 0x84, 0xB0, 0xBE, 0xBA, 0xFE, 0xCA);
  asm_.mov(OperandImpl(eax, edi, kTimes4, cafebabe), eax);
  EXPECT_BYTES(0x89, 0x84, 0xB8, 0xBE, 0xBA, 0xFE, 0xCA);

  // Destination mode, Scale.
  asm_.mov(OperandImpl(ecx, eax, kTimes1, cafebabe), ebx);
  EXPECT_BYTES(0x89, 0x9C, 0x01, 0xBE, 0xBA, 0xFE, 0xCA);
  asm_.mov(OperandImpl(ecx, eax, kTimes2, cafebabe), ebx);
  EXPECT_BYTES(0x89, 0x9C, 0x41, 0xBE, 0xBA, 0xFE, 0xCA);
  asm_.mov(OperandImpl(ecx, eax, kTimes4, cafebabe), ebx);
  EXPECT_BYTES(0x89, 0x9C, 0x81, 0xBE, 0xBA, 0xFE, 0xCA);
  asm_.mov(OperandImpl(ecx, eax, kTimes8, cafebabe), ebx);
  EXPECT_BYTES(0x89, 0x9C, 0xC1, 0xBE, 0xBA, 0xFE, 0xCA);
}

}  // namespace core
