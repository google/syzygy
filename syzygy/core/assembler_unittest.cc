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

#include "syzygy/core/assembler.h"

#include <vector>
#include "gtest/gtest.h"
#include "syzygy/core/disassembler_util.h"

namespace core {

namespace {

class TestSerializer : public core::AssemblerImpl::InstructionSerializer {
 public:
  struct Reference {
    uint32 location;
    const void* ref;
  };

  TestSerializer() {
  }

  virtual void AppendInstruction(uint32 location,
                                 const uint8* bytes,
                                 size_t num_bytes,
                                 const uint32 *ref_locations,
                                 const void* const* refs,
                                 size_t num_refs) {
    for (size_t i = 0; i < num_refs; ++i) {
      Reference ref = { code.size() + ref_locations[i], refs[i] };
      references.push_back(ref);
    }
    code.insert(code.end(), bytes, bytes + num_bytes);
  }

  std::vector<uint8> code;
  std::vector<Reference> references;
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

TEST_F(AssemblerTest, ValueImpl) {
  ValueImpl imm1;
  EXPECT_EQ(0, imm1.value());
  EXPECT_EQ(NULL, imm1.reference());
  EXPECT_EQ(kSizeNone, imm1.size());
  EXPECT_TRUE(imm1 == imm1);

  ValueImpl imm2(0xCAFEBABE, kSize32Bit);
  EXPECT_EQ(0xCAFEBABE, imm2.value());
  EXPECT_EQ(NULL, imm2.reference());
  EXPECT_EQ(kSize32Bit, imm2.size());
  EXPECT_TRUE(imm2 == imm2);
  EXPECT_FALSE(imm2 == imm1);

  int ref2 = 0;
  ValueImpl imm3(0xCAFEBABE, kSize32Bit, &ref2);
  EXPECT_EQ(0xCAFEBABE, imm3.value());
  EXPECT_EQ(&ref2, imm3.reference());
  EXPECT_EQ(kSize32Bit, imm3.size());
  EXPECT_TRUE(imm3 == imm3);
  EXPECT_FALSE(imm3 == imm2);
  EXPECT_FALSE(imm3 == imm1);

  ValueImpl imm4(0xCAFEBABE, kSize32Bit, &ref2);
  EXPECT_TRUE(imm4 == imm3);
}

TEST_F(AssemblerTest, OperandImpl) {
  {
    OperandImpl op(edi);
    EXPECT_EQ(kRegisterEdi, op.base());
    EXPECT_EQ(kRegisterNone, op.index());
    EXPECT_EQ(kTimes1, op.scale());
    EXPECT_EQ(0, op.displacement().value());
    EXPECT_EQ(NULL, op.displacement().reference());
    EXPECT_EQ(kSizeNone, op.displacement().size());
  }

  {
    int ref = 0;
    OperandImpl op(ecx, DisplacementImpl(0xCAFEBABE, kSize32Bit, &ref));
    EXPECT_EQ(kRegisterEcx, op.base());
    EXPECT_EQ(kRegisterNone, op.index());
    EXPECT_EQ(kTimes1, op.scale());
    EXPECT_EQ(0xCAFEBABE, op.displacement().value());
    EXPECT_EQ(&ref, op.displacement().reference());
    EXPECT_EQ(kSize32Bit, op.displacement().size());
  }

  {
    int ref = 0;
    OperandImpl op(DisplacementImpl(0xCAFEBABE, kSize32Bit, &ref));
    EXPECT_EQ(kRegisterNone, op.base());
    EXPECT_EQ(kRegisterNone, op.index());
    EXPECT_EQ(kTimes1, op.scale());
    EXPECT_EQ(0xCAFEBABE, op.displacement().value());
    EXPECT_EQ(&ref, op.displacement().reference());
    EXPECT_EQ(kSize32Bit, op.displacement().size());
  }

  {
    OperandImpl op(ebp, ecx, kTimes8);
    EXPECT_EQ(kRegisterEbp, op.base());
    EXPECT_EQ(kRegisterEcx, op.index());
    EXPECT_EQ(kTimes8, op.scale());
    EXPECT_EQ(0, op.displacement().value());
    EXPECT_EQ(NULL, op.displacement().reference());
    EXPECT_EQ(kSizeNone, op.displacement().size());
  }

  {
    int ref = 0;
    OperandImpl
        op(ebp, ecx, kTimes2, DisplacementImpl(0xCA, kSize8Bit, &ref));
    EXPECT_EQ(kRegisterEbp, op.base());
    EXPECT_EQ(kRegisterEcx, op.index());
    EXPECT_EQ(kTimes2, op.scale());
    EXPECT_EQ(0xCA, op.displacement().value());
    EXPECT_EQ(&ref, op.displacement().reference());
    EXPECT_EQ(kSize8Bit, op.displacement().size());
  }
}

TEST_F(AssemblerTest, Nop) {
  asm_.nop(0);
  EXPECT_TRUE(serializer_.code.empty());

  // NOPs are generated in bunches of instructions of up to 15 bytes in
  // length. We validate that each one of them is in fact a sequence of NOPs.
  for (size_t i = 1; i <= 15; ++i) {
    asm_.nop(i);
    EXPECT_EQ(i, serializer_.code.size());

    // The sequence of bytes should consist of NOP instructions.
    size_t j = 0;
    size_t instruction_count = 0;
    while (j < i) {
      _DInst instruction = {};
      ASSERT_TRUE(DecodeOneInstruction(serializer_.code.data() + j,
                                       i - j,
                                       &instruction));
      ASSERT_TRUE(IsNop(instruction));
      j += instruction.size;
      ++instruction_count;
    }
    // 1 or 2 instructions should be generated.
    ASSERT_LT(0u, instruction_count);
    ASSERT_GE(2u, instruction_count);
    serializer_.code.clear();
  }
}

TEST_F(AssemblerTest, Call) {
  asm_.set_location(0xCAFEBABE);

  // Immediate call.
  asm_.call(ImmediateImpl(0xCAFEBABE, kSize32Bit, NULL));
  EXPECT_BYTES(0xE8, 0xFB, 0xFF, 0xFF, 0xFF);

  // Indirect call - we test only one operand encoding, as the others
  // are well covered in the mov instruction.
  asm_.call(OperandImpl(DisplacementImpl(0xCAFEBABE, kSize32Bit, NULL)));
  EXPECT_BYTES(0xFF, 0x15, 0xBE, 0xBA, 0xFE, 0xCA);
}

TEST_F(AssemblerTest, Jmp) {
  asm_.set_location(0xCAFEBABE);

  // Immediate 8-bit reach jmp.
  asm_.jmp(ImmediateImpl(0xCAFEBABE, kSize8Bit, NULL));
  EXPECT_BYTES(0xEB, 0xFE);

  ASSERT_EQ(1, AssemblerImpl::kShortJumpOpcodeSize);
  ASSERT_EQ(2, AssemblerImpl::kShortJumpSize);

  // Immediate 32-bit reach jmp.
  asm_.jmp(ImmediateImpl(0xCAFEBABE, kSize32Bit, NULL));
  EXPECT_BYTES(0xE9, 0xF9, 0xFF, 0xFF, 0xFF);

  ASSERT_EQ(1, AssemblerImpl::kLongJumpOpcodeSize);
  ASSERT_EQ(5, AssemblerImpl::kLongJumpSize);

  // Indirect jmp - we test only one operand encoding, as the others
  // are well covered in the mov instruction.
  asm_.jmp(OperandImpl(DisplacementImpl(0xCAFEBABE, kSize32Bit, NULL)));
  EXPECT_BYTES(0xFF, 0x25, 0xBE, 0xBA, 0xFE, 0xCA);
}

TEST_F(AssemblerTest, Ret) {
  asm_.ret();
  EXPECT_BYTES(0xC3);

  asm_.ret(0x4);
  EXPECT_BYTES(0xC2, 0x04, 0x00);
}

TEST_F(AssemblerTest, MovByte) {
  asm_.mov_b(OperandImpl(eax, ebx, kTimes4,
                         DisplacementImpl(0xCAFEBABE, kSize32Bit)),
             ImmediateImpl(0xCB, kSize8Bit));
  EXPECT_BYTES(0xC6, 0x84, 0x98, 0xBE, 0xBA, 0xFE, 0xCA, 0xCB);
}

TEST_F(AssemblerTest, MovzxByte) {
  asm_.movzx_b(eax, OperandImpl(ebx));
  EXPECT_BYTES(0x0F, 0xB6, 0x03);

  asm_.movzx_b(ecx, OperandImpl(ecx, edx, kTimes2));
  EXPECT_BYTES(0x0F, 0xB6, 0x0C, 0x51);
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

  // Test a sampling of 8-bit displacements.
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

TEST_F(AssemblerTest, MovRegisterBaseDisplacementScaleIndirect) {
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

TEST_F(AssemblerTest, MovRegisterBaseIndexScaleIndirect) {
  // Tests the displacement-less [base + index * scale].
  asm_.mov(edx, OperandImpl(esi, eax, kTimes8));
  EXPECT_BYTES(0x8B, 0x14, 0xC6);
}

TEST_F(AssemblerTest, MovRegisterDisplacementScaleIndirect) {
  // Tests [index * scale + displ] modes, which are always encoded with a
  // 32-bit displacement, including [index * scale], which has a zero 32-bit
  // displacement that will be omitted from disassembly.

  DisplacementImpl one(1, kSize8Bit, NULL);

  // Source mode.
  asm_.mov(edx, OperandImpl(eax, kTimes4, one));
  EXPECT_BYTES(0x8B, 0x14, 0x85, 0x01, 0x00, 0x00, 0x00);
  asm_.mov(edx, OperandImpl(ecx, kTimes4, one));
  EXPECT_BYTES(0x8B, 0x14, 0x8D, 0x01, 0x00, 0x00, 0x00);
  asm_.mov(edx, OperandImpl(edx, kTimes4, one));
  EXPECT_BYTES(0x8B, 0x14, 0x95, 0x01, 0x00, 0x00, 0x00);
  asm_.mov(edx, OperandImpl(ebx, kTimes4, one));
  EXPECT_BYTES(0x8B, 0x14, 0x9D, 0x01, 0x00, 0x00, 0x00);
  asm_.mov(edx, OperandImpl(ebp, kTimes4, one));
  EXPECT_BYTES(0x8B, 0x14, 0xAD, 0x01, 0x00, 0x00, 0x00);
  asm_.mov(edx, OperandImpl(esi, kTimes4, one));
  EXPECT_BYTES(0x8B, 0x14, 0xB5, 0x01, 0x00, 0x00, 0x00);
  asm_.mov(edx, OperandImpl(edi, kTimes4, one));
  EXPECT_BYTES(0x8B, 0x14, 0xBD, 0x01, 0x00, 0x00, 0x00);

  // Destination mode.
  asm_.mov(OperandImpl(eax, kTimes4, one), edx);
  EXPECT_BYTES(0x89, 0x14, 0x85, 0x01, 0x00, 0x00, 0x00);
  asm_.mov(OperandImpl(ecx, kTimes4, one), edx);
  EXPECT_BYTES(0x89, 0x14, 0x8D, 0x01, 0x00, 0x00, 0x00);
  asm_.mov(OperandImpl(edx, kTimes4, one), edx);
  EXPECT_BYTES(0x89, 0x14, 0x95, 0x01, 0x00, 0x00, 0x00);
  asm_.mov(OperandImpl(ebx, kTimes4, one), edx);
  EXPECT_BYTES(0x89, 0x14, 0x9D, 0x01, 0x00, 0x00, 0x00);
  asm_.mov(OperandImpl(ebp, kTimes4, one), edx);
  EXPECT_BYTES(0x89, 0x14, 0xAD, 0x01, 0x00, 0x00, 0x00);
  asm_.mov(OperandImpl(esi, kTimes4, one), edx);
  EXPECT_BYTES(0x89, 0x14, 0xB5, 0x01, 0x00, 0x00, 0x00);
  asm_.mov(OperandImpl(edi, kTimes4, one), edx);
  EXPECT_BYTES(0x89, 0x14, 0xBD, 0x01, 0x00, 0x00, 0x00);
}

TEST_F(AssemblerTest, MovImmToRegisterDisplacementScaleIndirect) {
  DisplacementImpl cafebabe(0xCAFEBABE, kSize32Bit, NULL);
  ImmediateImpl deadbeef(0xDEADBEEF, kSize32Bit, NULL);

  // We expect the operand encoding has been adequately tested elsewhere,
  // so we only test one variant here.
  asm_.mov(OperandImpl(ecx, eax, kTimes4, cafebabe), deadbeef);
  EXPECT_BYTES(0xC7, 0x84, 0x81,
               0xBE, 0xBA, 0xFE, 0xCA,
               0xEF, 0xBE, 0xAD, 0xDE);
}

TEST_F(AssemblerTest, MovWithSegmentPrefix) {
  // Indirect register destination modes.
  asm_.mov_fs(OperandImpl(eax), ebx);
  EXPECT_BYTES(0x64, 0x89, 0x18);
  asm_.mov_fs(OperandImpl(ecx), eax);
  EXPECT_BYTES(0x64, 0x89, 0x01);
  asm_.mov_fs(OperandImpl(ebx), edx);
  EXPECT_BYTES(0x64, 0x89, 0x13);
  asm_.mov_fs(OperandImpl(edx), ecx);
  EXPECT_BYTES(0x64, 0x89, 0x0A);

  // Indirect register only source modes.
  asm_.mov_fs(ebx, OperandImpl(eax));
  EXPECT_BYTES(0x64, 0x8B, 0x18);
  asm_.mov_fs(eax, OperandImpl(ecx));
  EXPECT_BYTES(0x64, 0x8B, 0x01);
  asm_.mov_fs(edx, OperandImpl(ebx));
  EXPECT_BYTES(0x64, 0x8B, 0x13);
  asm_.mov_fs(ecx, OperandImpl(edx));
  EXPECT_BYTES(0x64, 0x8B, 0x0A);
}

TEST_F(AssemblerTest, LeaRegisterIndirect) {
  // Indirect register only source modes.
  asm_.lea(ebx, OperandImpl(eax));
  EXPECT_BYTES(0x8D, 0x18);
  asm_.lea(eax, OperandImpl(ecx));
  EXPECT_BYTES(0x8D, 0x01);
  asm_.lea(edx, OperandImpl(ebx));
  EXPECT_BYTES(0x8D, 0x13);
  asm_.lea(ecx, OperandImpl(edx));
  EXPECT_BYTES(0x8D, 0x0A);

  // Note that EBP is a special case that always requires a displacement.
  asm_.lea(ebx, OperandImpl(ebp));
  EXPECT_BYTES(0x8D, 0x5D, 0x00);

  // Note that ESP is a special case that always requires a SIB byte.
  asm_.lea(ecx, OperandImpl(esp));
  EXPECT_BYTES(0x8D, 0x0C, 0x24);

  asm_.lea(ebx, OperandImpl(esi));
  EXPECT_BYTES(0x8D, 0x1E);
  asm_.lea(eax, OperandImpl(edi));
  EXPECT_BYTES(0x8D, 0x07);
}

TEST_F(AssemblerTest, LeaRegisterDisplacementIndirect) {
  // Register & displacement source modes.
  DisplacementImpl cafebabe(0xCAFEBABE, kSize32Bit, NULL);

  asm_.lea(ebx, OperandImpl(eax, cafebabe));
  EXPECT_BYTES(0x8D, 0x98, 0xBE, 0xBA, 0xFE, 0xCA);
  asm_.lea(eax, OperandImpl(ecx, cafebabe));
  EXPECT_BYTES(0x8D, 0x81, 0xBE, 0xBA, 0xFE, 0xCA);
  asm_.lea(eax, OperandImpl(ebx, cafebabe));
  EXPECT_BYTES(0x8D, 0x83, 0xBE, 0xBA, 0xFE, 0xCA);
  asm_.lea(eax, OperandImpl(edx, cafebabe));
  EXPECT_BYTES(0x8D, 0x82, 0xBE, 0xBA, 0xFE, 0xCA);
  asm_.lea(eax, OperandImpl(ebp, cafebabe));
  EXPECT_BYTES(0x8D, 0x85, 0xBE, 0xBA, 0xFE, 0xCA);

  // ESP requires a SIB byte and has a longer encoding.
  asm_.lea(eax, OperandImpl(esp, cafebabe));
  EXPECT_BYTES(0x8D, 0x84, 0x24, 0xBE, 0xBA, 0xFE, 0xCA);

  asm_.lea(eax, OperandImpl(esi, cafebabe));
  EXPECT_BYTES(0x8D, 0x86, 0xBE, 0xBA, 0xFE, 0xCA);
  asm_.lea(eax, OperandImpl(edi, cafebabe));
  EXPECT_BYTES(0x8D, 0x87, 0xBE, 0xBA, 0xFE, 0xCA);

  // Test a sampling of 8-bit displacements.
  DisplacementImpl ca(0xCA, kSize8Bit, NULL);

  // Source.
  asm_.lea(ebx, OperandImpl(eax, ca));
  EXPECT_BYTES(0x8D, 0x58, 0xCA);

  // ESP requires a SIB byte and has a longer encoding.
  asm_.lea(eax, OperandImpl(esp, ca));
  EXPECT_BYTES(0x8D, 0x44, 0x24, 0xCA);
}

TEST_F(AssemblerTest, LeaDisplacementIndirect) {
  // Displacement-only mode.
  DisplacementImpl cafebabe(0xCAFEBABE, kSize32Bit, NULL);

  asm_.lea(eax, OperandImpl(cafebabe));
  EXPECT_BYTES(0x8D, 0x05, 0xBE, 0xBA, 0xFE, 0xCA);
  asm_.lea(ecx, OperandImpl(cafebabe));
  EXPECT_BYTES(0x8D, 0x0D, 0xBE, 0xBA, 0xFE, 0xCA);
}

TEST_F(AssemblerTest, LeaRegisterDisplacementScaleIndirect) {
  // There are 8 base * 7 index * 4 scales = 224 combinations.
  // We don't test all of them, but rather cycle through each of base,
  // index and scale individually.
  DisplacementImpl cafebabe(0xCAFEBABE, kSize32Bit, NULL);

  // Source mode, base register.
  asm_.lea(edx, OperandImpl(ecx, eax, kTimes4, cafebabe));
  EXPECT_BYTES(0x8D, 0x94, 0x81, 0xBE, 0xBA, 0xFE, 0xCA);
  asm_.lea(eax, OperandImpl(ecx, eax, kTimes4, cafebabe));
  EXPECT_BYTES(0x8D, 0x84, 0x81, 0xBE, 0xBA, 0xFE, 0xCA);
  asm_.lea(eax, OperandImpl(edx, eax, kTimes4, cafebabe));
  EXPECT_BYTES(0x8D, 0x84, 0x82, 0xBE, 0xBA, 0xFE, 0xCA);
  asm_.lea(eax, OperandImpl(ebx, eax, kTimes4, cafebabe));
  EXPECT_BYTES(0x8D, 0x84, 0x83, 0xBE, 0xBA, 0xFE, 0xCA);
  asm_.lea(eax, OperandImpl(esp, eax, kTimes4, cafebabe));
  EXPECT_BYTES(0x8D, 0x84, 0x84, 0xBE, 0xBA, 0xFE, 0xCA);
  asm_.lea(eax, OperandImpl(ebp, eax, kTimes4, cafebabe));
  EXPECT_BYTES(0x8D, 0x84, 0x85, 0xBE, 0xBA, 0xFE, 0xCA);
  asm_.lea(eax, OperandImpl(esi, eax, kTimes4, cafebabe));
  EXPECT_BYTES(0x8D, 0x84, 0x86, 0xBE, 0xBA, 0xFE, 0xCA);
  asm_.lea(eax, OperandImpl(edi, eax, kTimes4, cafebabe));
  EXPECT_BYTES(0x8D, 0x84, 0x87, 0xBE, 0xBA, 0xFE, 0xCA);

  // Source mode, index register.
  asm_.lea(ebx, OperandImpl(ecx, eax, kTimes4, cafebabe));
  EXPECT_BYTES(0x8D, 0x9C, 0x81, 0xBE, 0xBA, 0xFE, 0xCA);
  asm_.lea(eax, OperandImpl(eax, ecx, kTimes4, cafebabe));
  EXPECT_BYTES(0x8D, 0x84, 0x88, 0xBE, 0xBA, 0xFE, 0xCA);
  asm_.lea(eax, OperandImpl(eax, edx, kTimes4, cafebabe));
  EXPECT_BYTES(0x8D, 0x84, 0x90, 0xBE, 0xBA, 0xFE, 0xCA);
  asm_.lea(eax, OperandImpl(eax, ebx, kTimes4, cafebabe));
  EXPECT_BYTES(0x8D, 0x84, 0x98, 0xBE, 0xBA, 0xFE, 0xCA);
  asm_.lea(eax, OperandImpl(eax, ebp, kTimes4, cafebabe));
  EXPECT_BYTES(0x8D, 0x84, 0xA8, 0xBE, 0xBA, 0xFE, 0xCA);
  asm_.lea(eax, OperandImpl(eax, esi, kTimes4, cafebabe));
  EXPECT_BYTES(0x8D, 0x84, 0xB0, 0xBE, 0xBA, 0xFE, 0xCA);
  asm_.lea(eax, OperandImpl(eax, edi, kTimes4, cafebabe));
  EXPECT_BYTES(0x8D, 0x84, 0xB8, 0xBE, 0xBA, 0xFE, 0xCA);

  // Source mode, Scale.
  asm_.lea(ebx, OperandImpl(ecx, eax, kTimes1, cafebabe));
  EXPECT_BYTES(0x8D, 0x9C, 0x01, 0xBE, 0xBA, 0xFE, 0xCA);
  asm_.lea(ebx, OperandImpl(ecx, eax, kTimes2, cafebabe));
  EXPECT_BYTES(0x8D, 0x9C, 0x41, 0xBE, 0xBA, 0xFE, 0xCA);
  asm_.lea(ebx, OperandImpl(ecx, eax, kTimes4, cafebabe));
  EXPECT_BYTES(0x8D, 0x9C, 0x81, 0xBE, 0xBA, 0xFE, 0xCA);
  asm_.lea(ebx, OperandImpl(ecx, eax, kTimes8, cafebabe));
  EXPECT_BYTES(0x8D, 0x9C, 0xC1, 0xBE, 0xBA, 0xFE, 0xCA);
}

TEST_F(AssemblerTest, Push) {
  // Register push.
  asm_.push(eax);
  asm_.push(ecx);
  asm_.push(edx);
  asm_.push(ebx);
  asm_.push(esp);
  asm_.push(ebp);
  asm_.push(esi);
  asm_.push(edi);
  EXPECT_BYTES(0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57);

  // Immediate push.
  asm_.push(ImmediateImpl(0xCAFEBABE, kSize32Bit, NULL));
  EXPECT_BYTES(0x68, 0xBE, 0xBA, 0xFE, 0xCA);

  // General push, try one variant as the rest are OperandImpl encodings.
  asm_.push(OperandImpl(DisplacementImpl(0xCAFEBABE, kSize32Bit, NULL)));
  EXPECT_BYTES(0xFF, 0x35, 0xBE, 0xBA, 0xFE, 0xCA);

  asm_.pushad();
  EXPECT_BYTES(0x60);
}

TEST_F(AssemblerTest, Pop) {
  // Register pop.
  asm_.pop(eax);
  asm_.pop(ecx);
  asm_.pop(edx);
  asm_.pop(ebx);
  asm_.pop(esp);
  asm_.pop(ebp);
  asm_.pop(esi);
  asm_.pop(edi);
  EXPECT_BYTES(0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F);

  // General pop, try one variant as the rest are OperandImpl encodings.
  asm_.pop(OperandImpl(DisplacementImpl(0xCAFEBABE, kSize32Bit, NULL)));
  EXPECT_BYTES(0x8F, 0x05, 0xBE, 0xBA, 0xFE, 0xCA);

  asm_.popad();
  EXPECT_BYTES(0x61);
}

TEST_F(AssemblerTest, Flags) {
  asm_.pushfd();
  asm_.popfd();
  asm_.lahf();
  asm_.sahf();
  EXPECT_BYTES(0x9C, 0x9D, 0x9F, 0x9E);
}

TEST_F(AssemblerTest, TestByte) {
  asm_.test(al, bl);
  EXPECT_BYTES(0x84, 0xC3);
  asm_.test(bh, al);
  EXPECT_BYTES(0x84, 0xF8);

  asm_.test(al, ImmediateImpl(0x0A, kSize8Bit));
  EXPECT_BYTES(0xA8, 0x0A);
  asm_.test(bh, ImmediateImpl(0x0A, kSize8Bit));
  EXPECT_BYTES(0xF6, 0xC7, 0x0A);
}

TEST_F(AssemblerTest, Test) {
  asm_.test(eax, ecx);
  EXPECT_BYTES(0x85, 0xC1);
  asm_.test(ecx, OperandImpl(eax));
  EXPECT_BYTES(0x85, 0x08);
  asm_.test(ecx, OperandImpl(eax, DisplacementImpl(10, kSize8Bit)));
  EXPECT_BYTES(0x85, 0x48, 0x0A);
  asm_.test(ecx, OperandImpl(eax, DisplacementImpl(10, kSize32Bit)));
  EXPECT_BYTES(0x85, 0x88, 0x0A, 0x00, 0x00, 0x00);

  asm_.test(ecx, eax);
  EXPECT_BYTES(0x85, 0xC8);
  asm_.test(ecx, OperandImpl(eax));
  EXPECT_BYTES(0x85, 0x08);
  asm_.test(ecx, OperandImpl(eax, DisplacementImpl(10, kSize8Bit)));
  EXPECT_BYTES(0x85, 0x48, 0x0A);
  asm_.test(ecx, OperandImpl(eax, DisplacementImpl(10, kSize32Bit)));
  EXPECT_BYTES(0x85, 0x88, 0x0A, 0x00, 0x00, 0x00);

  asm_.test(OperandImpl(eax), ecx);
  EXPECT_BYTES(0x85, 0x08);
  asm_.test(OperandImpl(eax, DisplacementImpl(10, kSize8Bit)), ecx);
  EXPECT_BYTES(0x85, 0x48, 0x0A);
  asm_.test(OperandImpl(eax, DisplacementImpl(10, kSize32Bit)), ecx);
  EXPECT_BYTES(0x85, 0x88, 0x0A, 0x00, 0x00, 0x00);

  asm_.test(eax, ImmediateImpl(0x0A, kSize8Bit));
  EXPECT_BYTES(0xA9, 0x0A, 0x00, 0x00, 0x00);
  asm_.test(ecx, ImmediateImpl(0x0A, kSize8Bit));
  EXPECT_BYTES(0xF7, 0xC1, 0x0A, 0x00, 0x00, 0x00);
  asm_.test(ecx, ImmediateImpl(0xDEADBEEF, kSize32Bit));
  EXPECT_BYTES(0xF7, 0xC1, 0xEF, 0xBE, 0xAD, 0xDE);

  asm_.test(OperandImpl(eax), ImmediateImpl(1, kSize8Bit));
  EXPECT_BYTES(0xF7, 0x00, 0x01, 0x00, 0x00, 0x00);
  asm_.test(OperandImpl(eax), ImmediateImpl(0xDEADBEEF, kSize32Bit));
  EXPECT_BYTES(0xF7, 0x00, 0xEF, 0xBE, 0xAD, 0xDE);
  asm_.test(OperandImpl(eax, DisplacementImpl(10, kSize8Bit)),
            ImmediateImpl(0x1, kSize8Bit));
  EXPECT_BYTES(0xF7, 0x40, 0x0A, 0x01, 0x00, 0x00, 0x00);
  asm_.test(OperandImpl(eax, DisplacementImpl(10, kSize8Bit)),
            ImmediateImpl(0xDEADBEEF, kSize32Bit));
  EXPECT_BYTES(0xF7, 0x40, 0x0A, 0xEF, 0xBE, 0xAD, 0xDE);
  asm_.test(OperandImpl(eax, DisplacementImpl(10, kSize32Bit)),
            ImmediateImpl(0xDEADBEEF, kSize32Bit));
  EXPECT_BYTES(0xF7, 0x80, 0x0A, 0x00, 0x00, 0x00, 0xEF, 0xBE, 0xAD, 0xDE);

  // Special EAX mode + immediate.
  asm_.test(eax, ImmediateImpl(0xDEADBEEF, kSize32Bit));
  EXPECT_BYTES(0xA9, 0xEF, 0xBE, 0xAD, 0xDE);
}

TEST_F(AssemblerTest, CmpByte) {
  asm_.cmp(al, bl);
  EXPECT_BYTES(0x3A, 0xC3);
  asm_.cmp(bh, al);
  EXPECT_BYTES(0x3A, 0xF8);

  asm_.cmp(al, ImmediateImpl(0x0A, kSize8Bit));
  EXPECT_BYTES(0x3C, 0x0A);
  asm_.cmp(bh, ImmediateImpl(0x0A, kSize8Bit));
  EXPECT_BYTES(0x80, 0xFF, 0x0A);
}

TEST_F(AssemblerTest, Cmp) {
  asm_.cmp(eax, ecx);
  EXPECT_BYTES(0x3B, 0xC1);
  asm_.cmp(ecx, OperandImpl(eax));
  EXPECT_BYTES(0x3B, 0x08);
  asm_.cmp(ecx, OperandImpl(eax, DisplacementImpl(10, kSize8Bit)));
  EXPECT_BYTES(0x3B, 0x48, 0x0A);
  asm_.cmp(ecx, OperandImpl(eax, DisplacementImpl(10, kSize32Bit)));
  EXPECT_BYTES(0x3B, 0x88, 0x0A, 0x00, 0x00, 0x00);

  asm_.cmp(ecx, eax);
  EXPECT_BYTES(0x3B, 0xC8);
  asm_.cmp(ecx, OperandImpl(eax));
  EXPECT_BYTES(0x3B, 0x08);
  asm_.cmp(ecx, OperandImpl(eax, DisplacementImpl(10, kSize8Bit)));
  EXPECT_BYTES(0x3B, 0x48, 0x0A);
  asm_.cmp(ecx, OperandImpl(eax, DisplacementImpl(10, kSize32Bit)));
  EXPECT_BYTES(0x3B, 0x88, 0x0A, 0x00, 0x00, 0x00);

  asm_.cmp(OperandImpl(eax), ecx);
  EXPECT_BYTES(0x39, 0x08);
  asm_.cmp(OperandImpl(eax, DisplacementImpl(10, kSize8Bit)), ecx);
  EXPECT_BYTES(0x39, 0x48, 0x0A);
  asm_.cmp(OperandImpl(eax, DisplacementImpl(10, kSize32Bit)), ecx);
  EXPECT_BYTES(0x39, 0x88, 0x0A, 0x00, 0x00, 0x00);

  asm_.cmp(eax, ImmediateImpl(0x0A, kSize8Bit));
  EXPECT_BYTES(0x83, 0xF8, 0x0A);
  asm_.cmp(ecx, ImmediateImpl(0x0A, kSize8Bit));
  EXPECT_BYTES(0x83, 0xF9, 0x0A);
  asm_.cmp(ecx, ImmediateImpl(0xDEADBEEF, kSize32Bit));
  EXPECT_BYTES(0x81, 0xF9, 0xEF, 0xBE, 0xAD, 0xDE);

  asm_.cmp(OperandImpl(eax), ImmediateImpl(1, kSize8Bit));
  EXPECT_BYTES(0x83, 0x38, 0x01);
  asm_.cmp(OperandImpl(eax), ImmediateImpl(0xDEADBEEF, kSize32Bit));
  EXPECT_BYTES(0x81, 0x38, 0xEF, 0xBE, 0xAD, 0xDE);
  asm_.cmp(OperandImpl(eax, DisplacementImpl(10, kSize8Bit)),
           ImmediateImpl(0x1, kSize8Bit));
  EXPECT_BYTES(0x83, 0x78, 0x0A, 0x1);
  asm_.cmp(OperandImpl(eax, DisplacementImpl(10, kSize8Bit)),
           ImmediateImpl(0xDEADBEEF, kSize32Bit));
  EXPECT_BYTES(0x81, 0x78, 0x0A, 0xEF, 0xBE, 0xAD, 0xDE);
  asm_.cmp(OperandImpl(eax, DisplacementImpl(10, kSize32Bit)),
           ImmediateImpl(0xDEADBEEF, kSize32Bit));
  EXPECT_BYTES(0x81, 0xB8, 0x0A, 0x00, 0x00, 0x00, 0xEF, 0xBE, 0xAD, 0xDE);

  // Special EAX mode + immediate.
  asm_.cmp(eax, ImmediateImpl(0xDEADBEEF, kSize32Bit));
  EXPECT_BYTES(0x3D, 0xEF, 0xBE, 0xAD, 0xDE);
}

TEST_F(AssemblerTest, AddByte) {
  asm_.add(al, bl);
  EXPECT_BYTES(0x02, 0xC3);
  asm_.add(bh, al);
  EXPECT_BYTES(0x02, 0xF8);

  asm_.add(al, ImmediateImpl(0x0A, kSize8Bit));
  EXPECT_BYTES(0x04, 0x0A);
  asm_.add(bh, ImmediateImpl(0x0A, kSize8Bit));
  EXPECT_BYTES(0x80, 0xC7, 0x0A);
}


TEST_F(AssemblerTest, Add) {
  asm_.add(eax, eax);
  EXPECT_BYTES(0x03, 0xC0);
  asm_.add(eax, OperandImpl(eax));
  EXPECT_BYTES(0x03, 0x00);
  asm_.add(eax, OperandImpl(eax, DisplacementImpl(10, kSize8Bit)));
  EXPECT_BYTES(0x03, 0x40, 0x0A);
  asm_.add(eax, OperandImpl(eax, DisplacementImpl(10, kSize32Bit)));
  EXPECT_BYTES(0x03, 0x80, 0x0A, 0x00, 0x00, 0x00);

  asm_.add(ecx, eax);
  EXPECT_BYTES(0x03, 0xC8);
  asm_.add(ecx, OperandImpl(eax));
  EXPECT_BYTES(0x03, 0x08);
  asm_.add(ecx, OperandImpl(eax, DisplacementImpl(10, kSize8Bit)));
  EXPECT_BYTES(0x03, 0x48, 0x0A);
  asm_.add(ecx, OperandImpl(eax, DisplacementImpl(10, kSize32Bit)));
  EXPECT_BYTES(0x03, 0x88, 0x0A, 0x00, 0x00, 0x00);

  asm_.add(eax, ecx);
  EXPECT_BYTES(0x03, 0xC1);
  asm_.add(OperandImpl(eax), ecx);
  EXPECT_BYTES(0x01, 0x08);
  asm_.add(OperandImpl(eax, DisplacementImpl(10, kSize8Bit)), ecx);
  EXPECT_BYTES(0x01, 0x48, 0x0A);
  asm_.add(OperandImpl(eax, DisplacementImpl(10, kSize32Bit)), ecx);
  EXPECT_BYTES(0x01, 0x88, 0x0A, 0x00, 0x00, 0x00);

  asm_.add(eax, ImmediateImpl(0x0A, kSize8Bit));
  EXPECT_BYTES(0x83, 0xC0, 0x0A);
  asm_.add(ecx, ImmediateImpl(0x0A, kSize8Bit));
  EXPECT_BYTES(0x83, 0xC1, 0x0A);
  asm_.add(ecx, ImmediateImpl(0xDEADBEEF, kSize32Bit));
  EXPECT_BYTES(0x81, 0xC1, 0xEF, 0xBE, 0xAD, 0xDE);

  asm_.add(OperandImpl(eax), ImmediateImpl(1, kSize8Bit));
  EXPECT_BYTES(0x83, 0x00, 0x01);
  asm_.add(OperandImpl(eax), ImmediateImpl(0xDEADBEEF, kSize32Bit));
  EXPECT_BYTES(0x81, 0x00, 0xEF, 0xBE, 0xAD, 0xDE);
  asm_.add(OperandImpl(eax, DisplacementImpl(10, kSize8Bit)),
           ImmediateImpl(0xDEADBEEF, kSize32Bit));
  EXPECT_BYTES(0x81, 0x40, 0x0A, 0xEF, 0xBE, 0xAD, 0xDE);
  asm_.add(OperandImpl(eax, DisplacementImpl(10, kSize32Bit)),
           ImmediateImpl(0xDEADBEEF, kSize32Bit));
  EXPECT_BYTES(0x81, 0x80, 0x0A, 0x00, 0x00, 0x00, 0xEF, 0xBE, 0xAD, 0xDE);

  // Special EAX mode + immediate.
  asm_.add(eax, ImmediateImpl(0xDEADBEEF, kSize32Bit));
  EXPECT_BYTES(0x05, 0xEF, 0xBE, 0xAD, 0xDE);
}

TEST_F(AssemblerTest, SubByte) {
  asm_.sub(al, bl);
  EXPECT_BYTES(0x2A, 0xC3);
  asm_.sub(bh, al);
  EXPECT_BYTES(0x2A, 0xF8);

  asm_.sub(al, ImmediateImpl(0x0A, kSize8Bit));
  EXPECT_BYTES(0x2C, 0x0A);
  asm_.sub(bh, ImmediateImpl(0x0A, kSize8Bit));
  EXPECT_BYTES(0x80, 0xEF, 0x0A);
}

TEST_F(AssemblerTest, Sub) {
  asm_.sub(eax, eax);
  EXPECT_BYTES(0x2B, 0xC0);
  asm_.sub(eax, OperandImpl(eax));
  EXPECT_BYTES(0x2B, 0x00);
  asm_.sub(eax, OperandImpl(eax, DisplacementImpl(10, kSize8Bit)));
  EXPECT_BYTES(0x2B, 0x40, 0x0A);
  asm_.sub(eax, OperandImpl(eax, DisplacementImpl(10, kSize32Bit)));
  EXPECT_BYTES(0x2B, 0x80, 0x0A, 0x00, 0x00, 0x00);

  asm_.sub(ecx, eax);
  EXPECT_BYTES(0x2B, 0xC8);
  asm_.sub(ecx, OperandImpl(eax));
  EXPECT_BYTES(0x2B, 0x08);
  asm_.sub(ecx, OperandImpl(eax, DisplacementImpl(10, kSize8Bit)));
  EXPECT_BYTES(0x2B, 0x48, 0x0A);
  asm_.sub(ecx, OperandImpl(eax, DisplacementImpl(10, kSize32Bit)));
  EXPECT_BYTES(0x2B, 0x88, 0x0A, 0x00, 0x00, 0x00);

  asm_.sub(eax, ecx);
  EXPECT_BYTES(0x2B, 0xC1);
  asm_.sub(OperandImpl(eax), ecx);
  EXPECT_BYTES(0x29, 0x08);
  asm_.sub(OperandImpl(eax, DisplacementImpl(10, kSize8Bit)), ecx);
  EXPECT_BYTES(0x29, 0x48, 0x0A);
  asm_.sub(OperandImpl(eax, DisplacementImpl(10, kSize32Bit)), ecx);
  EXPECT_BYTES(0x29, 0x88, 0x0A, 0x00, 0x00, 0x00);

  asm_.sub(eax, ImmediateImpl(0x0A, kSize8Bit));
  EXPECT_BYTES(0x83, 0xE8, 0x0A);
  asm_.sub(ecx, ImmediateImpl(0x0A, kSize8Bit));
  EXPECT_BYTES(0x83, 0xE9, 0x0A);
  asm_.sub(ecx, ImmediateImpl(0xDEADBEEF, kSize32Bit));
  EXPECT_BYTES(0x81, 0xE9, 0xEF, 0xBE, 0xAD, 0xDE);

  asm_.sub(OperandImpl(eax), ImmediateImpl(0x1, kSize8Bit));
  EXPECT_BYTES(0x83, 0x28, 0x01);
  asm_.sub(OperandImpl(eax), ImmediateImpl(0xDEADBEEF, kSize32Bit));
  EXPECT_BYTES(0x81, 0x28, 0xEF, 0xBE, 0xAD, 0xDE);
  asm_.sub(OperandImpl(eax, DisplacementImpl(10, kSize8Bit)),
           ImmediateImpl(0xDEADBEEF, kSize32Bit));
  EXPECT_BYTES(0x81, 0x68, 0x0A, 0xEF, 0xBE, 0xAD, 0xDE);
  asm_.sub(OperandImpl(eax, DisplacementImpl(10, kSize32Bit)),
           ImmediateImpl(0xDEADBEEF, kSize32Bit));
  EXPECT_BYTES(0x81, 0xA8, 0x0A, 0x00, 0x00, 0x00, 0xEF, 0xBE, 0xAD, 0xDE);

  // Special EAX mode + immediate.
  asm_.sub(eax, ImmediateImpl(0xDEADBEEF, kSize32Bit));
  EXPECT_BYTES(0x2D, 0xEF, 0xBE, 0xAD, 0xDE);
}

TEST_F(AssemblerTest, Shl) {
  asm_.shl(eax, ImmediateImpl(0x1, kSize8Bit));
  EXPECT_BYTES(0xD1, 0xE0);
  asm_.shl(eax, ImmediateImpl(0x3, kSize8Bit));
  EXPECT_BYTES(0xC1, 0xE0, 0x03);
  asm_.shl(ecx, ImmediateImpl(0x1, kSize8Bit));
  EXPECT_BYTES(0xD1, 0xE1);
  asm_.shl(ecx, ImmediateImpl(0x3, kSize8Bit));
  EXPECT_BYTES(0xC1, 0xE1, 0x03);
}

TEST_F(AssemblerTest, Shr) {
  asm_.shr(eax, ImmediateImpl(0x1, kSize8Bit));
  EXPECT_BYTES(0xD1, 0xE8);
  asm_.shr(eax, ImmediateImpl(0x3, kSize8Bit));
  EXPECT_BYTES(0xC1, 0xE8, 0x03);
  asm_.shr(ecx, ImmediateImpl(0x1, kSize8Bit));
  EXPECT_BYTES(0xD1, 0xE9);
  asm_.shr(ecx, ImmediateImpl(0x3, kSize8Bit));
  EXPECT_BYTES(0xC1, 0xE9, 0x03);
}

TEST_F(AssemblerTest, Xchg32) {
  // Any exchange with the eax register should generate a single byte
  // instruction.
  asm_.xchg(eax, eax);
  EXPECT_BYTES(0x90);
  asm_.xchg(eax, ecx);
  EXPECT_BYTES(0x91);
  asm_.xchg(esp, eax);
  EXPECT_BYTES(0x94);

  // Any exchanges not involving the eax register should generate 2-byte
  // instructions.
  asm_.xchg(ebx, ecx);
  EXPECT_BYTES(0x87, 0xCB);
  asm_.xchg(edx, esp);
  EXPECT_BYTES(0x87, 0xE2);
  asm_.xchg(esp, edx);
  EXPECT_BYTES(0x87, 0xD4);
}

TEST_F(AssemblerTest, Xchg16) {
  // Any exchange with the ax register should generate 2-byte instructions.
  asm_.xchg(ax, ax);
  EXPECT_BYTES(0x66, 0x90);
  asm_.xchg(ax, cx);
  EXPECT_BYTES(0x66, 0x91);
  asm_.xchg(sp, ax);
  EXPECT_BYTES(0x66, 0x94);

  // Any exchanges not involving the ax register should generate 3-byte
  // instructions.
  asm_.xchg(cx, dx);
  EXPECT_BYTES(0x66, 0x87, 0xD1);
  asm_.xchg(bx, cx);
  EXPECT_BYTES(0x66, 0x87, 0xCB);
  asm_.xchg(dx, sp);
  EXPECT_BYTES(0x66, 0x87, 0xE2);
  asm_.xchg(sp, dx);
  EXPECT_BYTES(0x66, 0x87, 0xD4);
  asm_.xchg(bp, dx);
  EXPECT_BYTES(0x66, 0x87, 0xD5);
  asm_.xchg(si, sp);
  EXPECT_BYTES(0x66, 0x87, 0xE6);
  asm_.xchg(di, cx);
  EXPECT_BYTES(0x66, 0x87, 0xCF);
}

TEST_F(AssemblerTest, Xchg8) {
  asm_.xchg(al, ah);
  EXPECT_BYTES(0x86, 0xE0);
  asm_.xchg(cl, bl);
  EXPECT_BYTES(0x86, 0xD9);
  asm_.xchg(dl, bh);
  EXPECT_BYTES(0x86, 0xFA);
  asm_.xchg(bl, dh);
  EXPECT_BYTES(0x86, 0xF3);
  asm_.xchg(ah, cl);
  EXPECT_BYTES(0x86, 0xCC);
  asm_.xchg(ch, dl);
  EXPECT_BYTES(0x86, 0xD5);
  asm_.xchg(dh, ch);
  EXPECT_BYTES(0x86, 0xEE);
  asm_.xchg(bh, al);
  EXPECT_BYTES(0x86, 0xC7);
}

TEST_F(AssemblerTest, Ja) {
  ConditionCode cc = kAbove;
  asm_.set_location(0xCAFEBABE);

  asm_.j(cc, ImmediateImpl(0xCAFEBABE, kSize8Bit, NULL));
  EXPECT_BYTES(0x77, 0xFE);

  ASSERT_EQ(1, AssemblerImpl::kShortBranchOpcodeSize);
  ASSERT_EQ(2, AssemblerImpl::kShortBranchSize);

  asm_.j(cc, ImmediateImpl(0xCAFEBABE, kSize32Bit, NULL));
  EXPECT_BYTES(0x0F, 0x87, 0xF8, 0xFF, 0xFF, 0xFF);

  ASSERT_EQ(2, AssemblerImpl::kLongBranchOpcodeSize);
  ASSERT_EQ(6, AssemblerImpl::kLongBranchSize);
}

TEST_F(AssemblerTest, Jae) {
  ConditionCode cc = kAboveEqual;
  asm_.set_location(0xCAFEBABE);

  asm_.j(cc, ImmediateImpl(0xCAFEBABE, kSize8Bit, NULL));
  EXPECT_BYTES(0x73, 0xFE);
  asm_.j(cc, ImmediateImpl(0xCAFEBABE, kSize32Bit, NULL));
  EXPECT_BYTES(0x0F, 0x83, 0xF8, 0xFF, 0xFF, 0xFF);
}

TEST_F(AssemblerTest, Jb) {
  ConditionCode cc = kBelow;
  asm_.set_location(0xCAFEBABE);

  asm_.j(cc, ImmediateImpl(0xCAFEBABE, kSize8Bit, NULL));
  EXPECT_BYTES(0x72, 0xFE);
  asm_.j(cc, ImmediateImpl(0xCAFEBABE, kSize32Bit, NULL));
  EXPECT_BYTES(0x0F, 0x82, 0xF8, 0xFF, 0xFF, 0xFF);
}

TEST_F(AssemblerTest, Jbe) {
  ConditionCode cc = kBelowEqual;
  asm_.set_location(0xCAFEBABE);

  asm_.j(cc, ImmediateImpl(0xCAFEBABE, kSize8Bit, NULL));
  EXPECT_BYTES(0x76, 0xFE);
  asm_.j(cc, ImmediateImpl(0xCAFEBABE, kSize32Bit, NULL));
  EXPECT_BYTES(0x0F, 0x86, 0xF8, 0xFF, 0xFF, 0xFF);
}

TEST_F(AssemblerTest, Jc) {
  ConditionCode cc = kCarry;
  asm_.set_location(0xCAFEBABE);

  asm_.j(cc, ImmediateImpl(0xCAFEBABE, kSize8Bit, NULL));
  EXPECT_BYTES(0x72, 0xFE);
  asm_.j(cc, ImmediateImpl(0xCAFEBABE, kSize32Bit, NULL));
  EXPECT_BYTES(0x0F, 0x82, 0xF8, 0xFF, 0xFF, 0xFF);
}

TEST_F(AssemblerTest, Je) {
  ConditionCode cc = kEqual;
  asm_.set_location(0xCAFEBABE);

  asm_.j(cc, ImmediateImpl(0xCAFEBABE, kSize8Bit, NULL));
  EXPECT_BYTES(0x74, 0xFE);
  asm_.j(cc, ImmediateImpl(0xCAFEBABE, kSize32Bit, NULL));
  EXPECT_BYTES(0x0F, 0x84, 0xF8, 0xFF, 0xFF, 0xFF);
}

TEST_F(AssemblerTest, Jecxz) {
  asm_.set_location(0xCAFEBABE);

  asm_.jecxz(ImmediateImpl(0xCAFEBABE, kSize8Bit, NULL));
  EXPECT_BYTES(0xE3, 0xFE);
}

TEST_F(AssemblerTest, Jg) {
  ConditionCode cc = kGreater;
  asm_.set_location(0xCAFEBABE);

  asm_.j(cc, ImmediateImpl(0xCAFEBABE, kSize8Bit, NULL));
  EXPECT_BYTES(0x7F, 0xFE);
  asm_.j(cc, ImmediateImpl(0xCAFEBABE, kSize32Bit, NULL));
  EXPECT_BYTES(0x0F, 0x8F, 0xF8, 0xFF, 0xFF, 0xFF);
}

TEST_F(AssemblerTest, Jge) {
  ConditionCode cc = kGreaterEqual;
  asm_.set_location(0xCAFEBABE);

  asm_.j(cc, ImmediateImpl(0xCAFEBABE, kSize8Bit, NULL));
  EXPECT_BYTES(0x7D, 0xFE);
  asm_.j(cc, ImmediateImpl(0xCAFEBABE, kSize32Bit, NULL));
  EXPECT_BYTES(0x0F, 0x8D, 0xF8, 0xFF, 0xFF, 0xFF);
}

TEST_F(AssemblerTest, Jl) {
  ConditionCode cc = kLess;
  asm_.set_location(0xCAFEBABE);

  asm_.j(cc, ImmediateImpl(0xCAFEBABE, kSize8Bit, NULL));
  EXPECT_BYTES(0x7C, 0xFE);
  asm_.j(cc, ImmediateImpl(0xCAFEBABE, kSize32Bit, NULL));
  EXPECT_BYTES(0x0F, 0x8C, 0xF8, 0xFF, 0xFF, 0xFF);
}

TEST_F(AssemblerTest, Jle) {
  ConditionCode cc = kLessEqual;
  asm_.set_location(0xCAFEBABE);

  asm_.j(cc, ImmediateImpl(0xCAFEBABE, kSize8Bit, NULL));
  EXPECT_BYTES(0x7E, 0xFE);
  asm_.j(cc, ImmediateImpl(0xCAFEBABE, kSize32Bit, NULL));
  EXPECT_BYTES(0x0F, 0x8E, 0xF8, 0xFF, 0xFF, 0xFF);
}

TEST_F(AssemblerTest, Jo) {
  ConditionCode cc = kOverflow;
  asm_.set_location(0xCAFEBABE);

  asm_.j(cc, ImmediateImpl(0xCAFEBABE, kSize8Bit, NULL));
  EXPECT_BYTES(0x70, 0xFE);
  asm_.j(cc, ImmediateImpl(0xCAFEBABE, kSize32Bit, NULL));
  EXPECT_BYTES(0x0F, 0x80, 0xF8, 0xFF, 0xFF, 0xFF);
}

TEST_F(AssemblerTest, Jpe) {
  ConditionCode cc = kParityEven;
  asm_.set_location(0xCAFEBABE);

  asm_.j(cc, ImmediateImpl(0xCAFEBABE, kSize8Bit, NULL));
  EXPECT_BYTES(0x7A, 0xFE);
  asm_.j(cc, ImmediateImpl(0xCAFEBABE, kSize32Bit, NULL));
  EXPECT_BYTES(0x0F, 0x8A, 0xF8, 0xFF, 0xFF, 0xFF);
}

TEST_F(AssemblerTest, Jpo) {
  ConditionCode cc = kParityOdd;
  asm_.set_location(0xCAFEBABE);

  asm_.j(cc, ImmediateImpl(0xCAFEBABE, kSize8Bit, NULL));
  EXPECT_BYTES(0x7B, 0xFE);
  asm_.j(cc, ImmediateImpl(0xCAFEBABE, kSize32Bit, NULL));
  EXPECT_BYTES(0x0F, 0x8B, 0xF8, 0xFF, 0xFF, 0xFF);
}

TEST_F(AssemblerTest, Js) {
  ConditionCode cc = kSign;
  asm_.set_location(0xCAFEBABE);
  COMPILE_ASSERT(kSign == kNegative, kSignAndPositiveAreAliases);

  asm_.j(cc, ImmediateImpl(0xCAFEBABE, kSize8Bit, NULL));
  EXPECT_BYTES(0x78, 0xFE);
  asm_.j(cc, ImmediateImpl(0xCAFEBABE, kSize32Bit, NULL));
  EXPECT_BYTES(0x0F, 0x88, 0xF8, 0xFF, 0xFF, 0xFF);
}

TEST_F(AssemblerTest, Jz) {
  ConditionCode cc = kZero;
  asm_.set_location(0xCAFEBABE);

  asm_.j(cc, ImmediateImpl(0xCAFEBABE, kSize8Bit, NULL));
  EXPECT_BYTES(0x74, 0xFE);
  asm_.j(cc, ImmediateImpl(0xCAFEBABE, kSize32Bit, NULL));
  EXPECT_BYTES(0x0F, 0x84, 0xF8, 0xFF, 0xFF, 0xFF);
}

TEST_F(AssemblerTest, Jnc) {
  ConditionCode cc = kNotCarry;
  asm_.set_location(0xCAFEBABE);

  asm_.j(cc, ImmediateImpl(0xCAFEBABE, kSize8Bit, NULL));
  EXPECT_BYTES(0x73, 0xFE);
  asm_.j(cc, ImmediateImpl(0xCAFEBABE, kSize32Bit, NULL));
  EXPECT_BYTES(0x0F, 0x83, 0xF8, 0xFF, 0xFF, 0xFF);
}

TEST_F(AssemblerTest, Jne) {
  ConditionCode cc = kNotEqual;
  asm_.set_location(0xCAFEBABE);

  asm_.j(cc, ImmediateImpl(0xCAFEBABE, kSize8Bit, NULL));
  EXPECT_BYTES(0x75, 0xFE);
  asm_.j(cc, ImmediateImpl(0xCAFEBABE, kSize32Bit, NULL));
  EXPECT_BYTES(0x0F, 0x85, 0xF8, 0xFF, 0xFF, 0xFF);
}

TEST_F(AssemblerTest, Jno) {
  ConditionCode cc = kNoOverflow;
  asm_.set_location(0xCAFEBABE);

  asm_.j(cc, ImmediateImpl(0xCAFEBABE, kSize8Bit, NULL));
  EXPECT_BYTES(0x71, 0xFE);
  asm_.j(cc, ImmediateImpl(0xCAFEBABE, kSize32Bit, NULL));
  EXPECT_BYTES(0x0F, 0x81, 0xF8, 0xFF, 0xFF, 0xFF);
}

TEST_F(AssemblerTest, Jns) {
  COMPILE_ASSERT(kNotSign == kPositive, kSignAndPositiveAreAliases);
  ConditionCode cc = kNotSign;
  asm_.set_location(0xCAFEBABE);

  asm_.j(cc, ImmediateImpl(0xCAFEBABE, kSize8Bit, NULL));
  EXPECT_BYTES(0x79, 0xFE);
  asm_.j(cc, ImmediateImpl(0xCAFEBABE, kSize32Bit, NULL));
  EXPECT_BYTES(0x0F, 0x89, 0xF8, 0xFF, 0xFF, 0xFF);
}

TEST_F(AssemblerTest, Jnz) {
  ConditionCode cc = kNotZero;
  asm_.set_location(0xCAFEBABE);

  asm_.j(cc, ImmediateImpl(0xCAFEBABE, kSize8Bit, NULL));
  EXPECT_BYTES(0x75, 0xFE);
  asm_.j(cc, ImmediateImpl(0xCAFEBABE, kSize32Bit, NULL));
  EXPECT_BYTES(0x0F, 0x85, 0xF8, 0xFF, 0xFF, 0xFF);
}

TEST_F(AssemblerTest, Seto) {
  asm_.set_location(0xCAFEBABE);
  asm_.set(kOverflow, core::eax);
  EXPECT_BYTES(0x0F, 0x90, 0xC0);
}

TEST_F(AssemblerTest, Setno) {
  asm_.set(kNoOverflow, core::ebx);
  EXPECT_BYTES(0x0F, 0x91, 0xC3);
}

TEST_F(AssemblerTest, Sete) {
  asm_.set(kEqual, core::eax);
  EXPECT_BYTES(0x0F, 0x94, 0xC0);
}

TEST_F(AssemblerTest, Setne) {
  asm_.set(kNotEqual, core::eax);
  EXPECT_BYTES(0x0F, 0x95, 0xC0);
}

TEST_F(AssemblerTest, Setb) {
  asm_.set(kBelow, core::eax);
  EXPECT_BYTES(0x0F, 0x92, 0xC0);
}

TEST_F(AssemblerTest, Loop) {
  asm_.set_location(0xCAFEBABE);

  asm_.loop(ImmediateImpl(0xCAFEBABE, kSize8Bit, NULL));
  EXPECT_BYTES(0xE2, 0xFE);
}

TEST_F(AssemblerTest, Loope) {
  asm_.set_location(0xCAFEBABE);

  asm_.loope(ImmediateImpl(0xCAFEBABE, kSize8Bit, NULL));
  EXPECT_BYTES(0xE1, 0xFE);
}

TEST_F(AssemblerTest, Loopne) {
  asm_.set_location(0xCAFEBABE);

  asm_.loopne(ImmediateImpl(0xCAFEBABE, kSize8Bit, NULL));
  EXPECT_BYTES(0xE0, 0xFE);
}

TEST_F(AssemblerTest, References) {
  // We arbitrarily use the MOV instruction to test reference propagation.
  static const int ref1 = 1;
  asm_.mov(eax, ImmediateImpl(0, kSize8Bit, &ref1));

  static const int ref2 = 2;
  asm_.mov(eax, OperandImpl(eax, ebx, kTimes4,
                            DisplacementImpl(0, kSize32Bit, &ref2)));

  static const int ref3 = 3;
  static const int ref4 = 4;
  asm_.mov(OperandImpl(eax, ebx, kTimes4,
                       DisplacementImpl(0, kSize32Bit, &ref3)),
           ImmediateImpl(0, kSize32Bit, &ref4));

  EXPECT_EQ(4, serializer_.references.size());

  EXPECT_EQ(1, serializer_.references[0].location);
  EXPECT_EQ(&ref1, serializer_.references[0].ref);

  EXPECT_EQ(8, serializer_.references[1].location);
  EXPECT_EQ(&ref2, serializer_.references[1].ref);

  EXPECT_EQ(15, serializer_.references[2].location);
  EXPECT_EQ(&ref3, serializer_.references[2].ref);

  EXPECT_EQ(19, serializer_.references[3].location);
  EXPECT_EQ(&ref4, serializer_.references[3].ref);
}

}  // namespace core
