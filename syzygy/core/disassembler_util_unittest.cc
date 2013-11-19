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

#include "syzygy/core/disassembler_util.h"

#include "base/basictypes.h"
#include "base/logging.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace core {

namespace {

// Decompose a block of code using distorm wrapper.
_DecodeResult DecomposeCode(const uint8* code_data,
                            size_t length,
                            _DInst result[],
                            const unsigned int max_results,
                            unsigned int* result_count) {
  _CodeInfo code = {};
  code.dt = Decode32Bits;
  code.features = DF_NONE;
  code.codeOffset = 0;
  code.codeLen = length;
  code.code = code_data;
  return DistormDecompose(&code, result, max_results, result_count);
}

// Decompose a block of code using distorm directly.
_DecodeResult RawDecomposeCode(const uint8* code_data,
                               size_t length,
                               _DInst result[],
                               const unsigned int max_results,
                               unsigned int* result_count) {
  _CodeInfo code = {};
  code.dt = Decode32Bits;
  code.features = DF_NONE;
  code.codeOffset = 0;
  code.codeLen = length;
  code.code = code_data;
  return distorm_decompose(&code, result, max_results, result_count);
}

_DInst DecodeBuffer(const uint8* buffer, size_t length) {
  _DInst inst = {};
  EXPECT_TRUE(DecodeOneInstruction(buffer, length, &inst));
  EXPECT_EQ(length, inst.size);
  return inst;
}

// One of the AVX instructions that is currently not supported by distorm.
// vxorps ymm0, ymm0, ymm0
const uint8 kVxorps[] = { 0xC5, 0xFC, 0x57, 0xC0 };

// Instructions for which distorm indicates a size of 0 for the destination
// operand size.
// fnstcw m16
const uint8 kFnstcw[] = { 0xD9, 0x7D, 0xEA };
// fldcw m16
const uint8 kFldcw[] = { 0xD9, 0x6D, 0xE4 };

// Instructions for which distorm do not activated the write flag.
// fst qword ptr [0A374E8h]
const uint8 kFst[] = { 0xDD, 0x15, 0xE8, 0x74, 0xA3, 0x00 };
// fstp qword ptr [0A374E8h]
const uint8 kFstp[] = { 0xDD, 0x1D, 0xE8, 0x74, 0xA3, 0x00 };
// fist qword ptr [0A374E8h]
const uint8 kFist[] = { 0xDB, 0x15, 0xE0, 0x74, 0xA3, 0x00 };
// fistp qword ptr [0A374E8h]
const uint8 kFistp[] = { 0xDB, 0x1D, 0xE0, 0x74, 0xA3, 0x00 };

// Nop Instruction byte sequences.
const uint8 kNop2Mov[] = { 0x8B, 0xFF };
const uint8 kNop3Lea[] = { 0x8D, 0x49, 0x00 };
const uint8 kNop1[] = { 0x90 };
const uint8 kNop2[] = { 0x66, 0x90 };
const uint8 kNop3[] = { 0x66, 0x66, 0x90 };
const uint8 kNop4[] = { 0x0F, 0x1F, 0x40, 0x00 };
const uint8 kNop5[] = { 0x0F, 0x1F, 0x44, 0x00, 0x00 };
const uint8 kNop6[] = { 0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00 };
const uint8 kNop7[] = { 0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00 };
const uint8 kNop8[] = { 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00 };
const uint8 kNop9[] = {
    0x66,  // Prefix,
    0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00  // kNop8.
};
const uint8 kNop10[] = {
    0x66, 0x66,  // Prefix.
    0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00  // kNop8.
};
const uint8 kNop11[] = {
    0x66, 0x66, 0x66,  // Prefix.
    0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00  // kNop8
};

// Call instruction.
const uint8 kCall[] = { 0xE8, 0xCA, 0xFE, 0xBA, 0xBE };

// Control Flow byte sequences (note that the JMP is indirect).
const uint8 kJmp[] = { 0xFF, 0x24, 0x8D, 0xCA, 0xFE, 0xBA, 0xBE };
const uint8 kRet[] = { 0xC3 };
const uint8 kRetN[] = { 0xC2, 0x08, 0x00 };
const uint8 kJe[] = { 0x74, 0xCA };
const uint8 kSysEnter[] = { 0x0F, 0x34 };
const uint8 kSysExit[] = { 0x0F, 0x35 };

// Interrupts.
const uint8 kInt2[] = { 0xCD, 0x02 };
const uint8 kInt3[] = { 0xCC };

// Improperly handled instructions.
const uint8 kVpermq[] = { 0xC4, 0xE3, 0xFD, 0x00, 0xED, 0x44 };
const uint8 kVpermd[] = { 0xC4, 0xE2, 0x4D, 0x36, 0xC0 };

void TestBadlyDecodedInstruction(const uint8* code, size_t code_length) {
  _DInst inst[1] = {};
  unsigned int inst_count = 0;
  _DecodeResult result = RawDecomposeCode(
      code, code_length, inst, arraysize(inst), &inst_count);
  EXPECT_EQ(DECRES_MEMORYERR, result);
  EXPECT_EQ(0u, inst_count);

  result = DecomposeCode(
      code, code_length, inst, arraysize(inst), &inst_count);
  EXPECT_EQ(DECRES_SUCCESS, result);
  EXPECT_EQ(1u, inst_count);
  EXPECT_EQ(code_length, inst[0].size);
}

}  // namespace

TEST(DisassemblerUtilTest, DistormWrapperVxorpsPasses) {
  _DInst inst = {};
  EXPECT_TRUE(DecodeOneInstruction(kVxorps, sizeof(kVxorps), &inst));
}

TEST(DisassemblerUtilTest, InstructionToString) {
  _DInst inst = {};
  inst = DecodeBuffer(kNop1, sizeof(kNop1));

  std::string Nop1Str;
  EXPECT_TRUE(InstructionToString(inst, kNop1, sizeof(kNop1), &Nop1Str));
  ASSERT_THAT(Nop1Str, testing::HasSubstr("90"));
  ASSERT_THAT(Nop1Str, testing::HasSubstr("NOP"));
}

TEST(DisassemblerUtilTest, IsNop) {
  EXPECT_FALSE(IsNop(DecodeBuffer(kJmp, sizeof(kJmp))));
  EXPECT_TRUE(IsNop(DecodeBuffer(kNop1, sizeof(kNop1))));
  EXPECT_TRUE(IsNop(DecodeBuffer(kNop2, sizeof(kNop2))));
  EXPECT_TRUE(IsNop(DecodeBuffer(kNop3, sizeof(kNop3))));
  EXPECT_TRUE(IsNop(DecodeBuffer(kNop4, sizeof(kNop4))));
  EXPECT_TRUE(IsNop(DecodeBuffer(kNop5, sizeof(kNop5))));
  EXPECT_TRUE(IsNop(DecodeBuffer(kNop6, sizeof(kNop6))));
  EXPECT_TRUE(IsNop(DecodeBuffer(kNop7, sizeof(kNop7))));
  EXPECT_TRUE(IsNop(DecodeBuffer(kNop8, sizeof(kNop8))));
  EXPECT_TRUE(IsNop(DecodeBuffer(kNop9, sizeof(kNop9))));
  EXPECT_TRUE(IsNop(DecodeBuffer(kNop10, sizeof(kNop10))));
  EXPECT_TRUE(IsNop(DecodeBuffer(kNop11, sizeof(kNop11))));
  EXPECT_TRUE(IsNop(DecodeBuffer(kNop2Mov, sizeof(kNop2Mov))));
  EXPECT_TRUE(IsNop(DecodeBuffer(kNop3Lea, sizeof(kNop3Lea))));
}

TEST(DisassemblerUtilTest, IsCall) {
  EXPECT_FALSE(IsCall(DecodeBuffer(kJmp, sizeof(kJmp))));
  EXPECT_FALSE(IsCall(DecodeBuffer(kNop1, sizeof(kNop1))));
  EXPECT_TRUE(IsCall(DecodeBuffer(kCall, sizeof(kCall))));
}

TEST(DisassemblerUtilTest, IsSystemCall) {
  EXPECT_FALSE(IsSystemCall(DecodeBuffer(kJmp, sizeof(kJmp))));
  EXPECT_FALSE(IsSystemCall(DecodeBuffer(kNop1, sizeof(kNop1))));
  EXPECT_TRUE(IsSystemCall(DecodeBuffer(kSysEnter, sizeof(kSysEnter))));
  EXPECT_TRUE(IsSystemCall(DecodeBuffer(kSysExit, sizeof(kSysExit))));
}

TEST(DisassemblerUtilTest, IsConditionalBranch) {
  EXPECT_FALSE(IsConditionalBranch(DecodeBuffer(kNop4, sizeof(kNop4))));
  EXPECT_FALSE(IsConditionalBranch(DecodeBuffer(kJmp, sizeof(kJmp))));
  EXPECT_FALSE(IsConditionalBranch(DecodeBuffer(kRet, sizeof(kRet))));
  EXPECT_TRUE(IsConditionalBranch(DecodeBuffer(kJe, sizeof(kJe))));
}

TEST(DisassemblerUtilTest, IsUnconditionalBranch) {
  EXPECT_FALSE(IsUnconditionalBranch(DecodeBuffer(kNop4, sizeof(kNop4))));
  EXPECT_FALSE(IsUnconditionalBranch(DecodeBuffer(kRet, sizeof(kRet))));
  EXPECT_FALSE(IsUnconditionalBranch(DecodeBuffer(kJe, sizeof(kJe))));
  EXPECT_TRUE(IsUnconditionalBranch(DecodeBuffer(kJmp, sizeof(kJmp))));
}

TEST(DisassemblerUtilTest, IsBranch) {
  EXPECT_FALSE(IsBranch(DecodeBuffer(kNop4, sizeof(kNop4))));
  EXPECT_FALSE(IsBranch(DecodeBuffer(kRet, sizeof(kRet))));
  EXPECT_TRUE(IsBranch(DecodeBuffer(kJe, sizeof(kJe))));
  EXPECT_TRUE(IsBranch(DecodeBuffer(kJmp, sizeof(kJmp))));
}

TEST(DisassemblerUtilTest, HasPcRelativeOperand) {
  EXPECT_FALSE(HasPcRelativeOperand(DecodeBuffer(kRetN, sizeof(kRet)), 0));
  EXPECT_FALSE(HasPcRelativeOperand(DecodeBuffer(kJmp, sizeof(kJmp)), 0));
  EXPECT_TRUE(HasPcRelativeOperand(DecodeBuffer(kJe, sizeof(kJe)), 0));
}

TEST(DisassemblerUtilTest, IsControlFlow) {
  EXPECT_FALSE(IsControlFlow(DecodeBuffer(kNop4, sizeof(kNop4))));
  EXPECT_TRUE(IsControlFlow(DecodeBuffer(kJmp, sizeof(kJmp))));
  EXPECT_TRUE(IsControlFlow(DecodeBuffer(kRet, sizeof(kRet))));
  EXPECT_TRUE(IsControlFlow(DecodeBuffer(kRetN, sizeof(kRetN))));
  EXPECT_TRUE(IsControlFlow(DecodeBuffer(kJe, sizeof(kJe))));
  EXPECT_TRUE(IsControlFlow(DecodeBuffer(kSysEnter, sizeof(kSysEnter))));
}

TEST(DisassemblerUtilTest, IsImplicitControlFlow) {
  EXPECT_FALSE(IsImplicitControlFlow(DecodeBuffer(kJe, sizeof(kJe))));
  EXPECT_TRUE(IsImplicitControlFlow(DecodeBuffer(kRet, sizeof(kRet))));
  EXPECT_TRUE(IsImplicitControlFlow(DecodeBuffer(kRetN, sizeof(kRetN))));
  EXPECT_TRUE(IsImplicitControlFlow(DecodeBuffer(kJmp, sizeof(kJmp))));
}

TEST(DisassemblerUtilTest, IsInterrupt) {
  EXPECT_FALSE(IsInterrupt(DecodeBuffer(kJe, sizeof(kJe))));
  EXPECT_TRUE(IsInterrupt(DecodeBuffer(kInt2, sizeof(kInt2))));
  EXPECT_TRUE(IsInterrupt(DecodeBuffer(kInt3, sizeof(kInt3))));
}

TEST(DisassemblerUtilTest, IsDebugInterrupt) {
  EXPECT_FALSE(IsDebugInterrupt(DecodeBuffer(kJe, sizeof(kJe))));
  EXPECT_FALSE(IsDebugInterrupt(DecodeBuffer(kInt2, sizeof(kInt2))));
  EXPECT_TRUE(IsDebugInterrupt(DecodeBuffer(kInt3, sizeof(kInt3))));
}

TEST(DisassemblerUtilTest, GetRegisterType) {
  EXPECT_EQ(R_DL, GetRegisterType(core::kRegisterDl));
  EXPECT_EQ(R_AX, GetRegisterType(core::kRegisterAx));
  EXPECT_EQ(R_EDI, GetRegisterType(core::kRegisterEdi));

  EXPECT_EQ(R_BH, GetRegisterType(core::bh));
  EXPECT_EQ(R_CX, GetRegisterType(core::cx));
  EXPECT_EQ(R_ESP, GetRegisterType(core::esp));
}

TEST(DisassemblerUtilTest, GetRegisterId) {
  EXPECT_EQ(kRegisterAl, GetRegisterId(R_AL));
  EXPECT_EQ(kRegisterSp, GetRegisterId(R_SP));
  EXPECT_EQ(kRegisterEdi, GetRegisterId(R_EDI));
}

TEST(DisassemblerUtilTest, GetRegister) {
  EXPECT_EQ(core::bh, GetRegister(R_BH));
  EXPECT_EQ(core::cx, GetRegister(R_CX));
  EXPECT_EQ(core::ebp, GetRegister(R_EBP));
}

TEST(DisassemblerUtilTest, DistormDecompose) {
  const unsigned int kMaxResults = 16;
  unsigned int result_count = 0;
  _DInst results[kMaxResults];
  EXPECT_EQ(DECRES_SUCCESS,
            DecomposeCode(kNop3Lea,
                          sizeof(kNop3Lea),
                          results,
                          kMaxResults,
                          &result_count));
  EXPECT_EQ(1U, result_count);
  EXPECT_EQ(32U, results[0].ops[0].size);
}

TEST(DisassemblerUtilTest, DistormDecomposeFnstcw) {
  const unsigned int kMaxResults = 16;
  unsigned int result_count = 0;
  _DInst results[kMaxResults];
  EXPECT_EQ(DECRES_SUCCESS,
            DecomposeCode(kFnstcw,
                          sizeof(kFnstcw),
                          results,
                          kMaxResults,
                          &result_count));
  EXPECT_EQ(1U, result_count);
  EXPECT_EQ(16U, results[0].ops[0].size);
}

TEST(DisassemblerUtilTest, WrongAccessSizeOnRawDistormDecomposeFnstcw) {
  const unsigned int kMaxResults = 16;
  unsigned int result_count = 0;
  _DInst results[kMaxResults];
  EXPECT_EQ(DECRES_SUCCESS,
            RawDecomposeCode(kFldcw,
                             sizeof(kFldcw),
                             results,
                             kMaxResults,
                             &result_count));
  EXPECT_EQ(1U, result_count);
  EXPECT_EQ(0U, results[0].ops[0].size);
}

TEST(DisassemblerUtilTest, DistormDecomposeFldcw) {
  const unsigned int kMaxResults = 16;
  unsigned int result_count = 0;
  _DInst results[kMaxResults];
  EXPECT_EQ(DECRES_SUCCESS,
            DecomposeCode(kFldcw,
                          sizeof(kFldcw),
                          results,
                          kMaxResults,
                          &result_count));
  EXPECT_EQ(1U, result_count);
  EXPECT_EQ(16U, results[0].ops[0].size);
}

TEST(DisassemblerUtilTest, WrongAccessSizeOnRawDistormDecomposeFldcw) {
  const unsigned int kMaxResults = 16;
  unsigned int result_count = 0;
  _DInst results[kMaxResults];
  EXPECT_EQ(DECRES_SUCCESS,
            RawDecomposeCode(kFldcw,
                             sizeof(kFldcw),
                             results,
                             kMaxResults,
                             &result_count));
  EXPECT_EQ(1U, result_count);
  EXPECT_EQ(0U, results[0].ops[0].size);
}

TEST(DisassemblerUtilTest, WrongWriteFlagOnRawDistormDecomposeFst) {
  _DInst fst = DecodeBuffer(kFst, sizeof(kFst));
  EXPECT_NE(0, fst.flags & FLAG_DST_WR);

  _DInst fstp = DecodeBuffer(kFstp, sizeof(kFstp));
  EXPECT_NE(0, fstp.flags & FLAG_DST_WR);

  _DInst fist = DecodeBuffer(kFist, sizeof(kFist));
  EXPECT_NE(0, fist.flags & FLAG_DST_WR);

  _DInst fistp = DecodeBuffer(kFistp, sizeof(kFistp));
  EXPECT_NE(0, fistp.flags & FLAG_DST_WR);
}

// If this test starts failing then Distorm now properly handles the vpermq
// instruction. Please remove the workaround in disassembler_util.cc.
TEST(DisassemblerUtilTest, TestBadlyDecodedVpermq) {
  EXPECT_NO_FATAL_FAILURE(TestBadlyDecodedInstruction(
      kVpermq, sizeof(kVpermq)));
}

// If this test starts failing then Distorm now properly handles the vpermd
// instruction. Please remove the workaround in disassembler_util.cc.
TEST(DisassemblerUtilTest, TestBadlyDecodedVpermd) {
  EXPECT_NO_FATAL_FAILURE(TestBadlyDecodedInstruction(
      kVpermd, sizeof(kVpermd)));
}

}  // namespace core
