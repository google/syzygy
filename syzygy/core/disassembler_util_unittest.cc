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

// Interrupts.
const uint8 kInt2[] = { 0xCD, 0x02 };
const uint8 kInt3[] = { 0xCC };

}  // namespace

TEST(DisassemblerUtilTest, DistormWrapperVxorpsPasses) {
  _DInst inst = {};
  EXPECT_TRUE(DecodeOneInstruction(kVxorps, sizeof(kVxorps), &inst));
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

}  // namespace core
