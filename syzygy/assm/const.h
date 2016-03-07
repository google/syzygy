// Copyright 2014 Google Inc. All Rights Reserved.
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

#ifndef SYZYGY_ASSM_CONST_H_
#define SYZYGY_ASSM_CONST_H_

namespace assm {

enum Mod {
  kReg1Ind = 0,  // Register indirect mode.
  kReg1ByteDisp = 1,  // Register + byte displacement.
  kReg1WordDisp = 2,  // Register + word displacement.
  kReg1 = 3,  // Register itself.
};

// The code that AL/AX/EAX/RAX registers all map to. There are special encodings
// for arithmetic instructions with this register as the destination.
static const RegisterCode kAccumulatorCode = Register::Code(kRegisterEax);

const uint8_t kTwoByteOpCodePrefix = 0x0F;
// Prefix group 2 (segment selection).
const uint8_t kFsSegmentPrefix = 0x64;
// Prefix group 3 (operand size override).
const uint8_t kOperandSizePrefix = 0x66;

// Some opcodes that are used repeatedly.
const uint8_t kNopOpCode = 0x1F;

const size_t kShortBranchOpcodeSize = 1;
const size_t kShortBranchSize = kShortBranchOpcodeSize + 1;

const size_t kLongBranchOpcodeSize = 2;
const size_t kLongBranchSize = kLongBranchOpcodeSize + 4;

const size_t kShortJumpOpcodeSize = 1;
const size_t kShortJumpSize = kShortJumpOpcodeSize + 1;

const size_t kLongJumpOpcodeSize = 1;
const size_t kLongJumpSize = kLongJumpOpcodeSize + 4;

// The maximum length a single instruction will assemble to.
// No instruction on x86 can exceed 15 bytes, per specs.
static const size_t kMaxInstructionLength = 15;

}  // namespace assm

#endif  // SYZYGY_ASSM_CONST_H_
