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

#include "syzygy/core/disassembler_util.h"

#include "base/logging.h"
#include "mnemonics.h"  // NOLINT

namespace core {

bool DecodeOneInstruction(
    uint32 address, const uint8* buffer, size_t length, _DInst* instruction) {
  DCHECK(buffer != NULL);
  DCHECK(instruction != NULL);

  _CodeInfo code = {};
  code.dt = Decode32Bits;
  code.features = DF_NONE;
  code.codeOffset = address;
  code.codeLen = length;
  code.code = buffer;

  unsigned int decoded = 0;
  ::memset(instruction, 0, sizeof(instruction));
  _DecodeResult result = distorm_decompose(&code, instruction, 1, &decoded);

  if (result != DECRES_MEMORYERR && result != DECRES_SUCCESS)
    return false;

  DCHECK_EQ(1u, decoded);
  DCHECK_GE(length, instruction->size);
  DCHECK_LT(0, instruction->size);

  return true;
}

bool DecodeOneInstruction(
    const uint8* buffer, size_t length, _DInst* instruction) {
  DCHECK(buffer != NULL);
  DCHECK(instruction != NULL);
  if (!DecodeOneInstruction(0x10000000, buffer, length, instruction))
    return false;
  return true;
}

bool IsNop(const _DInst& instruction) {
  switch (instruction.opcode) {
    default:
      // Only the sequences recognized below qualify as NOP instructions.
      return false;

    case I_XCHG:
      // This handles the 1 bytes NOP sequence.
      //     1-byte: xchg eax, eax.
      return instruction.ops[0].type == O_REG &&
          instruction.ops[0].index == RM_AX &&
          instruction.ops[1].type == O_REG &&
          instruction.ops[1].index == RM_AX;

    case I_NOP:
      // This handles the 2, 4, 5, 7, 8 and 9 byte NOP sequences.
      //     2-byte: 66 NOP
      //     4-byte: NOP DWORD PTR [EAX + 0] (8-bit displacement)
      //     5-byte: NOP DWORD PTR [EAX + EAX*1 + 0] (8-bit displacement)
      //     7-byte: NOP DWORD PTR [EAX + 0] (32-bit displacement)
      //     8-byte: NOP DWORD PTR [EAX + EAX*1 + 0] (32-bit displacement)
      //     9-byte: NOP WORD PTR [EAX + EAX*1 + 0] (32-bit displacement)
      return true;

    case I_LEA:
      // This handles the 3 and 6 byte NOP sequences.
      //     3-byte: LEA REG, 0 (REG) (8-bit displacement)
      //     6-byte: LEA REG, 0 (REG) (32-bit displacement)
      return instruction.ops[0].type == O_REG &&
          instruction.ops[1].type == O_SMEM &&
          instruction.ops[0].index == instruction.ops[1].index &&
          instruction.disp == 0;

    case I_MOV:
      // Not documented in the Intel manuals, but we see "mov reg, reg" a lot.
      return instruction.ops[0].type == O_REG &&
          instruction.ops[1].type == O_REG &&
          instruction.ops[0].index == instruction.ops[1].index;
  }
}

bool IsCall(const _DInst& instruction) {
  uint8 fc = META_GET_FC(instruction.meta);
  if (fc == FC_CALL)
    return true;
  return false;
}

bool IsControlFlow(const _DInst& instruction) {
  uint8 fc = META_GET_FC(instruction.meta);
  if (fc == FC_CND_BRANCH || fc == FC_UNC_BRANCH ||
      fc == FC_RET || fc == FC_SYS) {
    return true;
  }
  return false;
}

bool IsImplicitControlFlow(const _DInst& instruction) {
  uint8 fc = META_GET_FC(instruction.meta);
  if (fc == FC_RET || fc == FC_SYS) {
    // Control flow jumps implicitly out of the block.
    return true;
  } else if (fc == FC_UNC_BRANCH && instruction.ops[0].type != O_PC) {
    // There is an explicit branch but the target is not explicitly given as
    // a PC relative value (i.e., the target is computed, stored in a register,
    // stored in a memory location, or otherwise indirect).
    return true;
  }
  return false;
}

bool IsInterrupt(const _DInst& instruction) {
  return META_GET_FC(instruction.meta) == FC_INT;
}

bool IsDebugInterrupt(const _DInst& instruction) {
  return IsInterrupt(instruction) && instruction.size == 1 &&
      instruction.opcode == I_INT_3;
}

}  // namespace core
