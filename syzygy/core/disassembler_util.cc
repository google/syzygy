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

#include "base/logging.h"
#include "base/strings/stringprintf.h"
#include "mnemonics.h"  // NOLINT

namespace core {

namespace {

// Return the size of a 3-byte VEX encoded instruction.
//
// The layout of these instructions is as follows, starting with a byte with
// value 0xC4:
//     - First byte:
//         +---+---+---+---+---+---+---+---+
//         | 1   1   0   0   0   1   0   0 |
//         +---+---+---+---+---+---+---+---+
//     - Second byte:
//         +---+---+---+---+---+---+---+---+
//         |~R |~X |~B |     map_select    |
//         +---+---+---+---+---+---+---+---+
//     - Third byte:
//         +---+---+---+---+---+---+---+---+
//         |W/E|     ~vvvv     | L |   pp  |
//         +---+---+---+---+---+---+---+---+
//     - Fourth byte: The opcode for this instruction.
//
// |map_select| Indicates the opcode map that should be used for this
// instruction.
//
// See http://wiki.osdev.org/X86-64_Instruction_Encoding#Three_byte_VEX_escape_prefix
// for more details.
size_t Get3ByteVexEncodedInstructionSize(_CodeInfo* ci) {
  DCHECK_EQ(0xC4, ci->code[0]);
  // Switch case based on the opcode map used by this instruction.
  switch (ci->code[1] & 0x1F) {
    case 0x01: {
      switch (ci->code[3]) {
        case 0x1D: return 5;  // vpermd
        default: break;
      }
      break;
    }
    case 0x02: {
      switch (ci->code[3]) {
        case 0x13: return 5;  // vcvtps2ps
        case 0x36: return 5;  // vpermd
        case 0x5A: return 6;  // vbroadcasti128
        case 0x78: return 5;  // vpbroadcastb
        default: break;
      }
      break;
    }
    case 0x03: {
      switch (ci->code[3]) {
        case 0x00: return 6;  // vpermq
        case 0x1D: return 6;  // vcvtps2ph
        case 0x38: return 7;  // vinserti128
        case 0x39: return 6;  // vextracti128
        default: break;
      }
      break;
    }
    default:
      break;
  }
  return 0;
}

// Handle improperly decoded instructions. Returns true if an instruction was
// handled, false otherwise. If this returns false then none of the output
// parameters will have been changed.
bool HandleBadDecode(_CodeInfo* ci,
                     _DInst result[],
                     unsigned int max_instructions,
                     unsigned int* used_instructions_count,
                     _DecodeResult* ret) {
  DCHECK_NE(reinterpret_cast<_CodeInfo*>(NULL), ci);
  DCHECK_LE(1u, max_instructions);
  DCHECK_NE(reinterpret_cast<unsigned int*>(NULL), used_instructions_count);
  DCHECK_NE(reinterpret_cast<_DecodeResult*>(NULL), ret);

  size_t size = 0;

  if (ci->code[0] == 0xC4)
    size = Get3ByteVexEncodedInstructionSize(ci);

  if (size == 0)
    return false;

  // We set the bare minimum properties that are required for any
  // subsequent processing that we perform.

  *used_instructions_count = 1;

  ::memset(result, 0, sizeof(result[0]));
  result[0].addr = ci->codeOffset;
  result[0].size = static_cast<uint8_t>(size);

  DCHECK_EQ(FC_NONE, META_GET_FC(result[0].meta));
  DCHECK_EQ(O_NONE, result[0].ops[0].type);
  DCHECK_EQ(O_NONE, result[0].ops[1].type);
  DCHECK_EQ(O_NONE, result[0].ops[2].type);
  DCHECK_EQ(O_NONE, result[0].ops[3].type);

  *ret = DECRES_SUCCESS;

  return true;
}

}  // namespace

_DecodeResult DistormDecompose(_CodeInfo* ci,
                               _DInst result[],
                               unsigned int max_instructions,
                               unsigned int* used_instructions_count) {
  _DecodeResult ret =
      distorm_decompose(ci, result, max_instructions, used_instructions_count);

  // Distorm @ac277fb has a bug where it has problems decoding some AVX
  // instructions. The encoding is described in detail here:
  //   http://en.wikipedia.org/wiki/VEX_prefix
  // An issue has been filed here:
  //   https://code.google.com/p/distorm/issues/detail?id=77
  // This is a workaround until the bug is fixed. We only care about the case
  // where decoding failed.
  if (ret != DECRES_SUCCESS && *used_instructions_count == 0) {
    if (HandleBadDecode(ci, result, max_instructions, used_instructions_count,
                        &ret)) {
      return ret;
    }
  }

  for (unsigned int i = 0; i < *used_instructions_count; ++i) {
    switch (result[i].opcode) {
      // Distorm @ac277fb has a bug where the access size for I_FXRSTOR and
      // I_FXSAVE destination operand is 0 instead of 64. I've filed
      // https://github.com/gdabah/distorm/issues/96 to have this fixed.
      // In the meantime this is a workaround to have the correct operand size.
      case I_FXRSTOR:
      case I_FXSAVE:
        DCHECK_EQ(0U, result[i].ops[0].size);
        result[i].ops[0].size = 64;
        break;
      default:
        break;
    }
  }

  return ret;
}

bool DecodeOneInstruction(uint32_t address,
                          const uint8_t* buffer,
                          size_t length,
                          _DInst* instruction) {
  DCHECK(buffer != NULL);
  DCHECK(instruction != NULL);

  _CodeInfo code = {};
  code.dt = Decode32Bits;
  code.features = DF_NONE;
  code.codeOffset = address;
  code.codeLen = length;
  code.code = buffer;

  unsigned int decoded = 0;
  ::memset(instruction, 0, sizeof(*instruction));
  _DecodeResult result = DistormDecompose(&code, instruction, 1, &decoded);

  if (result != DECRES_MEMORYERR && result != DECRES_SUCCESS)
    return false;

  // It's possible for the decode to fail as having decoded a single partially
  // valid instruction (ie: valid prefix of an instruction, waiting on more
  // data), in which case it will return MEMORYERR (wants more data) and a
  // decoded length of zero.
  if (decoded == 0)
    return false;

  DCHECK_GE(length, instruction->size);
  DCHECK_LT(0, instruction->size);

  return true;
}

bool DecodeOneInstruction(const uint8_t* buffer,
                          size_t length,
                          _DInst* instruction) {
  DCHECK(buffer != NULL);
  DCHECK(instruction != NULL);
  if (!DecodeOneInstruction(0x10000000, buffer, length, instruction))
    return false;
  return true;
}

bool InstructionToString(
    const _DInst& instruction,
    const uint8_t* data,
    int code_length,
    std::string* buffer) {
  DCHECK(data != NULL);
  DCHECK(buffer != NULL);

  _CodeInfo code = {};
  code.codeOffset = 0;
  code.code = data;
  code.codeLen = code_length;
  code.dt = Decode32Bits;
  _DecodedInst decoded = {};
  _DInst dinst = instruction;

  dinst.addr = 0;
  distorm_format64(&code, &dinst, &decoded);

  *buffer = base::StringPrintf("%-14s %s %s",
                               decoded.instructionHex.p,
                               decoded.mnemonic.p,
                               decoded.operands.p);
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
  return META_GET_FC(instruction.meta) == FC_CALL;
}

bool IsReturn(const _DInst& instruction) {
  return META_GET_FC(instruction.meta) == FC_RET;
}

bool IsSystemCall(const _DInst& instruction) {
  return META_GET_FC(instruction.meta) == FC_SYS;
}

bool IsConditionalBranch(const _DInst& instruction) {
  return META_GET_FC(instruction.meta) == FC_CND_BRANCH;
}

bool IsUnconditionalBranch(const _DInst& instruction) {
  return META_GET_FC(instruction.meta) == FC_UNC_BRANCH;
}

bool IsBranch(const _DInst& instruction) {
  return IsConditionalBranch(instruction) || IsUnconditionalBranch(instruction);
}

bool HasPcRelativeOperand(const _DInst& instruction, int operand_index) {
  DCHECK_LE(0, operand_index);
  DCHECK_LT(operand_index, static_cast<int>(arraysize(instruction.ops)));
  return instruction.ops[operand_index].type == O_PC;
}

bool IsControlFlow(const _DInst& instruction) {
  // For the purposes of Syzygy we include all of the control flow altering
  // instruction EXCEPT for call as true control flow.
  return IsBranch(instruction) ||
      IsReturn(instruction) ||
      IsSystemCall(instruction);
}

bool IsImplicitControlFlow(const _DInst& instruction) {
  // Control flow jumps implicitly out of the block for RET and SYS
  if (IsReturn(instruction) || IsSystemCall(instruction))
    return true;

  // Control flow is implicit for non PC-relative jumps (i.e., explicit
  // branches where the target is computed, stored in a register, stored
  // in a memory location, or otherwise indirect).
  if (IsUnconditionalBranch(instruction) &&
      !HasPcRelativeOperand(instruction, 0)) {
    return true;
  }

  // Otherwise it's not implicit control flow.
  return false;
}

bool IsInterrupt(const _DInst& instruction) {
  return META_GET_FC(instruction.meta) == FC_INT;
}

bool IsDebugInterrupt(const _DInst& instruction) {
  return IsInterrupt(instruction) && instruction.size == 1 &&
      instruction.opcode == I_INT_3;
}

_RegisterType GetRegisterType(const Register& reg) {
  return GetRegisterType(reg.id());
}

_RegisterType GetRegisterType(RegisterId reg_id) {
  static const _RegisterType kRegisterTypesById[assm::kRegisterMax] = {
    R_AL,  R_CL,  R_DL,  R_BL,  R_AH,  R_CH,  R_DH,  R_BH,  // 8-bit.
    R_AX,  R_CX,  R_DX,  R_BX,  R_SP,  R_BP,  R_SI,  R_DI,  // 16-bit.
    R_EAX, R_ECX, R_EDX, R_EBX, R_ESP, R_EBP, R_ESI, R_EDI  // 32-bit.
  };
  DCHECK_LE(assm::kRegisterMin, reg_id);
  DCHECK_GT(assm::kRegisterMax, reg_id);
  return kRegisterTypesById[reg_id];
}

RegisterId GetRegisterId(uint32_t distorm_reg_type) {
  switch (distorm_reg_type) {
    // 8-bit registers.
    case R_AL: return assm::kRegisterAl;
    case R_CL: return assm::kRegisterCl;
    case R_DL: return assm::kRegisterDl;
    case R_BL: return assm::kRegisterBl;
    case R_AH: return assm::kRegisterAh;
    case R_CH: return assm::kRegisterCh;
    case R_DH: return assm::kRegisterDh;
    case R_BH: return assm::kRegisterBh;

    // 16-bit registers.
    case R_AX: return assm::kRegisterAx;
    case R_CX: return assm::kRegisterCx;
    case R_DX: return assm::kRegisterDx;
    case R_BX: return assm::kRegisterBx;
    case R_SP: return assm::kRegisterSp;
    case R_BP: return assm::kRegisterBp;
    case R_SI: return assm::kRegisterSi;
    case R_DI: return assm::kRegisterDi;

    // 32-bit registers.
    case R_EAX: return assm::kRegisterEax;
    case R_ECX: return assm::kRegisterEcx;
    case R_EDX: return assm::kRegisterEdx;
    case R_EBX: return assm::kRegisterEbx;
    case R_ESP: return assm::kRegisterEsp;
    case R_EBP: return assm::kRegisterEbp;
    case R_ESI: return assm::kRegisterEsi;
    case R_EDI: return assm::kRegisterEdi;

    default: return assm::kRegisterNone;
  }
}

const Register& GetRegister(uint32_t distorm_reg_type) {
  return Register::Get(GetRegisterId(distorm_reg_type));
}

}  // namespace core
