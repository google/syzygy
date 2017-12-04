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

#include <algorithm>

#include "base/logging.h"
#include "base/strings/stringprintf.h"
#include "mnemonics.h"  // NOLINT

namespace core {

namespace {

// Opcode of the 3-byte VEX instructions.
const uint8_t kThreeByteVexOpcode = 0xC4;

// Structure representing a Mod R/M byte, it has the following format:
//         +---+---+---+---+---+---+---+---+
//         |  mod  |reg/opcode |    r/m    |
//         +---+---+---+---+---+---+---+---+
//
// Here's a description of the different fields (from
// https://en.wikipedia.org/wiki/VEX_prefix):
//   - mod: combined with the r/m field, encodes either 8 registers or 24
//     addressing modes. Also encodes opcode information for some
//     instructions.
//   - reg/opcode: specifies either a register or three more bits of
//     opcode information, as specified in the primary opcode byte.
//   - r/m: can specify a register as an operand, or combine with the mod
//     field to encode an addressing mode.
//
// The |mod| field can have the following values:
//   - 0b00: Register indirect addressing mode or SIB with no displacement
//     (if r/m = 0b100) or displacement only addressing mode (if r/m = 0b101).
//   - 0b01: One-byte signed displacement follows addressing mode byte(s).
//   - 0b10: Four-byte signed displacement follows addressing mode byte(s).
//   - 0b11: Register addressing mode.
struct ModRMByte {
  // Constructor.
  // @param value The Value used to initialize this Mod R/M byte.
  explicit ModRMByte(uint8_t value) : raw_value(value) {}

  union {
    uint8_t raw_value;
    struct {
      uint8_t r_m : 3;
      uint8_t reg_or_opcode : 3;
      uint8_t mod : 2;
    };
  };
};

// Calculates the number of bytes used to encode a Mod R/M operand.
// @param ci The code information for this instruction.
// @param has_register_addressing_mode Indicates if the instruction supports
//     the register addressing mode (value of |mod| of 0b11).
// @returns the total size of this Mod R/M operand (in bytes), 0 on failure.
size_t GetModRMOperandBytesSize(const _CodeInfo* ci,
                                bool has_register_addressing_mode) {
  DCHECK_GE(ci->codeLen, 5);

  // If SIB (Scale*Index+Base) is specified then the operand uses an
  // additional SIB byte.
  const uint8_t kSIBValue = 0b100;
  ModRMByte modRM_byte(ci->code[4]);

  switch (modRM_byte.mod) {
    case 0b00: {
      if (modRM_byte.r_m == kSIBValue) {
        CHECK_GE(ci->codeLen, 6);
        // The SIB byte has the following layout:
        //     +---+---+---+---+---+---+---+---+
        //     | scale |   index   |    base   |
        //     +---+---+---+---+---+---+---+---+
        //
        // If |base| = 5 then there's an additional 4 bytes used to encode the
        // displacement, e.g.:
        // vpbroadcastd ymm0, DWORD PTR [ebp+eax*8+0x76543210]
        const uint8_t kSIBBaseMask = 0b111;
        if ((ci->code[5] & kSIBBaseMask) == 5)
          return 6;
        // If |base| != 5 then there's just the SIB byte, e.g.:
        // vpbroadcastd ymm0, DWORD PTR [ecx+edx*1]
        return 2;
      }
      if (modRM_byte.r_m == 0b101) {
        // Displacement only addressing mode, e.g.:
        // vpbroadcastb xmm2, BYTE PTR ds:0x12345678
        return 5;
      }
      // Register indirect addressing mode, e.g.:
      // vpbroadcastb xmm2, BYTE PTR [eax]
      return 1;
    }
    case 0b01: {
      // One-byte displacement.
      if (modRM_byte.r_m == kSIBValue) {
        // Additional SIB byte, e.g.:
        // vpbroadcastb xmm2, BYTE PTR [eax+edx*1+0x42]
        return 3;
      }
      // No SIB byte, e.g.:
      // vpbroadcastb xmm2, BYTE PTR [eax+0x42]
      return 2;
    }
    case 0b10: {
      // One-byte displacement.
      if (modRM_byte.r_m == kSIBValue) {
        // Additional SIB byte, e.g.:
        // vpbroadcastb xmm0, BYTE PTR [edx+edx*1+0x12345678]
        return 6;
      }
      // No SIB byte, e.g.:
      // vpbroadcastb xmm0, BYTE PTR [eax+0x34567812]
      return 5;
    }
    case 0b11:
      // Register addressing mode, e.g.:
      // vpbroadcastb xmm2, BYTE PTR [eax]
      if (has_register_addressing_mode)
        return 1;
      LOG(ERROR) << "Unexpected |mod| value of 0b11 for an instruction that "
                 << "doesn't support it.";
      return 0;
    default:
      NOTREACHED();
  }

  return 0;
}

// Structure representing a 3-byte VEX encoded instruction.
//
// The layout of these instructions is as follows, starting with a byte with
// value 0xC4:
//     - Opcode indicating that this is a 3-byte VEX instruction:
//         +---+---+---+---+---+---+---+---+
//         | 1   1   0   0   0   1   0   0 |
//         +---+---+---+---+---+---+---+---+
//     - First byte:
//         +---+---+---+---+---+---+---+---+
//         |~R |~X |~B |     map_select    |
//         +---+---+---+---+---+---+---+---+
//     - Second byte:
//         +---+---+---+---+---+---+---+---+
//         |W/E|     ~vvvv     | L |   pp  |
//         +---+---+---+---+---+---+---+---+
//     - Third byte: The opcode for this instruction.
//
// If this instructions takes some operands then it's followed by a ModR/M byte
// and some optional bytes to represent the operand. We don't represent these
// optional bytes here.
//
// See
// http://wiki.osdev.org/X86-64_Instruction_Encoding#Three_byte_VEX_escape_prefix
// for more details.
struct ThreeBytesVexInstruction {
  explicit ThreeBytesVexInstruction(const uint8_t* data) {
    DCHECK_NE(nullptr, data);
    CHECK_EQ(kThreeByteVexOpcode, data[0]);
    first_byte = data[1];
    second_byte = data[2];
    opcode = data[3];
  }

  // Checks if this instruction match the expectations that we have for it.
  //
  // It compares the value of several fields that can have an impact on the
  // instruction size and make sure that they have the expected value.
  //
  // @param expected_inv_rxb The expected value for |inv_rxb|.
  // @param expected_we The expected value for |we|.
  // @returns true if all the expectations are met, false otherwise.
  bool MatchExpectations(uint8_t expected_inv_rxb,
                         uint8_t expected_we,
                         const char* instruction);

  // First byte, contains the RXB value and map_select.
  union {
    uint8_t first_byte;
    struct {
      uint8_t map_select : 5;
      uint8_t inv_rxb : 3;
    };
  };
  // Second byte, contains the W/E, ~vvvv, L and pp values.
  union {
    uint8_t second_byte;
    struct {
      // Implied mandatory prefix:
      //   +-------+--------------------------+
      //   | value | Implied mandatory prefix |
      //   +-------+--------------------------+
      //   | 0b00  | none                     |
      //   | 0b01  | 0x66                     |
      //   | 0b10  | 0xF3                     |
      //   | 0b11  | 0xF2                     |
      //   +-------+--------------------------+
      uint8_t pp : 2;
      // Vector length.
      uint8_t l : 1;
      // Additional operand.
      uint8_t inv_vvvv : 4;
      // 64-bit operand size / general opcode extension bit.
      uint8_t w_e : 1;
    };
  };

  // Opcode of this instruction.
  uint8_t opcode;
};

// Checks if |value| is equal to |expected| value and log verbosely if it's not
// the case.
bool CheckField(uint8_t expected_value,
                uint8_t value,
                const char* field_name,
                const char* instruction) {
  if (expected_value != value) {
    LOG(ERROR) << "Unexpected " << field_name << " value for the "
               << instruction << " instruction, expecting 0x" << std::hex
               << static_cast<size_t>(expected_value) << " but got 0x"
               << static_cast<size_t>(value) << "." << std::dec;
    return false;
  }
  return true;
}

bool ThreeBytesVexInstruction::MatchExpectations(uint8_t expected_inv_rxb,
                                                 uint8_t expected_we,
                                                 const char* instruction) {
  if (!CheckField(expected_inv_rxb, inv_rxb, "inv_rxb", instruction))
    return false;
  if (!CheckField(expected_we, w_e, "we", instruction))
    return false;
  return true;
}

// Returns the size of a 3-byte VEX encoded instruction.
//
// NOTE: We only support the instructions that have been encountered in Chrome
// and there's some restrictions on which variants of these instructions are
// supported.
size_t Get3ByteVexEncodedInstructionSize(_CodeInfo* ci) {
  // A 3-byte VEX instructions has always a size of 5 bytes or more (the C4
  // constant, the 3 VEX bytes and the mod R/M byte).
  DCHECK_GE(ci->codeLen, 5);

  ThreeBytesVexInstruction instruction(ci->code);

  const size_t kBaseSize = 4;
  size_t operand_size = 0;
  size_t constants_size = 0;

  // Switch case based on the opcode used by this instruction.
  //
  // The different opcodes and their encoding is described in the "Intel
  // Architecture Instruction Set Extensions Programming Reference" document.
  switch (instruction.map_select) {
    case 0x02: {
      switch (instruction.opcode) {
        case 0x13:  // vcvtph2ps
          if (instruction.MatchExpectations(0b111, 0, "vcvtph2ps"))
            operand_size = GetModRMOperandBytesSize(ci, true);
          break;
        case 0x18:  // vbroadcastss
          if (instruction.MatchExpectations(0b111, 0, "vbroadcastss"))
            operand_size = GetModRMOperandBytesSize(ci, true);
          break;
        case 0x36:  // vpermd
          if (instruction.MatchExpectations(0b111, 0, "vpermd"))
            operand_size = GetModRMOperandBytesSize(ci, true);
          break;
        case 0x58:  // vpbroadcastd
          if (instruction.MatchExpectations(0b111, 0, "vpbroadcastd"))
            operand_size = GetModRMOperandBytesSize(ci, true);
          break;
        case 0x5A:  // vbroadcasti128
          if (instruction.MatchExpectations(0b111, 0, "vbroadcasti128"))
            operand_size = GetModRMOperandBytesSize(ci, false);
          break;
        case 0x78:  // vpbroadcastb
          if (instruction.MatchExpectations(0b111, 0, "vpbroadcastb"))
            operand_size = GetModRMOperandBytesSize(ci, true);
          break;
        case 0x79:  // vpbroadcastw
          if (instruction.MatchExpectations(0b111, 0, "vpbroadcastw"))
            operand_size = GetModRMOperandBytesSize(ci, true);
          break;
        case 0x8C:  // vpmaskmovd
          if (instruction.MatchExpectations(0b111, 0, "vpmaskmovd"))
            operand_size = GetModRMOperandBytesSize(ci, false);
          break;
        case 0x90:  // vpgatherdd
          if (instruction.MatchExpectations(0b111, 0, "vpgatherdd"))
            operand_size = GetModRMOperandBytesSize(ci, false);
          break;
        case 0xF7:  // bextr/shlx/sarx/shrx
          // The bextr/shlx/sarx/shrx instructions share the same opcode, the
          // distinction is made via the |pp| (mandatory prefix) field. They
          // all have the same operand encoding.
          if (instruction.MatchExpectations(0b111, 0, "bextr/shlx/sarx/shrx"))
            operand_size = GetModRMOperandBytesSize(ci, true);
          break;
        default:
          break;
      }
      break;
    }
    case 0x03: {
      switch (instruction.opcode) {
        case 0x00:  // vpermq
          if (instruction.MatchExpectations(0b111, 1, "vpermq")) {
            operand_size = GetModRMOperandBytesSize(ci, true);
            constants_size = 1;
          }
          break;
        case 0x1D:  // vcvtps2ph
          if (instruction.MatchExpectations(0b111, 0, "vcvtps2ph")) {
            operand_size = GetModRMOperandBytesSize(ci, true);
            constants_size = 1;
          }
          break;
        case 0x38:  // vinserti128
          if (instruction.MatchExpectations(0b111, 0, "vinserti128")) {
            operand_size = GetModRMOperandBytesSize(ci, true);
            constants_size = 1;
          }
          break;
        case 0x39:  // vextracti128
          if (instruction.MatchExpectations(0b111, 0, "vextracti128")) {
            operand_size = GetModRMOperandBytesSize(ci, true);
            constants_size = 1;
          }
        case 0x46:  // vperm2i128
          if (instruction.MatchExpectations(0b111, 0, "vperm2i128")) {
            operand_size = GetModRMOperandBytesSize(ci, true);
            constants_size = 1;
          }
        default: break;
      }
      break;
    }
    default:
      break;
  }

  if (operand_size != 0)
    return kBaseSize + operand_size + constants_size;

  // Print the instructions that we haven't been able to decompose in a format
  // that can easily be pasted into ODA (https://onlinedisassembler.com/).
  const int kMaxBytes = 10;
  size_t byte_count = std::min(ci->codeLen, kMaxBytes);
  std::string instruction_bytes;
  for (size_t i = 0; i < byte_count; ++i) {
    base::StringAppendF(&instruction_bytes, "%02X", ci->code[i]);
    if (i != byte_count - 1)
      instruction_bytes += " ";
  }
  if (ci->codeLen > kMaxBytes)
    instruction_bytes += "...";
  LOG(WARNING) << "Failed to decompose a VEX encoded instructions with the "
               << "following bytes: " << instruction_bytes;
  return 0;
}

void AdjustOperandSizeTo16Bit(_Operand* op) {
  DCHECK_EQ(32, op->size);

  op->size = 16;
  if (op->type == O_REG) {
    DCHECK(op->index >= R_EAX && op->index < R_AX);
    // Size classes for registers are 16 indices apart.
    op->index += 16;
    DCHECK(op->index >= R_AX && op->index < R_AL);
  }
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

  // The instruction crc32 with a 16 bit size prefix does not decode.
  if (ci->code[0] == 0x66) {
    _CodeInfo co = *ci;
    // Try to decode the instruction past the prefix.
    ++co.code;
    --co.codeLen;

    unsigned int decoded = 0;
    _DecodeResult tmp_ret = distorm_decompose(&co, result, 1, &decoded);
    if ((tmp_ret == DECRES_SUCCESS || tmp_ret == DECRES_MEMORYERR) &&
        decoded == 1 && result->opcode == I_CRC32) {
      // This is the CRC32 with a 16 bit prefix byte.
      AdjustOperandSizeTo16Bit(&result->ops[0]);
      AdjustOperandSizeTo16Bit(&result->ops[1]);
      CHECK_EQ(O_NONE, result->ops[2].type);
      CHECK_EQ(O_NONE, result->ops[3].type);

      --result->addr;
      ++result->size;

      *used_instructions_count = 1;
      *ret = DECRES_SUCCESS;

      return true;
    }
  } else if (ci->code[0] == kThreeByteVexOpcode) {
    size = Get3ByteVexEncodedInstructionSize(ci);
  }

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
      // There's a similar issue with I_STMXCSR which has a size of 0 instead
      // of 32, reported in https://github.com/gdabah/distorm/issues/120.
      case I_STMXCSR:
        DCHECK_EQ(0U, result[i].ops[0].size);
        result[i].ops[0].size = 32;
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
  code.codeLen = static_cast<int>(length);
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
