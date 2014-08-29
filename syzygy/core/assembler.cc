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

#include <limits>

namespace core {

namespace {

enum Mod {
  kReg1Ind = 0,  // Register indirect mode.
  kReg1ByteDisp = 1,  // Register + byte displacement.
  kReg1WordDisp = 2,  // Register + word displacement.
  kReg1 = 3,  // Register itself.
};

// The code that AL/AX/EAX/RAX registers all map to. There are special encodings
// for arithmetic instructions with this register as the destination.
static const RegisterCode kAccumulatorCode = Register::Code(kRegisterEax);

const uint8 kTwoByteOpCodePrefix = 0x0F;
// Prefix group 2 (segment selection).
const uint8 kFsSegmentPrefix = 0x64;
// Prefix group 3 (operand size override).
const uint8 kOperandSizePrefix = 0x66;

// Some opcodes that are used repeatedly.
const uint8 kNopOpCode = 0x1F;

// Returns true if @p operand is a displacement only - e.g.
// specifies neither a base, nor an index register.
bool IsDisplacementOnly(const OperandImpl& operand) {
  return operand.displacement().size() != kSizeNone &&
      operand.base() == kRegisterNone &&
      operand.index() == kRegisterNone;
}

}  // namespace

const size_t AssemblerImpl::kShortBranchOpcodeSize = 1;
const size_t AssemblerImpl::kShortBranchSize = kShortBranchOpcodeSize + 1;

const size_t AssemblerImpl::kLongBranchOpcodeSize = 2;
const size_t AssemblerImpl::kLongBranchSize = kLongBranchOpcodeSize + 4;

const size_t AssemblerImpl::kShortJumpOpcodeSize = 1;
const size_t AssemblerImpl::kShortJumpSize = kShortJumpOpcodeSize + 1;

const size_t AssemblerImpl::kLongJumpOpcodeSize = 1;
const size_t AssemblerImpl::kLongJumpSize = kLongJumpOpcodeSize + 4;

OperandImpl::OperandImpl(const Register32& base)
    : base_(base.id()),
      index_(kRegisterNone),
      scale_(kTimes1) {
}

OperandImpl::OperandImpl(const Register32& base,
                         const DisplacementImpl& displacement)
    : base_(base.id()),
      index_(kRegisterNone),
      scale_(kTimes1),
      displacement_(displacement) {
  // There must be a base register.
  DCHECK_NE(kRegisterNone, base_);
}

OperandImpl::OperandImpl(const DisplacementImpl& displacement)
    : base_(kRegisterNone),
      index_(kRegisterNone),
      scale_(kTimes1),
      displacement_(displacement) {
  DCHECK_NE(kSizeNone, displacement.size());
}

OperandImpl::OperandImpl(const Register32& base,
                         const Register32& index,
                         ScaleFactor scale,
                         const DisplacementImpl& displacement)
    : base_(base.id()),
      index_(index.id()),
      scale_(scale),
      displacement_(displacement) {
  // ESP cannot be used as an index register.
  DCHECK_NE(kRegisterEsp, index.id());
  DCHECK_NE(kSizeNone, displacement.size());
}

OperandImpl::OperandImpl(const Register32& base,
                         const Register32& index,
                         ScaleFactor scale)
    : base_(base.id()),
      index_(index.id()),
      scale_(scale) {
  // ESP cannot be used as an index register.
  DCHECK_NE(kRegisterEsp, index.id());
  DCHECK_EQ(kSizeNone, displacement_.size());
}

OperandImpl::OperandImpl(const Register32& index,
                         ScaleFactor scale,
                         const DisplacementImpl& displacement)
    : base_(kRegisterNone),
      index_(index.id()),
      scale_(scale),
      displacement_(displacement) {
  // ESP cannot be used as an index register.
  DCHECK_NE(kRegisterEsp, index.id());
  DCHECK_NE(kSizeNone, displacement.size());
}

OperandImpl::OperandImpl(RegisterId base,
                         RegisterId index,
                         ScaleFactor scale,
                         const DisplacementImpl& displacement)
    : base_(base),
      index_(index),
      scale_(scale),
      displacement_(displacement) {
}

ValueImpl::ValueImpl()
    : value_(0), reference_(NULL), size_(kSizeNone) {
}

ValueImpl::ValueImpl(uint32 value, ValueSize size)
    : value_(value), reference_(NULL), size_(size) {
}

ValueImpl::ValueImpl(uint32 value,
                     ValueSize size,
                     const void* value_ref)
    : value_(value), reference_(value_ref), size_(size) {
  // We can't have a 16-bit value *and* a reference, as there are no
  // addressing modes that accept 16-bit input.
  DCHECK(value_ref == NULL || size != kSize16Bit);
}

bool ValueImpl::operator==(const ValueImpl& rhs) const {
  return value_ == rhs.value_ &&
      reference_ == rhs.reference_ &&
      size_ == rhs.size_;
}

// This class is used to buffer a single instruction during it's creation.
// TODO(siggi): Add a small state machine in debug mode to ensure the
//     correct order of invocation to opcode/modrm etc.
class AssemblerImpl::InstructionBuffer {
 public:
  explicit InstructionBuffer(AssemblerImpl* assm);
  ~InstructionBuffer();

  // @name Accessors.
  // @{
  size_t len() const { return len_; }
  const uint8* buf() const { return buf_; }
  size_t num_references() const { return num_references_; }
  const size_t *reference_offsets() const { return reference_offsets_; }
  const void*const* references() const { return references_; }
  // @}

  // Emits operand size prefix (0x66) bytes.
  // @param count The number of operand size prefix bytes to emit.
  void EmitOperandSizePrefix(size_t count);
  // Emit an opcode byte.
  void EmitOpCodeByte(uint8 opcode);
  // Emit a ModR/M byte with an opcode extension.
  void EmitModRMByte(Mod mod, uint8 op, RegisterId reg1);
  // Emit a ModR/M byte with a destination register.
  void EmitModRMByte(Mod mod, RegisterId reg2, RegisterId reg1);
  // Emit a SIB byte.
  void EmitScaleIndexBaseByte(ScaleFactor scale,
                              RegisterId index,
                              RegisterId base);
  // Emit an operand.
  void EmitOperand(uint8 reg_op, const OperandImpl& op);

  // Emit an 8-bit displacement, with optional reference info.
  void Emit8BitDisplacement(const DisplacementImpl& disp);

  // Emit a 32-bit displacement with optional reference info.
  void Emit32BitDisplacement(const DisplacementImpl& disp);

  // Emit an 8-bit PC-relative value.
  void Emit8BitPCRelative(uint32 location, const ValueImpl& disp);

  // Emit a 32-bit PC-relative value.
  void Emit32BitPCRelative(uint32 location, const ValueImpl& disp);

  // Emit a 16-bit immediate value.
  void Emit16BitValue(uint16 value);

  // Emit an arithmetic instruction with various encoding.
  void EmitArithmeticInstruction(
      uint8 op, const Register& dst, const Register& src);
  void EmitArithmeticInstruction(
      uint8 op, const Register& dst, const OperandImpl& src);
  void EmitArithmeticInstruction(
      uint8 op, const OperandImpl& dst, const Register32& src);
  void EmitArithmeticInstructionToRegister32(uint8 op_eax, uint8 op_8,
      uint8 op_32, uint8 sub_op, const Register32& dst,
      const ImmediateImpl& src);
  void EmitArithmeticInstructionToRegister8(uint8 op_eax, uint8 op_8,
      uint8 sub_op, const Register8& dst, const ImmediateImpl& src);
  void EmitArithmeticInstructionToOperand(uint8 op_8, uint8 op_32, uint8 sub_op,
      const OperandImpl& dst, const ImmediateImpl& src);

  // Emit an XCHG instruction.
  void EmitXchg(ValueSize size, RegisterId dst, RegisterId src);

  // Add reference at current location.
  void AddReference(const void* reference);

 protected:
  void EmitByte(uint8 byte);

  AssemblerImpl* asm_;
  size_t num_references_;
  const void* (references_)[2];
  size_t reference_offsets_[2];
  size_t len_;
  uint8 buf_[kMaxInstructionLength];
};

AssemblerImpl::InstructionBuffer::InstructionBuffer(AssemblerImpl* assm)
    : asm_(assm), len_(0), num_references_(0) {
  DCHECK(assm != NULL);
#ifndef NDEBUG
  // Initialize the buffer in debug mode for easier debugging.
  ::memset(buf_, 0xCC, sizeof(buf_));
#endif
}

AssemblerImpl::InstructionBuffer::~InstructionBuffer() {
  asm_->Output(*this);
}

void AssemblerImpl::InstructionBuffer::EmitOperandSizePrefix(size_t count) {
  for (size_t i = 0; i < count; ++i)
    EmitByte(kOperandSizePrefix);
}

void AssemblerImpl::InstructionBuffer::EmitOpCodeByte(uint8 opcode) {
  EmitByte(opcode);
}

void AssemblerImpl::InstructionBuffer::EmitModRMByte(
    Mod mod, uint8 reg_op, RegisterId reg1) {
  DCHECK_LE(reg_op, 8);
  DCHECK_NE(kRegisterNone, reg1);
  EmitByte((mod << 6) | (reg_op << 3) | Register::Code(reg1));
}

void AssemblerImpl::InstructionBuffer::EmitModRMByte(
    Mod mod, RegisterId reg2, RegisterId reg1) {
  DCHECK_NE(kRegisterNone, reg2);
  DCHECK_NE(kRegisterNone, reg1);
  EmitModRMByte(mod, Register::Code(reg2), reg1);
}

void AssemblerImpl::InstructionBuffer::EmitScaleIndexBaseByte(
    ScaleFactor scale, RegisterId index, RegisterId base) {
  DCHECK_NE(kRegisterNone, index);
  DCHECK_NE(kRegisterNone, base);

  EmitByte((scale << 6) | (Register::Code(index) << 3) | Register::Code(base));
}

void AssemblerImpl::InstructionBuffer::EmitOperand(
    uint8 reg_op, const OperandImpl& op) {
  DCHECK_GE(8, reg_op);

  // The op operand can encode any one of the following things:
  // An indirect register access [EAX].
  // An indirect 32-bit displacement only [0xDEADBEEF].
  // An indirect base register + 32/8-bit displacement [EAX+0xDEADBEEF].
  // An indirect base + index register*scale [EAX+ECX*4].
  // An indirect base + index register*scale + 32/8-bit displacement
  //   [EAX+ECX*4+0xDEADBEEF].
  // To complicate things, there are certain combinations that can't be encoded
  // canonically. The mode [ESP] or [ESP+disp] can never be encoded in a
  // ModR/M byte alone, as ESP in the ModR/M byte for any of the indirect modes
  // is overloaded to select the SIB representation.
  // Likewise [EBP] is overloaded to encode the [disp32] case.
  // See e.g. http://ref.x86asm.net/geek32-abc.html#modrm_byte_32 for a nice
  // overview table of the ModR/M byte encoding.

  // ESP can never be used as an index register on X86.
  DCHECK_NE(kRegisterEsp, op.index());

  // Is there an index register?
  if (op.index() == kRegisterNone) {
    DCHECK_EQ(kTimes1, op.scale());

    // No index register, is there a base register?
    if (op.base() == kRegisterNone) {
      // No base register, this is a displacement only.
      DCHECK_NE(kSizeNone, op.displacement().size());
      DCHECK_EQ(kTimes1, op.scale());

      // The [disp32] mode is encoded by overloading [EBP].
      EmitModRMByte(kReg1Ind, reg_op, kRegisterEbp);
      Emit32BitDisplacement(op.displacement());
    } else {
      // Base register only, is it ESP?
      if (op.base() == kRegisterEsp) {
        // The [ESP] and [ESP+disp] cases cannot be encoded without a SIB byte.
        if (op.displacement().size() == kSizeNone) {
          EmitModRMByte(kReg1Ind, reg_op, kRegisterEsp);
          EmitScaleIndexBaseByte(kTimes1, kRegisterEsp, kRegisterEsp);
        } else if (op.displacement().size() == kSize8Bit) {
          EmitModRMByte(kReg1ByteDisp, reg_op, kRegisterEsp);
          EmitScaleIndexBaseByte(kTimes1, kRegisterEsp, kRegisterEsp);
          Emit8BitDisplacement(op.displacement());
        } else {
          DCHECK_EQ(kSize32Bit, op.displacement().size());
          EmitModRMByte(kReg1WordDisp, reg_op, kRegisterEsp);
          EmitScaleIndexBaseByte(kTimes1, kRegisterEsp, kRegisterEsp);
          Emit32BitDisplacement(op.displacement());
        }
      } else if (op.displacement().size() == kSizeNone) {
        if (op.base() == kRegisterEbp) {
          // The [EBP] case cannot be encoded canonically, there always must
          // be a (zero) displacement.
          EmitModRMByte(kReg1ByteDisp, reg_op, op.base());
          Emit8BitDisplacement(DisplacementImpl(0, kSize8Bit, NULL));
        } else {
          EmitModRMByte(kReg1Ind, reg_op, op.base());
        }
      } else if (op.displacement().size() == kSize8Bit) {
        // It's [base+disp8], or possibly [EBP].
        EmitModRMByte(kReg1ByteDisp, reg_op, op.base());
        Emit8BitDisplacement(op.displacement());
      } else {
        DCHECK_EQ(kSize32Bit, op.displacement().size());
        // It's [base+disp32].
        EmitModRMByte(kReg1WordDisp, reg_op, op.base());
        Emit32BitDisplacement(op.displacement());
      }
    }
  } else if (op.base() == kRegisterNone) {
    // Index, no base.
    DCHECK_NE(kRegisterNone, op.index());
    DCHECK_EQ(kRegisterNone, op.base());

    // This mode always has a 32 bit displacement.
    EmitModRMByte(kReg1Ind, reg_op, kRegisterEsp);
    EmitScaleIndexBaseByte(op.scale(), op.index(), kRegisterEbp);
    Emit32BitDisplacement(op.displacement());
  } else {
    // Index and base case.
    DCHECK_NE(kRegisterNone, op.index());
    DCHECK_NE(kRegisterNone, op.base());

    // Is there a displacement?
    if (op.displacement().size() == kSizeNone) {
      EmitModRMByte(kReg1Ind, reg_op, kRegisterEsp);
      EmitScaleIndexBaseByte(op.scale(), op.index(), op.base());
    } else if (op.displacement().size() == kSize8Bit) {
      EmitModRMByte(kReg1ByteDisp, reg_op, kRegisterEsp);
      EmitScaleIndexBaseByte(op.scale(), op.index(), op.base());
      Emit8BitDisplacement(op.displacement());
    } else {
      DCHECK_EQ(kSize32Bit, op.displacement().size());
      EmitModRMByte(kReg1WordDisp, reg_op, kRegisterEsp);
      EmitScaleIndexBaseByte(op.scale(), op.index(), op.base());
      Emit32BitDisplacement(op.displacement());
    }
  }
}

void AssemblerImpl::InstructionBuffer::Emit8BitDisplacement(
    const DisplacementImpl& disp) {
  DCHECK(disp.size() == kSize8Bit);

  AddReference(disp.reference());

  EmitByte(disp.value());
}

void AssemblerImpl::InstructionBuffer::Emit32BitDisplacement(
    const DisplacementImpl& disp) {
  AddReference(disp.reference());

  uint32 value = disp.value();
  EmitByte(value);
  EmitByte(value >> 8);
  EmitByte(value >> 16);
  EmitByte(value >> 24);
}

void AssemblerImpl::InstructionBuffer::Emit8BitPCRelative(
    uint32 location, const ValueImpl& value) {
  DCHECK_EQ(kSize8Bit, value.size());

  AddReference(value.reference());

  // Turn the absolute value into a value relative to the address of
  // the end of the emitted constant.
  int32 relative_value = value.value() - (location + len_ + 1);
  DCHECK_LE(std::numeric_limits<int8>::min(), relative_value);
  DCHECK_GE(std::numeric_limits<int8>::max(), relative_value);
  EmitByte(relative_value);
}

void AssemblerImpl::InstructionBuffer::Emit32BitPCRelative(
    uint32 location, const ValueImpl& value) {
  DCHECK_EQ(kSize32Bit, value.size());

  AddReference(value.reference());

  // Turn the absolute value into a value relative to the address of
  // the end of the emitted constant.
  uint32 relative_value = value.value() - (location + len_ + 4);
  EmitByte(relative_value);
  EmitByte(relative_value >> 8);
  EmitByte(relative_value >> 16);
  EmitByte(relative_value >> 24);
}

void AssemblerImpl::InstructionBuffer::Emit16BitValue(uint16 value) {
  EmitByte(value);
  EmitByte(value >> 8);
}

void AssemblerImpl::InstructionBuffer::EmitArithmeticInstruction(
    uint8 op, const Register& dst, const Register& src) {
  DCHECK_EQ(dst.size(), src.size());
  EmitOpCodeByte(op);
  EmitModRMByte(kReg1, dst.id(), src.id());
}

void AssemblerImpl::InstructionBuffer::EmitArithmeticInstruction(
    uint8 op, const Register& dst, const OperandImpl& src) {
  EmitOpCodeByte(op);
  EmitOperand(dst.code(), src);
}

void AssemblerImpl::InstructionBuffer::EmitArithmeticInstruction(
    uint8 op, const OperandImpl& dst, const Register32& src) {
  EmitOpCodeByte(op);
  EmitOperand(src.code(), dst);
}

void AssemblerImpl::InstructionBuffer::EmitArithmeticInstructionToRegister32(
    uint8 op_eax, uint8 op_8, uint8 op_32, uint8 sub_op,
    const Register32& dst, const ImmediateImpl& src) {
  if (dst.id() == kRegisterEax && src.size() == kSize32Bit) {
    // Special encoding for EAX.
    EmitOpCodeByte(op_eax);
    Emit32BitDisplacement(src);
  } else if (src.size() == kSize8Bit) {
    EmitOpCodeByte(op_8);
    EmitModRMByte(kReg1, sub_op, dst.id());
    Emit8BitDisplacement(src);
  } else {
    EmitOpCodeByte(op_32);
    EmitModRMByte(kReg1, sub_op, dst.id());
    Emit32BitDisplacement(src);
  }
}

void AssemblerImpl::InstructionBuffer::EmitArithmeticInstructionToRegister8(
    uint8 op_eax, uint8 op_8, uint8 sub_op,
    const Register8& dst, const ImmediateImpl& src) {
  DCHECK(src.size() == kSize8Bit);
  if (dst.code() == kAccumulatorCode) {
    // Special encoding for AL/AX/EAX.
    EmitOpCodeByte(op_eax);
  } else {
    EmitOpCodeByte(op_8);
    EmitModRMByte(kReg1, sub_op, dst.id());
  }
  Emit8BitDisplacement(src);
}

void AssemblerImpl::InstructionBuffer::EmitArithmeticInstructionToOperand(
    uint8 op_8, uint8 op_32, uint8 sub_op,
    const OperandImpl& dst, const ImmediateImpl& src) {
  if (src.size() == kSize8Bit) {
    EmitOpCodeByte(op_8);
    EmitOperand(sub_op, dst);
    Emit8BitDisplacement(src);
  } else {
    EmitOpCodeByte(op_32);
    EmitOperand(sub_op, dst);
    Emit32BitDisplacement(src);
  }
}

void AssemblerImpl::InstructionBuffer::EmitXchg(
    ValueSize size, RegisterId dst, RegisterId src) {
  // Encoding for 8-bit registers.
  if (size == kSize8Bit) {
    EmitOpCodeByte(0x86);
    EmitModRMByte(kReg1, src, dst);
  } else {
    // 16-bit encodings are identical to 32-bit encodings, simply with
    // a operand size override prefix.
    if (size == kSize16Bit)
      EmitOperandSizePrefix(1);

    // If either register is EAX/AX there's a 1-byte encoding.
    RegisterCode dst_code = Register::Code(dst);
    RegisterCode src_code = Register::Code(src);
    if (src_code == kAccumulatorCode || dst_code == kAccumulatorCode) {
      RegisterCode other_register = dst_code;
      if (dst_code == kAccumulatorCode)
        other_register = src_code;
      EmitOpCodeByte(0x90 | other_register);
    } else {
      // Otherwise we use a 2-byte encoding with a ModR/M byte.
      EmitOpCodeByte(0x87);
      EmitModRMByte(kReg1, src, dst);
    }
  }
}

void AssemblerImpl::InstructionBuffer::AddReference(const void* reference) {
  if (reference == NULL)
    return;

  DCHECK_GT(arraysize(references_), num_references_);
  reference_offsets_[num_references_] = len();
  references_[num_references_] = reference;
  ++num_references_;
}

void AssemblerImpl::InstructionBuffer::EmitByte(uint8 byte) {
  DCHECK_GT(sizeof(buf_), len_);
  buf_[len_++] = byte;
}

AssemblerImpl::AssemblerImpl(uint32 location, InstructionSerializer* serializer)
    : location_(location), serializer_(serializer) {
  DCHECK(serializer != NULL);
}

void AssemblerImpl::nop(size_t size) {
  // These are NOP sequences suggested by the Intel Architecture
  // Software Developer's manual, page 4-8.
  //
  //  1: 0x90
  //  2: 0x66 0x90
  //  3: 0x66 0x66 0x90
  //  4: 0x0F 0x1F 0x40 0x00
  //  5: 0x0F 0x1F 0x44 0x00 0x00
  //  6: 0x66 0x0F 0x1F 0x44 0x00 0x00
  //  7: 0x0F 0x1F 0x80 0x00 0x00 0x00 0x00
  //  8: 0x0F 0x1F 0x84 0x00 0x00 0x00 0x00 0x00
  //  9: 0x66 0x0F 0x1F 0x84 0x00 0x00 0x00 0x00 0x00
  // 10: 0x66 0x66 0x0F 0x1F 0x84 0x00 0x00 0x00 0x00 0x00
  // 11: 0x66 0x66 0x66 0x0F 0x1F 0x84 0x00 0x00 0x00 0x00 0x00
  //
  // It is further suggested not to put consecutive XCHG NOPs with prefixes,
  // but rather to mix them with 0x1F NOPs or XCHG NOPs without prefixes. The
  // basic nops without any operand prefixes (0x66) have been implemented as
  // helper functions nop1, nop4, nop5, nop7 and nop8. This implementation of
  // NOP sequences has been inspired by Oracle's HotSpot JVM JIT assembler
  // (http://openjdk.java.net/groups/hotspot/).

  // Eat up the NOPs in chunks of 15 bytes.
  while (size >= 15) {
    nop8(3);  // 11-byte non-XCHG NOP.
    nop1(3);  // 4-byte prefixed XCHG NOP.
    size -= 15;
  }
  DCHECK_GE(14u, size);

  // Handle the last chunk of bytes.
  size_t prefix_count = 0;
  switch (size) {
    // Handle 12- to 14-byte NOPs.
    case 14:
      ++prefix_count;
    case 13:
      ++prefix_count;
    case 12:
      nop8(prefix_count);  // 8- to 10-byte non-XCHG NOP.
      nop1(3);  // 4-byte prefixed XCHG NOP.
      return;

    // Handle 8- to 11-byte NOPs.
    case 11:
      ++prefix_count;
    case 10:
      ++prefix_count;
    case 9:
      ++prefix_count;
    case 8:
      nop8(prefix_count);  // 8- to 11-byte non-XCHG NOP.
      return;

    // Handle 7-byte NOPs.
    case 7:
      nop7(prefix_count);  // 7-byte non-XCHG NOP.
      return;

    // Handle 5- to 6-byte NOPs.
    case 6:
      ++prefix_count;
    case 5:
      nop5(prefix_count);  // 5- to 6-byte non-XCHG NOP.
      return;

    // Handle 4-byte NOPs.
    case 4:
      nop4(prefix_count);  // 4-byte non-XCHG NOP.
      return;

    // Handle 1- to 3-byte NOPs.
    case 3:
      ++prefix_count;
    case 2:
      ++prefix_count;
    case 1:
      nop1(prefix_count);  // 1- to 3-byte XCHG NOP.
      return;

    case 0:
      // Nothing to do!
      break;
  }
  return;
}

void AssemblerImpl::call(const ImmediateImpl& dst) {
  InstructionBuffer instr(this);

  instr.EmitOpCodeByte(0xE8);
  instr.Emit32BitPCRelative(location_, dst);
}

void AssemblerImpl::call(const OperandImpl& dst) {
  InstructionBuffer instr(this);

  instr.EmitOpCodeByte(0xFF);
  instr.EmitOperand(0x2, dst);
}

void AssemblerImpl::j(ConditionCode cc, const ImmediateImpl& dst) {
  DCHECK_LE(kMinConditionCode, cc);
  DCHECK_GE(kMaxConditionCode, cc);

  InstructionBuffer instr(this);
  if (dst.size() == kSize32Bit) {
    instr.EmitOpCodeByte(kTwoByteOpCodePrefix);
    instr.EmitOpCodeByte(0x80 | cc);
    instr.Emit32BitPCRelative(location_, dst);
  } else {
    DCHECK_EQ(kSize8Bit, dst.size());
    instr.EmitOpCodeByte(0x70 | cc);
    instr.Emit8BitPCRelative(location_, dst);
  }
}

void AssemblerImpl::jecxz(const ImmediateImpl& dst) {
  DCHECK_EQ(kSize8Bit, dst.size());
  InstructionBuffer instr(this);
  instr.EmitOpCodeByte(0xE3);
  instr.Emit8BitPCRelative(location_, dst);
}

void AssemblerImpl::jmp(const ImmediateImpl& dst) {
  InstructionBuffer instr(this);

  if (dst.size() == kSize32Bit) {
    instr.EmitOpCodeByte(0xE9);
    instr.Emit32BitPCRelative(location_, dst);
  } else {
    DCHECK_EQ(kSize8Bit, dst.size());
    instr.EmitOpCodeByte(0xEB);
    instr.Emit8BitPCRelative(location_, dst);
  }
}

void AssemblerImpl::jmp(const OperandImpl& dst) {
  InstructionBuffer instr(this);

  instr.EmitOpCodeByte(0xFF);
  instr.EmitOperand(0x4, dst);
}

void AssemblerImpl::l(LoopCode lc, const ImmediateImpl& dst) {
  DCHECK_EQ(kSize8Bit, dst.size());
  DCHECK_LE(0, lc);
  DCHECK_GE(2, lc);
  InstructionBuffer instr(this);

  instr.EmitOpCodeByte(0xE0 | lc);
  instr.Emit8BitPCRelative(location_, dst);
}

void AssemblerImpl::ret() {
  InstructionBuffer instr(this);

  instr.EmitOpCodeByte(0xC3);
}

void AssemblerImpl::ret(uint16 n) {
  InstructionBuffer instr(this);

  instr.EmitOpCodeByte(0xC2);
  instr.Emit16BitValue(n);
}

void AssemblerImpl::set(ConditionCode cc, const Register32& dst) {
  DCHECK_LE(kMinConditionCode, cc);
  DCHECK_GE(kMaxConditionCode, cc);

  InstructionBuffer instr(this);
  instr.EmitOpCodeByte(kTwoByteOpCodePrefix);
  instr.EmitOpCodeByte(0x90 | cc);

  // AMD64 Architecture Programmers Manual Volume 3: General-Purpose and System
  // Instructions: The reg field in the ModR/M byte is unused.
  const Register32& unused = core::eax;
  instr.EmitModRMByte(kReg1, unused.id(), dst.id());
}

void AssemblerImpl::mov_b(const OperandImpl& dst, const ImmediateImpl& src) {
  InstructionBuffer instr(this);

  instr.EmitOpCodeByte(0xC6);
  instr.EmitOperand(0, dst);
  instr.Emit8BitDisplacement(src);
}

void AssemblerImpl::movzx_b(const Register32& dst, const OperandImpl& src) {
  InstructionBuffer instr(this);
  instr.EmitOpCodeByte(kTwoByteOpCodePrefix);
  instr.EmitOpCodeByte(0xB6);
  instr.EmitOperand(dst.code(), src);
}

void AssemblerImpl::mov(const Register32& dst, const Register32& src) {
  InstructionBuffer instr(this);

  instr.EmitOpCodeByte(0x8B);
  instr.EmitModRMByte(kReg1, dst.id(), src.id());
}

void AssemblerImpl::mov(const Register32& dst, const OperandImpl& src) {
  InstructionBuffer instr(this);

  if (dst.id() == kRegisterEax && IsDisplacementOnly(src)) {
    // Special encoding for indirect displacement only to EAX.
    instr.EmitOpCodeByte(0xA1);
    instr.Emit32BitDisplacement(src.displacement());
  } else {
    instr.EmitOpCodeByte(0x8B);
    instr.EmitOperand(dst.code(), src);
  }
}

void AssemblerImpl::mov(const OperandImpl& dst, const Register32& src) {
  InstructionBuffer instr(this);

  if (src.id() == kRegisterEax && IsDisplacementOnly(dst)) {
    // Special encoding for indirect displacement only from EAX.
    instr.EmitOpCodeByte(0xA3);
    instr.Emit32BitDisplacement(dst.displacement());
  } else {
    instr.EmitOpCodeByte(0x89);
    instr.EmitOperand(src.code(), dst);
  }
}

void AssemblerImpl::mov(const Register32& dst, const ValueImpl& src) {
  DCHECK_NE(kSizeNone, src.size());
  InstructionBuffer instr(this);

  instr.EmitOpCodeByte(0xB8 | dst.code());
  instr.Emit32BitDisplacement(src);
}

void AssemblerImpl::mov(const OperandImpl& dst, const ImmediateImpl& src) {
  InstructionBuffer instr(this);

  instr.EmitOpCodeByte(0xC7);
  instr.EmitOperand(0, dst);
  instr.Emit32BitDisplacement(src);
}

void AssemblerImpl::mov_fs(const Register32& dst, const OperandImpl& src) {
  InstructionBuffer instr(this);
  instr.EmitOpCodeByte(kFsSegmentPrefix);

  if (dst.id() == kRegisterEax && IsDisplacementOnly(src)) {
    // Special encoding for indirect displacement only to EAX.
    instr.EmitOpCodeByte(0xA1);
    instr.Emit32BitDisplacement(src.displacement());
  } else {
    instr.EmitOpCodeByte(0x8B);
    instr.EmitOperand(dst.code(), src);
  }
}

void AssemblerImpl::mov_fs(const OperandImpl& dst, const Register32& src) {
  InstructionBuffer instr(this);
  instr.EmitOpCodeByte(kFsSegmentPrefix);

  if (src.id() == kRegisterEax && IsDisplacementOnly(dst)) {
    // Special encoding for indirect displacement only from EAX.
    instr.EmitOpCodeByte(0xA3);
    instr.Emit32BitDisplacement(dst.displacement());
  } else {
    instr.EmitOpCodeByte(0x89);
    instr.EmitOperand(src.code(), dst);
  }
}

void AssemblerImpl::lea(const Register32& dst, const OperandImpl& src) {
  InstructionBuffer instr(this);

  instr.EmitOpCodeByte(0x8D);
  instr.EmitOperand(dst.code(), src);
}

void AssemblerImpl::push(const Register32& src) {
  InstructionBuffer instr(this);

  instr.EmitOpCodeByte(0x50 | src.code());
}

void AssemblerImpl::push(const ImmediateImpl& src) {
  DCHECK_EQ(kSize32Bit, src.size());
  InstructionBuffer instr(this);

  instr.EmitOpCodeByte(0x68);
  instr.Emit32BitDisplacement(src);
}

void AssemblerImpl::push(const OperandImpl& dst) {
  InstructionBuffer instr(this);

  instr.EmitOpCodeByte(0xFF);
  instr.EmitOperand(0x6, dst);
}

void AssemblerImpl::pushad() {
  InstructionBuffer instr(this);

  instr.EmitOpCodeByte(0x60);
}

void AssemblerImpl::pop(const Register32& src) {
  InstructionBuffer instr(this);

  instr.EmitOpCodeByte(0x58 | src.code());
}

void AssemblerImpl::pop(const OperandImpl& dst) {
  InstructionBuffer instr(this);

  instr.EmitOpCodeByte(0x8F);
  instr.EmitOperand(0, dst);
}

void AssemblerImpl::popad() {
  InstructionBuffer instr(this);

  instr.EmitOpCodeByte(0x61);
}

void AssemblerImpl::pushfd() {
  InstructionBuffer instr(this);
  instr.EmitOpCodeByte(0x9C);
}

void AssemblerImpl::popfd() {
  InstructionBuffer instr(this);
  instr.EmitOpCodeByte(0x9D);
}

void AssemblerImpl::lahf() {
  InstructionBuffer instr(this);
  instr.EmitOpCodeByte(0x9F);
}

void AssemblerImpl::sahf() {
  InstructionBuffer instr(this);
  instr.EmitOpCodeByte(0x9E);
}

void AssemblerImpl::test(const Register8& dst, const Register8& src) {
  InstructionBuffer instr(this);
  instr.EmitArithmeticInstruction(0x84, dst, src);
}

void AssemblerImpl::test(const Register8& dst, const ImmediateImpl& src) {
  InstructionBuffer instr(this);
  instr.EmitArithmeticInstructionToRegister8(0xA8, 0xF6, 0, dst, src);
}

void AssemblerImpl::test(const Register32& dst, const Register32& src) {
  InstructionBuffer instr(this);
  instr.EmitArithmeticInstruction(0x85, dst, src);
}

void AssemblerImpl::test(const Register32& dst, const OperandImpl& src) {
  // Use commutative property for a smaller encoding.
  test(src, dst);
}

void AssemblerImpl::test(const OperandImpl& dst, const Register32& src) {
  InstructionBuffer instr(this);
  instr.EmitArithmeticInstruction(0x85, dst, src);
}

void AssemblerImpl::test(const Register32& dst, const ImmediateImpl& src) {
  if (src.size() == kSize8Bit) {
    // note: There is no encoding for a 8-bit immediate with 32-bit register.
    test(dst, ImmediateImpl(src.value(), kSize32Bit));
  } else {
    InstructionBuffer instr(this);
    instr.EmitArithmeticInstructionToRegister32(0xA9, 0xF7, 0xF7, 0, dst, src);
  }
}

void AssemblerImpl::test(const OperandImpl& dst, const ImmediateImpl& src) {
  if (src.size() == kSize8Bit) {
    // note: There is no encoding for a 8-bit immediate with 32-bit register.
    test(dst, ImmediateImpl(src.value(), kSize32Bit));
  } else {
    InstructionBuffer instr(this);
    instr.EmitArithmeticInstructionToOperand(0xF7, 0xF7, 0, dst, src);
  }
}

void AssemblerImpl::cmp(const Register8& dst, const Register8& src) {
  InstructionBuffer instr(this);
  instr.EmitArithmeticInstruction(0x3A, dst, src);
}

void AssemblerImpl::cmp(const Register8& dst, const ImmediateImpl& src) {
  InstructionBuffer instr(this);
  instr.EmitArithmeticInstructionToRegister8(0x3C, 0x80, 7, dst, src);
}

void AssemblerImpl::cmp(const Register32& dst, const Register32& src) {
  InstructionBuffer instr(this);
  instr.EmitArithmeticInstruction(0x3B, dst, src);
}

void AssemblerImpl::cmp(const Register32& dst, const OperandImpl& src) {
  InstructionBuffer instr(this);
  instr.EmitArithmeticInstruction(0x3B, dst, src);
}

void AssemblerImpl::cmp(const OperandImpl& dst, const Register32& src) {
  InstructionBuffer instr(this);
  instr.EmitArithmeticInstruction(0x39, dst, src);
}

void AssemblerImpl::cmp(const Register32& dst, const ImmediateImpl& src) {
  InstructionBuffer instr(this);
  instr.EmitArithmeticInstructionToRegister32(0x3D, 0x83, 0x81, 7, dst, src);
}

void AssemblerImpl::cmp(const OperandImpl& dst, const ImmediateImpl& src) {
  InstructionBuffer instr(this);
  instr.EmitArithmeticInstructionToOperand(0x83, 0x81, 7, dst, src);
}

void AssemblerImpl::add(const Register8& dst, const Register8& src) {
  InstructionBuffer instr(this);
  instr.EmitArithmeticInstruction(0x02, dst, src);
}

void AssemblerImpl::add(const Register8& dst, const ImmediateImpl& src) {
  InstructionBuffer instr(this);
  instr.EmitArithmeticInstructionToRegister8(0x04, 0x80, 0, dst, src);
}

void AssemblerImpl::add(const Register32& dst, const Register32& src) {
  InstructionBuffer instr(this);
  instr.EmitArithmeticInstruction(0x03, dst, src);
}

void AssemblerImpl::add(const Register32& dst, const OperandImpl& src) {
  InstructionBuffer instr(this);
  instr.EmitArithmeticInstruction(0x03, dst, src);
}

void AssemblerImpl::add(const OperandImpl& dst, const Register32& src) {
  InstructionBuffer instr(this);
  instr.EmitArithmeticInstruction(0x01, dst, src);
}

void AssemblerImpl::add(const Register32& dst, const ImmediateImpl& src) {
  InstructionBuffer instr(this);
  instr.EmitArithmeticInstructionToRegister32(0x05, 0x83, 0x81, 0, dst, src);
}

void AssemblerImpl::add(const OperandImpl& dst, const ImmediateImpl& src) {
  InstructionBuffer instr(this);
  instr.EmitArithmeticInstructionToOperand(0x83, 0x81, 0, dst, src);
}

void AssemblerImpl::sub(const Register8& dst, const Register8& src) {
  InstructionBuffer instr(this);
  instr.EmitArithmeticInstruction(0x2A, dst, src);
}

void AssemblerImpl::sub(const Register8& dst, const ImmediateImpl& src) {
  InstructionBuffer instr(this);
  instr.EmitArithmeticInstructionToRegister8(0x2C, 0x80, 5, dst, src);
}

void AssemblerImpl::sub(const Register32& dst, const Register32& src) {
  InstructionBuffer instr(this);
  instr.EmitArithmeticInstruction(0x2B, dst, src);
}

void AssemblerImpl::sub(const Register32& dst, const OperandImpl& src) {
  InstructionBuffer instr(this);
  instr.EmitArithmeticInstruction(0x2B, dst, src);
}

void AssemblerImpl::sub(const OperandImpl&  dst, const Register32& src) {
  InstructionBuffer instr(this);
  instr.EmitArithmeticInstruction(0x29, dst, src);
}

void AssemblerImpl::sub(const Register32& dst, const ImmediateImpl& src) {
  InstructionBuffer instr(this);
  instr.EmitArithmeticInstructionToRegister32(0x2D, 0x83, 0x81, 5, dst, src);
}

void AssemblerImpl::sub(const OperandImpl&  dst, const ImmediateImpl& src) {
  InstructionBuffer instr(this);
  instr.EmitArithmeticInstructionToOperand(0x83, 0x81, 5, dst, src);
}

void AssemblerImpl::shl(const Register32& dst, const ImmediateImpl& src) {
  InstructionBuffer instr(this);
  if (src.value() == 1) {
    instr.EmitOpCodeByte(0xD1);
    instr.EmitModRMByte(kReg1, 4, dst.id());
  } else {
    instr.EmitOpCodeByte(0xC1);
    instr.EmitModRMByte(kReg1, 4, dst.id());
    instr.Emit8BitDisplacement(src);
  }
}

void AssemblerImpl::shr(const Register32& dst, const ImmediateImpl& src) {
  InstructionBuffer instr(this);
  if (src.value() == 1) {
    instr.EmitOpCodeByte(0xD1);
    instr.EmitModRMByte(kReg1, 5, dst.id());
  } else {
    instr.EmitOpCodeByte(0xC1);
    instr.EmitModRMByte(kReg1, 5, dst.id());
    instr.Emit8BitDisplacement(src);
  }
}

void AssemblerImpl::xchg(const Register32& dst, const Register32& src) {
  InstructionBuffer instr(this);
  instr.EmitXchg(kSize32Bit, dst.id(), src.id());
}

void AssemblerImpl::xchg(const Register16& dst, const Register16& src) {
  InstructionBuffer instr(this);
  instr.EmitXchg(kSize16Bit, dst.id(), src.id());
}

void AssemblerImpl::xchg(const Register8& dst, const Register8& src) {
  InstructionBuffer instr(this);
  instr.EmitXchg(kSize8Bit, dst.id(), src.id());
}

void AssemblerImpl::nop1(size_t prefix_count) {
  InstructionBuffer instr(this);
  instr.EmitOperandSizePrefix(prefix_count);
  instr.EmitXchg(kSize32Bit, kRegisterEax, kRegisterEax);
}

void AssemblerImpl::nop4(size_t prefix_count) {
  InstructionBuffer instr(this);
  instr.EmitOperandSizePrefix(prefix_count);
  // 4 bytes: NOP DWORD PTR [EAX + 0] 8-bit offset
  instr.EmitOpCodeByte(kTwoByteOpCodePrefix);
  instr.EmitOpCodeByte(kNopOpCode);
  instr.EmitModRMByte(kReg1ByteDisp, 0, kRegisterEax);
  instr.Emit8BitDisplacement(DisplacementImpl(0, kSize8Bit));
}

void AssemblerImpl::nop5(size_t prefix_count) {
  InstructionBuffer instr(this);
  instr.EmitOperandSizePrefix(prefix_count);
  // 5 bytes: NOP DWORD PTR [EAX + EAX * 1 + 0] 8-bit offset
  instr.EmitOpCodeByte(kTwoByteOpCodePrefix);
  instr.EmitOpCodeByte(kNopOpCode);
  // esp in the ModR/M byte indicates SIB to follow.
  instr.EmitModRMByte(kReg1ByteDisp, 0, kRegisterEsp);
  instr.EmitScaleIndexBaseByte(kTimes1, kRegisterEax, kRegisterEax);
  instr.Emit8BitDisplacement(DisplacementImpl(0, kSize8Bit));
}

void AssemblerImpl::nop7(size_t prefix_count) {
  InstructionBuffer instr(this);
  instr.EmitOperandSizePrefix(prefix_count);
  // 7 bytes: NOP DWORD PTR [EAX + 0] 32-bit offset
  instr.EmitOpCodeByte(kTwoByteOpCodePrefix);
  instr.EmitOpCodeByte(kNopOpCode);
  instr.EmitModRMByte(kReg1WordDisp, 0, kRegisterEax);
  instr.Emit32BitDisplacement(DisplacementImpl(0, kSize32Bit));
}

void AssemblerImpl::nop8(size_t prefix_count) {
  InstructionBuffer instr(this);
  instr.EmitOperandSizePrefix(prefix_count);
  // 8 bytes: NOP DWORD PTR [EAX + EAX * 1 + 0] 32-bit offset
  instr.EmitOpCodeByte(kTwoByteOpCodePrefix);
  instr.EmitOpCodeByte(kNopOpCode);
  // esp in the ModR/M byte indicates SIB to follow.
  instr.EmitModRMByte(kReg1WordDisp, 0, kRegisterEsp);
  instr.EmitScaleIndexBaseByte(kTimes1, kRegisterEax, kRegisterEax);
  instr.Emit32BitDisplacement(DisplacementImpl(0, kSize32Bit));
}

void AssemblerImpl::Output(const InstructionBuffer& instr) {
  serializer_->AppendInstruction(location_,
                                 instr.buf(),
                                 instr.len(),
                                 instr.reference_offsets(),
                                 instr.references(),
                                 instr.num_references());

  location_ += instr.len();
}

}  // namespace core
