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

#ifndef SYZYGY_ASSM_ASSEMBLER_BASE_IMPL_H_
#define SYZYGY_ASSM_ASSEMBLER_BASE_IMPL_H_

#ifndef SYZYGY_ASSM_ASSEMBLER_BASE_H_
#error Do not include this file directly.
#endif  // SYZYGY_ASSM_ASSEMBLER_BASE_H_

#include <stdint.h>
#include <limits>

#include "syzygy/assm/const.h"

namespace assm {

// This class is used to buffer a single instruction during its creation.
// TODO(siggi): Add a small state machine in debug mode to ensure the
//     correct order of invocation to opcode/modrm etc.
// @note @p ReferenceType must either be a pointer type, or else have
//     a method bool IsValid() const.
template <class ReferenceType>
class AssemblerBase<ReferenceType>::InstructionBuffer {
 public:
  explicit InstructionBuffer(AssemblerBase* assm);
  ~InstructionBuffer();

  // @name Accessors.
  // @{
  uint32_t len() const { return len_; }
  const uint8_t* buf() const { return buf_; }
  size_t num_reference_infos() const { return num_reference_infos_; }
  const ReferenceInfo* reference_infos() const { return reference_infos_; }
  // @}

  // Emits operand size prefix (0x66) bytes.
  // @param count The number of operand size prefix bytes to emit.
  void EmitOperandSizePrefix(size_t count);
  // Emit an opcode byte.
  void EmitOpCodeByte(uint8_t opcode);
  // Emit a ModR/M byte with an opcode extension.
  void EmitModRMByte(Mod mod, uint8_t op, RegisterId reg1);
  // Emit a ModR/M byte with a destination register.
  void EmitModRMByte(Mod mod, RegisterId reg2, RegisterId reg1);
  // Emit a SIB byte.
  void EmitScaleIndexBaseByte(ScaleFactor scale,
                              RegisterId index,
                              RegisterId base);
  // Emit an operand.
  void EmitOperand(uint8_t reg_op, const Operand& op);

  // Emit an 8-bit displacement, with optional reference info.
  void Emit8BitDisplacement(const Displacement& disp);
  // Emit an 8-bit immediate, with optional reference info.
  void Emit8BitImmediate(const Immediate& disp);

  // Emit a 32-bit displacement with optional reference info.
  void Emit32BitDisplacement(const Displacement& disp);

  // Emit a 32-bit immediate with optional reference info.
  void Emit32BitImmediate(const Immediate& disp);

  // Emit an 8-bit PC-relative value.
  void Emit8BitPCRelative(uint32_t location, const Immediate& imm);

  // Emit a 32-bit PC-relative value.
  void Emit32BitPCRelative(uint32_t location, const Immediate& imm);

  // Emit a 16-bit immediate value.
  void Emit16BitValue(uint16_t value);

  // Emit an arithmetic instruction with various encoding.
  void EmitArithmeticInstruction(uint8_t op,
                                 const Register& dst,
                                 const Register& src);
  void EmitArithmeticInstruction(uint8_t op,
                                 const Register& dst,
                                 const Operand& src);
  void EmitArithmeticInstruction(uint8_t op,
                                 const Operand& dst,
                                 const Register32& src);
  void EmitArithmeticInstructionToRegister32(uint8_t op_eax,
                                             uint8_t op_8,
                                             uint8_t op_32,
                                             uint8_t sub_op,
                                             const Register32& dst,
                                             const Immediate& src);
  void EmitArithmeticInstructionToRegister8(uint8_t op_eax,
                                            uint8_t op_8,
                                            uint8_t sub_op,
                                            const Register8& dst,
                                            const Immediate& src);
  void EmitArithmeticInstructionToOperand(uint8_t op_8,
                                          uint8_t op_32,
                                          uint8_t sub_op,
                                          const Operand& dst,
                                          const Immediate& src);

  // Emit an arithmetic instruction with 3 operands.
  void EmitThreeOperandArithmeticInstructionToRegister32(
      uint8_t op,
      const Register32& dst,
      const Register32& src,
      const Immediate& index);

  // Emit an XCHG instruction.
  void EmitXchg(ValueSize size, RegisterId dst, RegisterId src);

  // Add reference at current location.
  void AddReference(const ReferenceType& reference,
                    RegisterSize size,
                    bool pc_relative);

 protected:
  void EmitByte(uint8_t byte);

  AssemblerBase* asm_;
  size_t num_reference_infos_;
  ReferenceInfo reference_infos_[2];
  uint32_t len_;
  uint8_t buf_[kMaxInstructionLength];
};

namespace details {

template <class ReferenceType>
bool IsValidReference(const ReferenceType* ref) {
  return ref != NULL;
}

template <class ReferenceType>
bool IsValidReference(const ReferenceType& ref) {
  return ref.IsValid();
}

}  // namespace details

// Returns true if @p operand is a displacement only - e.g.
// specifies neither a base, nor an index register.
template <class ReferenceType>
bool IsDisplacementOnly(const OperandBase<ReferenceType>& operand) {
  return operand.displacement().size() != kSizeNone &&
      operand.base() == kRegisterNone &&
      operand.index() == kRegisterNone;
}

template <class ReferenceType>
AssemblerBase<ReferenceType>::InstructionBuffer::InstructionBuffer(
    AssemblerBase* assm) : asm_(assm), len_(0), num_reference_infos_(0) {
  DCHECK(assm != NULL);
#ifndef NDEBUG
  // Initialize the buffer in debug mode for easier debugging.
  ::memset(buf_, 0xCC, sizeof(buf_));
#endif
}

template <class ReferenceType>
AssemblerBase<ReferenceType>::InstructionBuffer::~InstructionBuffer() {
  asm_->Output(*this);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::InstructionBuffer::EmitOperandSizePrefix(
    size_t count) {
  for (size_t i = 0; i < count; ++i)
    EmitByte(kOperandSizePrefix);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::InstructionBuffer::EmitOpCodeByte(
    uint8_t opcode) {
  EmitByte(opcode);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::InstructionBuffer::EmitModRMByte(
    Mod mod,
    uint8_t reg_op,
    RegisterId reg1) {
  DCHECK_LE(reg_op, 8);
  DCHECK_NE(kRegisterNone, reg1);
  EmitByte((mod << 6) | (reg_op << 3) | Register::Code(reg1));
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::InstructionBuffer::EmitModRMByte(
    Mod mod, RegisterId reg2, RegisterId reg1) {
  DCHECK_NE(kRegisterNone, reg2);
  DCHECK_NE(kRegisterNone, reg1);
  EmitModRMByte(mod, Register::Code(reg2), reg1);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::InstructionBuffer::EmitScaleIndexBaseByte(
    ScaleFactor scale, RegisterId index, RegisterId base) {
  DCHECK_NE(kRegisterNone, index);
  DCHECK_NE(kRegisterNone, base);

  EmitByte((scale << 6) | (Register::Code(index) << 3) | Register::Code(base));
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::InstructionBuffer::EmitOperand(
    uint8_t reg_op,
    const Operand& op) {
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
          Emit8BitDisplacement(
              Displacement(0, kSize8Bit, ReferenceType()));
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

template <class ReferenceType>
void AssemblerBase<ReferenceType>::InstructionBuffer::Emit8BitDisplacement(
    const Displacement& disp) {
  DCHECK(disp.size() == kSize8Bit);

  AddReference(disp.reference(), kSize8Bit, false);

  EmitByte(disp.value());
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::InstructionBuffer::Emit8BitImmediate(
    const Immediate& imm) {
  DCHECK(imm.size() == kSize8Bit);

  AddReference(imm.reference(), kSize8Bit, false);

  EmitByte(imm.value());
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::InstructionBuffer::Emit32BitDisplacement(
    const Displacement& disp) {
  AddReference(disp.reference(), kSize32Bit, false);

  uint32_t value = disp.value();
  EmitByte(value);
  EmitByte(value >> 8);
  EmitByte(value >> 16);
  EmitByte(value >> 24);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::InstructionBuffer::Emit32BitImmediate(
    const Immediate& imm) {
  AddReference(imm.reference(), kSize32Bit, false);

  uint32_t value = imm.value();
  EmitByte(value);
  EmitByte(value >> 8);
  EmitByte(value >> 16);
  EmitByte(value >> 24);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::InstructionBuffer::Emit8BitPCRelative(
    uint32_t location,
    const Immediate& imm) {
  DCHECK_EQ(kSize8Bit, imm.size());

  AddReference(imm.reference(), kSize8Bit, true);

  // Turn the absolute imm into a imm relative to the address of
  // the end of the emitted constant.
  int32_t relative_value = imm.value() - (location + len_ + 1);
  DCHECK_LE(std::numeric_limits<int8_t>::min(), relative_value);
  DCHECK_GE(std::numeric_limits<int8_t>::max(), relative_value);
  EmitByte(relative_value);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::InstructionBuffer::Emit32BitPCRelative(
    uint32_t location,
    const Immediate& imm) {
  DCHECK_EQ(kSize32Bit, imm.size());

  AddReference(imm.reference(), kSize32Bit, true);

  // Turn the absolute imm into a imm relative to the address of
  // the end of the emitted constant.
  uint32_t relative_value = static_cast<uint32_t>(imm.value() -
                                                  (location + len_ + 4));
  EmitByte(relative_value);
  EmitByte(relative_value >> 8);
  EmitByte(relative_value >> 16);
  EmitByte(relative_value >> 24);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::InstructionBuffer::Emit16BitValue(
    uint16_t value) {
  EmitByte(value);
  EmitByte(value >> 8);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::InstructionBuffer::EmitArithmeticInstruction(
    uint8_t op,
    const Register& dst,
    const Register& src) {
  DCHECK_EQ(dst.size(), src.size());
  EmitOpCodeByte(op);
  EmitModRMByte(kReg1, dst.id(), src.id());
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::InstructionBuffer::EmitArithmeticInstruction(
    uint8_t op,
    const Register& dst,
    const Operand& src) {
  EmitOpCodeByte(op);
  EmitOperand(dst.code(), src);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::InstructionBuffer::EmitArithmeticInstruction(
    uint8_t op,
    const Operand& dst,
    const Register32& src) {
  EmitOpCodeByte(op);
  EmitOperand(src.code(), dst);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::InstructionBuffer::
    EmitArithmeticInstructionToRegister32(uint8_t op_eax,
                                          uint8_t op_8,
                                          uint8_t op_32,
                                          uint8_t sub_op,
                                          const Register32& dst,
                                          const Immediate& src) {
  if (dst.id() == kRegisterEax && src.size() == kSize32Bit) {
    // Special encoding for EAX.
    EmitOpCodeByte(op_eax);
    Emit32BitImmediate(src);
  } else if (src.size() == kSize8Bit) {
    EmitOpCodeByte(op_8);
    EmitModRMByte(kReg1, sub_op, dst.id());
    Emit8BitImmediate(src);
  } else {
    EmitOpCodeByte(op_32);
    EmitModRMByte(kReg1, sub_op, dst.id());
    Emit32BitImmediate(src);
  }
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::InstructionBuffer::
    EmitArithmeticInstructionToRegister8(uint8_t op_eax,
                                         uint8_t op_8,
                                         uint8_t sub_op,
                                         const Register8& dst,
                                         const Immediate& src) {
  DCHECK(src.size() == kSize8Bit);
  if (dst.code() == kAccumulatorCode) {
    // Special encoding for AL/AX/EAX.
    EmitOpCodeByte(op_eax);
  } else {
    EmitOpCodeByte(op_8);
    EmitModRMByte(kReg1, sub_op, dst.id());
  }
  Emit8BitImmediate(src);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::InstructionBuffer::
    EmitArithmeticInstructionToOperand(uint8_t op_8,
                                       uint8_t op_32,
                                       uint8_t sub_op,
                                       const Operand& dst,
                                       const Immediate& src) {
  if (src.size() == kSize8Bit) {
    EmitOpCodeByte(op_8);
    EmitOperand(sub_op, dst);
    Emit8BitImmediate(src);
  } else {
    EmitOpCodeByte(op_32);
    EmitOperand(sub_op, dst);
    Emit32BitImmediate(src);
  }
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::InstructionBuffer::
    EmitThreeOperandArithmeticInstructionToRegister32(uint8_t op,
                                                      const Register32& dst,
                                                      const Register32& src,
                                                      const Immediate& index) {
  EmitArithmeticInstruction(op, dst, src);
  Emit32BitImmediate(index);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::InstructionBuffer::EmitXchg(
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

template <class ReferenceType>
void AssemblerBase<ReferenceType>::InstructionBuffer::AddReference(
    const ReferenceType& reference, RegisterSize size, bool pc_relative) {
  if (!details::IsValidReference(reference))
    return;

  DCHECK_GT(arraysize(reference_infos_), num_reference_infos_);
  ReferenceInfo& info = reference_infos_[num_reference_infos_];
  info.offset = len();
  info.reference = reference;
  info.size = size;
  info.pc_relative = pc_relative;
  ++num_reference_infos_;
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::InstructionBuffer::EmitByte(uint8_t byte) {
  DCHECK_GT(sizeof(buf_), len_);
  buf_[len_++] = byte;
}

template <class ReferenceType>
AssemblerBase<ReferenceType>::AssemblerBase(uint32_t location,
                                            InstructionSerializer* serializer)
    : location_(location), serializer_(serializer) {
  DCHECK(serializer != NULL);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::nop(size_t size) {
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

template <class ReferenceType>
void AssemblerBase<ReferenceType>::call(const Immediate& dst) {
  InstructionBuffer instr(this);

  instr.EmitOpCodeByte(0xE8);
  instr.Emit32BitPCRelative(location_, dst);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::call(const Operand& dst) {
  InstructionBuffer instr(this);

  instr.EmitOpCodeByte(0xFF);
  instr.EmitOperand(0x2, dst);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::j(ConditionCode cc, const Immediate& dst) {
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

template <class ReferenceType>
bool AssemblerBase<ReferenceType>::j(ConditionCode cc,
                                     Label* label,
                                     RegisterSize size) {
  DCHECK(label != NULL);
  DCHECK_LE(kMinConditionCode, cc);
  DCHECK_GE(kMaxConditionCode, cc);
  DCHECK(size == kSize8Bit || size == kSize32Bit || size == kSizeNone);

  Immediate dst;
  if (label->bound()) {
    // Check whether the short reach is in range.
    // TODO(siggi): Utility function for this.
    int32_t offs = label->location() - (location() + kShortBranchSize);
    if (offs > std::numeric_limits<int8_t>::max() ||
        offs < std::numeric_limits<int8_t>::min()) {
      // Short is out of range, fail if that's requested.
      if (size == kSize8Bit)
        return false;
      // Short is out of range, go long.
      size = kSize32Bit;
    } else {
      // Short is in range, pick short if there's a choice.
      if (size == kSizeNone)
        size = kSize8Bit;
    }

    dst = Immediate(label->location(), size);
  } else {
    if (size == kSizeNone)
      size = kSize32Bit;

    size_t opcode_size = kShortBranchOpcodeSize;
    if (size == kSize32Bit)
      opcode_size = kLongBranchOpcodeSize;

    // The label is not yet bound, declare our use.
    label->Use(location() + opcode_size, size);
    // Point the destination to our own instruction as a debugging aid.
    dst = Immediate(location(), size);
  }

  j(cc, dst);

  return true;
}

template <class ReferenceType>
bool AssemblerBase<ReferenceType>::j(ConditionCode cc, Label* label) {
  return j(cc, label, kSizeNone);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::jecxz(const Immediate& dst) {
  DCHECK_EQ(kSize8Bit, dst.size());
  InstructionBuffer instr(this);
  instr.EmitOpCodeByte(0xE3);
  instr.Emit8BitPCRelative(location_, dst);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::jmp(const Immediate& dst) {
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

template <class ReferenceType>
void AssemblerBase<ReferenceType>::jmp(const Operand& dst) {
  InstructionBuffer instr(this);

  instr.EmitOpCodeByte(0xFF);
  instr.EmitOperand(0x4, dst);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::jmp(const Register32& dst) {
  InstructionBuffer instr(this);

  instr.EmitOpCodeByte(0xFF);
  instr.EmitOpCodeByte(0xE0 | dst.code());
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::l(LoopCode lc, const Immediate& dst) {
  DCHECK_EQ(kSize8Bit, dst.size());
  DCHECK_LE(0, lc);
  DCHECK_GE(2, lc);
  InstructionBuffer instr(this);

  instr.EmitOpCodeByte(0xE0 | lc);
  instr.Emit8BitPCRelative(location_, dst);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::ret() {
  InstructionBuffer instr(this);

  instr.EmitOpCodeByte(0xC3);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::ret(uint16_t n) {
  InstructionBuffer instr(this);

  instr.EmitOpCodeByte(0xC2);
  instr.Emit16BitValue(n);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::set(ConditionCode cc,
                                       const Register32& dst) {
  DCHECK_LE(kMinConditionCode, cc);
  DCHECK_GE(kMaxConditionCode, cc);

  InstructionBuffer instr(this);
  instr.EmitOpCodeByte(kTwoByteOpCodePrefix);
  instr.EmitOpCodeByte(0x90 | cc);

  // AMD64 Architecture Programmers Manual Volume 3: General-Purpose and System
  // Instructions: The reg field in the ModR/M byte is unused.
  const Register32& unused = eax;
  instr.EmitModRMByte(kReg1, unused.id(), dst.id());
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::mov_b(const Operand& dst,
                                         const Immediate& src) {
  InstructionBuffer instr(this);

  instr.EmitOpCodeByte(0xC6);
  instr.EmitOperand(0, dst);
  instr.Emit8BitImmediate(src);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::movzx_b(const Register32& dst,
                                           const Operand& src) {
  InstructionBuffer instr(this);
  instr.EmitOpCodeByte(kTwoByteOpCodePrefix);
  instr.EmitOpCodeByte(0xB6);
  instr.EmitOperand(dst.code(), src);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::mov(const Register32& dst,
                                       const Register32& src) {
  InstructionBuffer instr(this);

  instr.EmitOpCodeByte(0x8B);
  instr.EmitModRMByte(kReg1, dst.id(), src.id());
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::mov(const Register32& dst,
                                       const Operand& src) {
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

template <class ReferenceType>
void AssemblerBase<ReferenceType>::mov(const Operand& dst,
                                       const Register32& src) {
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

template <class ReferenceType>
void AssemblerBase<ReferenceType>::mov(const Register32& dst,
                                       const Immediate& src) {
  DCHECK_NE(kSizeNone, src.size());
  InstructionBuffer instr(this);

  instr.EmitOpCodeByte(0xB8 | dst.code());
  instr.Emit32BitImmediate(src);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::mov(const Operand& dst,
                                       const Immediate& src) {
  InstructionBuffer instr(this);

  instr.EmitOpCodeByte(0xC7);
  instr.EmitOperand(0, dst);
  instr.Emit32BitImmediate(src);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::mov_fs(const Register32& dst,
                                          const Operand& src) {
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

template <class ReferenceType>
void AssemblerBase<ReferenceType>::mov_fs(const Register32& dst,
                                          const Immediate& src) {
  InstructionBuffer instr(this);
  instr.EmitOpCodeByte(kFsSegmentPrefix);

  if (dst.id() == kRegisterEax) {
    // Special encoding for indirect displacement only to EAX.
    instr.EmitOpCodeByte(0xA1);
  } else {
    instr.EmitOpCodeByte(0x8B);
    instr.EmitOpCodeByte(0x1D);
  }
  instr.Emit32BitImmediate(src);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::mov_fs(const Operand& dst,
                                          const Register32& src) {
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

template <class ReferenceType>
void AssemblerBase<ReferenceType>::lea(const Register32& dst,
                                       const Operand& src) {
  InstructionBuffer instr(this);

  instr.EmitOpCodeByte(0x8D);
  instr.EmitOperand(dst.code(), src);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::push(const Register32& src) {
  InstructionBuffer instr(this);

  instr.EmitOpCodeByte(0x50 | src.code());
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::push(const Immediate& src) {
  DCHECK_EQ(kSize32Bit, src.size());
  InstructionBuffer instr(this);

  instr.EmitOpCodeByte(0x68);
  instr.Emit32BitImmediate(src);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::push(const Operand& dst) {
  InstructionBuffer instr(this);

  instr.EmitOpCodeByte(0xFF);
  instr.EmitOperand(0x6, dst);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::pushad() {
  InstructionBuffer instr(this);

  instr.EmitOpCodeByte(0x60);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::pop(const Register32& src) {
  InstructionBuffer instr(this);

  instr.EmitOpCodeByte(0x58 | src.code());
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::pop(const Operand& dst) {
  InstructionBuffer instr(this);

  instr.EmitOpCodeByte(0x8F);
  instr.EmitOperand(0, dst);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::popad() {
  InstructionBuffer instr(this);

  instr.EmitOpCodeByte(0x61);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::pushfd() {
  InstructionBuffer instr(this);
  instr.EmitOpCodeByte(0x9C);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::popfd() {
  InstructionBuffer instr(this);
  instr.EmitOpCodeByte(0x9D);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::lahf() {
  InstructionBuffer instr(this);
  instr.EmitOpCodeByte(0x9F);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::sahf() {
  InstructionBuffer instr(this);
  instr.EmitOpCodeByte(0x9E);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::test(const Register8& dst,
                                        const Register8& src) {
  InstructionBuffer instr(this);
  instr.EmitArithmeticInstruction(0x84, dst, src);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::test(const Register8& dst,
                                        const Immediate& src) {
  InstructionBuffer instr(this);
  instr.EmitArithmeticInstructionToRegister8(0xA8, 0xF6, 0, dst, src);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::test(const Register32& dst,
                                        const Register32& src) {
  InstructionBuffer instr(this);
  instr.EmitArithmeticInstruction(0x85, dst, src);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::test(const Register32& dst,
                                        const Operand& src) {
  // Use commutative property for a smaller encoding.
  test(src, dst);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::test(const Operand& dst,
                                        const Register32& src) {
  InstructionBuffer instr(this);
  instr.EmitArithmeticInstruction(0x85, dst, src);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::test(const Register32& dst,
                                        const Immediate& src) {
  if (src.size() == kSize8Bit) {
    // note: There is no encoding for a 8-bit immediate with 32-bit register.
    test(dst, Immediate(src.value(), kSize32Bit));
  } else {
    InstructionBuffer instr(this);
    instr.EmitArithmeticInstructionToRegister32(0xA9, 0xF7, 0xF7, 0, dst, src);
  }
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::test(const Operand& dst,
                                        const Immediate& src) {
  if (src.size() == kSize8Bit) {
    // note: There is no encoding for a 8-bit immediate with 32-bit register.
    test(dst, Immediate(src.value(), kSize32Bit));
  } else {
    InstructionBuffer instr(this);
    instr.EmitArithmeticInstructionToOperand(0xF7, 0xF7, 0, dst, src);
  }
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::cmp(const Register8& dst,
                                       const Register8& src) {
  InstructionBuffer instr(this);
  instr.EmitArithmeticInstruction(0x3A, dst, src);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::cmp(const Register8& dst,
                                       const Immediate& src) {
  InstructionBuffer instr(this);
  instr.EmitArithmeticInstructionToRegister8(0x3C, 0x80, 7, dst, src);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::cmp(const Register32& dst,
                                       const Register32& src) {
  InstructionBuffer instr(this);
  instr.EmitArithmeticInstruction(0x3B, dst, src);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::cmp(const Register32& dst,
                                       const Operand& src) {
  InstructionBuffer instr(this);
  instr.EmitArithmeticInstruction(0x3B, dst, src);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::cmp(const Operand& dst,
                                       const Register32& src) {
  InstructionBuffer instr(this);
  instr.EmitArithmeticInstruction(0x39, dst, src);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::cmp(const Register32& dst,
                                       const Immediate& src) {
  InstructionBuffer instr(this);
  instr.EmitArithmeticInstructionToRegister32(0x3D, 0x83, 0x81, 7, dst, src);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::cmp(const Operand& dst,
                                       const Immediate& src) {
  InstructionBuffer instr(this);
  instr.EmitArithmeticInstructionToOperand(0x83, 0x81, 7, dst, src);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::add(const Register8& dst,
                                       const Register8& src) {
  InstructionBuffer instr(this);
  instr.EmitArithmeticInstruction(0x02, dst, src);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::add(const Register8& dst,
                                       const Immediate& src) {
  InstructionBuffer instr(this);
  instr.EmitArithmeticInstructionToRegister8(0x04, 0x80, 0, dst, src);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::add(const Register32& dst,
                                       const Register32& src) {
  InstructionBuffer instr(this);
  instr.EmitArithmeticInstruction(0x03, dst, src);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::add(const Register32& dst,
                                       const Operand& src) {
  InstructionBuffer instr(this);
  instr.EmitArithmeticInstruction(0x03, dst, src);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::add(const Operand& dst,
                                       const Register32& src) {
  InstructionBuffer instr(this);
  instr.EmitArithmeticInstruction(0x01, dst, src);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::add(const Register32& dst,
                                       const Immediate& src) {
  InstructionBuffer instr(this);
  instr.EmitArithmeticInstructionToRegister32(0x05, 0x83, 0x81, 0, dst, src);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::add(const Operand& dst,
                                       const Immediate& src) {
  InstructionBuffer instr(this);
  instr.EmitArithmeticInstructionToOperand(0x83, 0x81, 0, dst, src);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::inc(const Operand& dst) {
  InstructionBuffer instr(this);
  instr.EmitOpCodeByte(0xFE);
  instr.EmitOperand(0, dst);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::sub(const Register8& dst,
                                       const Register8& src) {
  InstructionBuffer instr(this);
  instr.EmitArithmeticInstruction(0x2A, dst, src);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::sub(const Register8& dst,
                                       const Immediate& src) {
  InstructionBuffer instr(this);
  instr.EmitArithmeticInstructionToRegister8(0x2C, 0x80, 5, dst, src);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::sub(const Register32& dst,
                                       const Register32& src) {
  InstructionBuffer instr(this);
  instr.EmitArithmeticInstruction(0x2B, dst, src);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::sub(const Register32& dst,
                                       const Operand& src) {
  InstructionBuffer instr(this);
  instr.EmitArithmeticInstruction(0x2B, dst, src);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::sub(const Operand&  dst,
                                       const Register32& src) {
  InstructionBuffer instr(this);
  instr.EmitArithmeticInstruction(0x29, dst, src);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::sub(const Register32& dst,
                                       const Immediate& src) {
  InstructionBuffer instr(this);
  instr.EmitArithmeticInstructionToRegister32(0x2D, 0x83, 0x81, 5, dst, src);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::sub(const Operand&  dst,
                                       const Immediate& src) {
  InstructionBuffer instr(this);
  instr.EmitArithmeticInstructionToOperand(0x83, 0x81, 5, dst, src);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::imul(const Register32& dst,
                                        const Register32& src) {
  InstructionBuffer instr(this);
  instr.EmitOpCodeByte(0x0F);
  instr.EmitArithmeticInstruction(0xAF, dst, src);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::imul(const Register32& dst,
                                        const Operand& src) {
  InstructionBuffer instr(this);
  instr.EmitOpCodeByte(0x0F);
  instr.EmitArithmeticInstruction(0xAF, dst, src);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::imul(const Register32& dst,
                                        const Register32& base,
                                        const Immediate& disp) {
  InstructionBuffer instr(this);
  instr.EmitThreeOperandArithmeticInstructionToRegister32(0x69, dst, base,
                                                          disp);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::and(const Register8& dst,
                                       const Register8& src) {
  InstructionBuffer instr(this);
  instr.EmitArithmeticInstruction(0x20, src, dst);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::and(const Register8& dst,
                                       const Immediate& src) {
  InstructionBuffer instr(this);
  instr.EmitArithmeticInstructionToRegister8(0x24, 0x80, 4, dst, src);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::and(const Register32& dst,
                                       const Register32& src) {
  InstructionBuffer instr(this);
  instr.EmitArithmeticInstruction(0x21, src, dst);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::and(const Register32& dst,
                                       const Operand& src) {
  InstructionBuffer instr(this);
  instr.EmitArithmeticInstruction(0x23, dst, src);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::and(const Operand& dst,
                                       const Register32& src) {
  InstructionBuffer instr(this);
  instr.EmitArithmeticInstruction(0x21, dst, src);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::and(const Register32& dst,
                                       const Immediate& src) {
  InstructionBuffer instr(this);
  instr.EmitArithmeticInstructionToRegister32(0x25, 0x83, 0x81, 4, dst, src);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::and(const Operand& dst,
                                       const Immediate& src) {
  InstructionBuffer instr(this);
  instr.EmitArithmeticInstructionToOperand(0x83, 0x81, 4, dst, src);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::xor(const Register8& dst,
                                       const Register8& src) {
  InstructionBuffer instr(this);
  instr.EmitArithmeticInstruction(0x30, src, dst);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::xor(const Register8& dst,
                                       const Immediate& src) {
  InstructionBuffer instr(this);
  instr.EmitArithmeticInstructionToRegister8(0x34, 0x80, 6, dst, src);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::xor(const Register32& dst,
                                       const Register32& src) {
  InstructionBuffer instr(this);
  instr.EmitArithmeticInstruction(0x31, src, dst);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::xor(const Register32& dst,
                                       const Operand& src) {
  InstructionBuffer instr(this);
  instr.EmitArithmeticInstruction(0x33, dst, src);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::xor(const Operand& dst,
                                       const Register32& src) {
  InstructionBuffer instr(this);
  instr.EmitArithmeticInstruction(0x31, dst, src);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::xor(const Register32& dst,
                                       const Immediate& src) {
  InstructionBuffer instr(this);
  instr.EmitArithmeticInstructionToRegister32(0x35, 0x83, 0x81, 6, dst, src);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::xor(const Operand& dst,
                                       const Immediate& src) {
  InstructionBuffer instr(this);
  instr.EmitArithmeticInstructionToOperand(0x83, 0x81, 6, dst, src);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::shl(const Register32& dst,
                                       const Immediate& src) {
  InstructionBuffer instr(this);
  if (src.value() == 1) {
    instr.EmitOpCodeByte(0xD1);
    instr.EmitModRMByte(kReg1, 4, dst.id());
  } else {
    instr.EmitOpCodeByte(0xC1);
    instr.EmitModRMByte(kReg1, 4, dst.id());
    instr.Emit8BitImmediate(src);
  }
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::shr(const Register32& dst,
                                       const Immediate& src) {
  InstructionBuffer instr(this);
  if (src.value() == 1) {
    instr.EmitOpCodeByte(0xD1);
    instr.EmitModRMByte(kReg1, 5, dst.id());
  } else {
    instr.EmitOpCodeByte(0xC1);
    instr.EmitModRMByte(kReg1, 5, dst.id());
    instr.Emit8BitImmediate(src);
  }
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::xchg(const Register32& dst,
                                        const Register32& src) {
  InstructionBuffer instr(this);
  instr.EmitXchg(kSize32Bit, dst.id(), src.id());
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::xchg(const Register16& dst,
                                        const Register16& src) {
  InstructionBuffer instr(this);
  instr.EmitXchg(kSize16Bit, dst.id(), src.id());
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::xchg(const Register8& dst,
                                        const Register8& src) {
  InstructionBuffer instr(this);
  instr.EmitXchg(kSize8Bit, dst.id(), src.id());
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::xchg(const Register32& dst,
                                        const Operand& src) {
  InstructionBuffer instr(this);
  instr.EmitOpCodeByte(0x87);
  instr.EmitOperand(dst.code(), src);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::nop1(size_t prefix_count) {
  InstructionBuffer instr(this);
  instr.EmitOperandSizePrefix(prefix_count);
  instr.EmitXchg(kSize32Bit, kRegisterEax, kRegisterEax);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::nop4(size_t prefix_count) {
  InstructionBuffer instr(this);
  instr.EmitOperandSizePrefix(prefix_count);
  // 4 bytes: NOP DWORD PTR [EAX + 0] 8-bit offset
  instr.EmitOpCodeByte(kTwoByteOpCodePrefix);
  instr.EmitOpCodeByte(kNopOpCode);
  instr.EmitModRMByte(kReg1ByteDisp, 0, kRegisterEax);
  instr.Emit8BitDisplacement(Displacement(0, kSize8Bit));
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::nop5(size_t prefix_count) {
  InstructionBuffer instr(this);
  instr.EmitOperandSizePrefix(prefix_count);
  // 5 bytes: NOP DWORD PTR [EAX + EAX * 1 + 0] 8-bit offset
  instr.EmitOpCodeByte(kTwoByteOpCodePrefix);
  instr.EmitOpCodeByte(kNopOpCode);
  // esp in the ModR/M byte indicates SIB to follow.
  instr.EmitModRMByte(kReg1ByteDisp, 0, kRegisterEsp);
  instr.EmitScaleIndexBaseByte(kTimes1, kRegisterEax, kRegisterEax);
  instr.Emit8BitDisplacement(Displacement(0, kSize8Bit));
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::nop7(size_t prefix_count) {
  InstructionBuffer instr(this);
  instr.EmitOperandSizePrefix(prefix_count);
  // 7 bytes: NOP DWORD PTR [EAX + 0] 32-bit offset
  instr.EmitOpCodeByte(kTwoByteOpCodePrefix);
  instr.EmitOpCodeByte(kNopOpCode);
  instr.EmitModRMByte(kReg1WordDisp, 0, kRegisterEax);
  instr.Emit32BitDisplacement(Displacement(0, kSize32Bit));
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::nop8(size_t prefix_count) {
  InstructionBuffer instr(this);
  instr.EmitOperandSizePrefix(prefix_count);
  // 8 bytes: NOP DWORD PTR [EAX + EAX * 1 + 0] 32-bit offset
  instr.EmitOpCodeByte(kTwoByteOpCodePrefix);
  instr.EmitOpCodeByte(kNopOpCode);
  // esp in the ModR/M byte indicates SIB to follow.
  instr.EmitModRMByte(kReg1WordDisp, 0, kRegisterEsp);
  instr.EmitScaleIndexBaseByte(kTimes1, kRegisterEax, kRegisterEax);
  instr.Emit32BitDisplacement(Displacement(0, kSize32Bit));
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::data(const uint8_t b) {
  InstructionBuffer instr(this);
  instr.EmitOpCodeByte(b);
}

template <class ReferenceType>
void AssemblerBase<ReferenceType>::Output(const InstructionBuffer& instr) {
  serializer_->AppendInstruction(location_,
                                 instr.buf(),
                                 instr.len(),
                                 instr.reference_infos(),
                                 instr.num_reference_infos());

  location_ += instr.len();
}

template <class ReferenceType>
bool AssemblerBase<ReferenceType>::FinalizeLabel(uint32_t location,
                                                 uint32_t destination,
                                                 RegisterSize size) {
  if (size == kSize8Bit) {
    // Compute the relative value, note that this is computed relative to
    // the end of the PC-relative constant, e.g. from the start of the next
    // instruction.
    int32_t relative_value = destination - (location + 1);
    if (relative_value < std::numeric_limits<int8_t>::min() ||
        relative_value > std::numeric_limits<int8_t>::max()) {
      // Out of bounds...
      return false;
    }
    uint8_t byte = relative_value & 0xFF;
    return serializer_->FinalizeLabel(location, &byte, sizeof(byte));
  } else {
    DCHECK_EQ(kSize32Bit, size);
    int32_t relative_value = destination - (location + 4);

    return serializer_->FinalizeLabel(
        location, reinterpret_cast<const uint8_t*>(&relative_value),
        sizeof(relative_value));
  }
}

}  // namespace assm

#endif  // SYZYGY_ASSM_ASSEMBLER_BASE_IMPL_H_
