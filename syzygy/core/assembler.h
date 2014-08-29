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
//
// This file declares implementation classes to generate assembly code.
// The API to the assembler is intentionally very close to the API exposed
// by the V8 assembler (see src/ia32/assembler-ia32.* in V8 repository).

#ifndef SYZYGY_CORE_ASSEMBLER_H_
#define SYZYGY_CORE_ASSEMBLER_H_

#include "syzygy/core/register.h"

namespace core {

// The condition codes by which conditional branches are determined. This enum
// is taken from the V8 project, and has the property that the conditions are
// defined to be bit-wise ORed into the base conditional branch opcode, and
// they can be easily negated/inverted.
//
// See:
//     http://code.google.com/p/v8/source/browse/trunk/src/ia32/assembler-ia32.h
enum ConditionCode {
  // Any value < 0 is considered no_condition
  kNoCondition  = -1,

  kOverflow =  0,
  kNoOverflow =  1,
  kBelow =  2,
  kAboveEqual =  3,
  kEqual =  4,
  kNotEqual =  5,
  kBelowEqual =  6,
  kAbove =  7,
  kNegative =  8,
  kPositive =  9,
  kParityEven = 10,
  kParityOdd = 11,
  kLess = 12,
  kGreaterEqual = 13,
  kLessEqual = 14,
  kGreater = 15,

  // Aliases.
  kCarry = kBelow,
  kNotCarry = kAboveEqual,
  kZero = kEqual,
  kNotZero = kNotEqual,
  kSign = kNegative,
  kNotSign = kPositive,

  // Extents.
  kMinConditionCode = 0,
  kMaxConditionCode = 15
};

// The conditions on which a loop instruction should branch. These are modeled
// in the same manner as ConditionCode (above).
enum LoopCode {
  kLoopOnCounterAndNotZeroFlag = 0,  // LOOPNE and LOOPNZ
  kLoopOnCounterAndZeroFlag = 1,  // LOOPE and NOOPZ.
  kLoopOnCounter = 2,  // LOOP.
};

inline ConditionCode NegateConditionCode(ConditionCode cc) {
  DCHECK_GT(16, cc);
  return static_cast<ConditionCode>(cc ^ 1);
}

// Selects a scale for the Operand addressing modes.
// The values match the encoding in the x86 SIB bytes.
enum ScaleFactor {
  kTimes1 = 0,
  kTimes2 = 1,
  kTimes4 = 2,
  kTimes8 = 3,
};

// We use the same enum for value sizes.
typedef RegisterSize ValueSize;

// An instance of this class is an explicit value, which is either
// an immediate or a displacement.
class ValueImpl {
 public:
  ValueImpl();
  ValueImpl(uint32 value, ValueSize size);
  ValueImpl(uint32 value, ValueSize size, const void* imm_ref);

  // @name Accessors.
  // @{
  uint32 value() const { return value_; }
  const void* reference() const { return reference_; }
  ValueSize size() const { return size_; }
  // @}

  // Comparison operator.
  bool operator==(const ValueImpl& rhs) const;

 private:
  uint32 value_;
  const void* reference_;
  ValueSize size_;
};

// Displacements and immediates behave near-identically, but are semantically
// slightly different.
typedef ValueImpl ImmediateImpl;
typedef ValueImpl DisplacementImpl;

// An operand implies indirection to memory through one of the myriad
// modes supported by IA32.
class OperandImpl {
 public:
  // A register-indirect mode.
  explicit OperandImpl(const Register32& base);

  // A register-indirect with displacement mode.
  OperandImpl(const Register32& base, const DisplacementImpl& displ);

  // A displacement-only mode.
  explicit OperandImpl(const DisplacementImpl& displ);

  // The full [base + index * scale + displ32] mode.
  // @note esp cannot be used as an index register.
  OperandImpl(const Register32& base,
              const Register32& index,
              ScaleFactor scale,
              const DisplacementImpl& displ);

  // The [base + index * scale] mode.
  // @note esp cannot be used as an index register.
  OperandImpl(const Register32& base,
              const Register32& index,
              ScaleFactor scale);

  // The [index * scale + displ32] mode - e.g. no base.
  // @note esp cannot be used as an index register.
  OperandImpl(const Register32& index,
              ScaleFactor scale,
              const DisplacementImpl& displ);

  // Low-level constructor, none of the parameters are checked.
  OperandImpl(RegisterId base,
              RegisterId index,
              ScaleFactor scale,
              const DisplacementImpl& displacement);

  // @name Accessors.
  // @{
  RegisterId base() const { return base_; }
  RegisterId index() const { return index_; }
  ScaleFactor scale() const { return scale_; }
  const DisplacementImpl& displacement() const { return displacement_; }
  // @}

 private:
  // The base register involved, or none.
  RegisterId base_;
  // The index register involved, or none.
  RegisterId index_;
  // The scaling factor, must be kTimes1 if no index register.
  ScaleFactor scale_;
  // The displacement, if any.
  DisplacementImpl displacement_;
};

// The assembler takes care of maintaining an output location (address), and
// generating a stream of bytes and references as instructions are assembled.
class AssemblerImpl {
 public:
  // The assembler pushes instructions and references to
  // one of these for serialization.
  class InstructionSerializer {
   public:
    virtual void AppendInstruction(uint32 location,
                                   const uint8* bytes,
                                   size_t num_bytes,
                                   const size_t *ref_locations,
                                   const void* const* refs,
                                   size_t num_refs) = 0;
  };

  // Constructs an assembler that assembles to @p delegate
  // starting at @p location.
  AssemblerImpl(uint32 location, InstructionSerializer* serializer);

  // @name Accessors.
  // @{
  uint32 location() const { return location_; }
  void set_location(uint32 location) { location_ = location; }
  // @}

  // Emits one or more NOP instructions, their total length being @p size
  // bytes.
  // @param size The number of bytes of NOPs to generate.
  // @note For a generated NOP sequence of optimal performance it is best to
  //     call nop once rather than successively (ie: the NOP sequence generated
  //     by nop(x) nop(y) may perform worse than that generated by nop(x + y).
  void nop(size_t size);

  // @name Call instructions.
  // @{
  void call(const ImmediateImpl& dst);
  void call(const OperandImpl& dst);
  // @}

  // @name Control flow instructions.
  // @{
  void j(ConditionCode cc, const ImmediateImpl& dst);
  void jecxz(const ImmediateImpl& dst);
  void jmp(const ImmediateImpl& dst);
  void jmp(const OperandImpl& dst);
  void l(LoopCode lc, const ImmediateImpl& dst);
  void ret();
  void ret(uint16 n);
  // @}

  // @name Set flags.
  // @{
  void set(ConditionCode cc, const Register32& src);
  // @}

  // @name Byte mov varieties.
  // @{
  void mov_b(const OperandImpl& dst, const ImmediateImpl& src);
  void movzx_b(const Register32& dst, const OperandImpl& src);
  // @}

  // @name Double-word mov varieties.
  // @{
  void mov(const Register32& dst, const Register32& src);
  void mov(const Register32& dst, const OperandImpl& src);
  void mov(const OperandImpl& dst, const Register32& src);
  void mov(const Register32& dst, const ImmediateImpl& src);
  void mov(const OperandImpl& dst, const ImmediateImpl& src);
  void mov_fs(const Register32& dst, const OperandImpl& src);
  void mov_fs(const OperandImpl& dst, const Register32& src);
  // @}

  // @name Load effective address.
  void lea(const Register32& dst, const OperandImpl& src);

  // @name Stack manipulation.
  // @{
  void push(const Register32& src);
  void push(const ImmediateImpl& src);
  void push(const OperandImpl& src);
  void pushad();

  void pop(const Register32& dst);
  void pop(const OperandImpl& dst);
  void popad();
  // @}

  // @name Flag manipulation.
  // @{
  void pushfd();
  void popfd();
  void lahf();
  void sahf();
  // @}

  // @name Arithmetic operations.
  // @{
  void test(const Register8& dst, const Register8& src);
  void test(const Register8& dst, const ImmediateImpl& src);

  void test(const Register32& dst, const Register32& src);
  void test(const Register32& dst, const OperandImpl& src);
  void test(const OperandImpl& dst, const Register32& src);
  void test(const Register32& dst, const ImmediateImpl& src);
  void test(const OperandImpl& dst, const ImmediateImpl& src);

  void cmp(const Register8& dst, const Register8& src);
  void cmp(const Register8& dst, const ImmediateImpl& src);

  void cmp(const Register32& dst, const Register32& src);
  void cmp(const Register32& dst, const OperandImpl& src);
  void cmp(const OperandImpl& dst, const Register32& src);
  void cmp(const Register32& dst, const ImmediateImpl& src);
  void cmp(const OperandImpl& dst, const ImmediateImpl& src);

  void add(const Register8& dst, const Register8& src);
  void add(const Register8& dst, const ImmediateImpl& src);

  void add(const Register32& dst, const Register32& src);
  void add(const Register32& dst, const OperandImpl& src);
  void add(const OperandImpl& dst, const Register32& src);
  void add(const Register32& dst, const ImmediateImpl& src);
  void add(const OperandImpl& dst, const ImmediateImpl& src);

  void sub(const Register8& dst, const Register8& src);
  void sub(const Register8& dst, const ImmediateImpl& src);

  void sub(const Register32& dst, const Register32& src);
  void sub(const Register32& dst, const OperandImpl& src);
  void sub(const OperandImpl& dst, const Register32& src);
  void sub(const Register32& dst, const ImmediateImpl& src);
  void sub(const OperandImpl& dst, const ImmediateImpl& src);
  // @}

  // @name Shifting operations.
  // @{
  void shl(const Register32& dst, const ImmediateImpl& src);
  void shr(const Register32& dst, const ImmediateImpl& src);
  // @}

  // Exchange contents of two registers.
  // @param dst The destination register.
  // @param src The source register.
  // @note Exchanges involving eax generate shorter byte code.
  // @note This instruction can be used as a primitive for writing
  //     synchronization mechanisms as there is an implicit lock taken
  //     during execution.
  void xchg(const Register32& dst, const Register32& src);
  void xchg(const Register16& dst, const Register16& src);
  void xchg(const Register8& dst, const Register8& src);

  // @name Aliases
  // @{
  void loop(const ImmediateImpl& dst) { l(kLoopOnCounter, dst); }
  void loope(const ImmediateImpl& dst) { l(kLoopOnCounterAndZeroFlag, dst); }
  void loopne(const ImmediateImpl& dst) {
    l(kLoopOnCounterAndNotZeroFlag, dst);
  }
  // @}

  // Size of an 8 bit reach branch opcode.
  static const size_t kShortBranchOpcodeSize;
  // Size of an 8 bit reach branch.
  static const size_t kShortBranchSize;

  // Size of a 32 bit reach branch op code.
  static const size_t kLongBranchOpcodeSize;
  // Size of an 8bit reach branch.
  static const size_t kLongBranchSize;

  // Size of an 8 bit reach jump opcode.
  static const size_t kShortJumpOpcodeSize;
  // Size of an 8 bit reach jump.
  static const size_t kShortJumpSize;

  // Size of a 32 bit reach jump op code.
  static const size_t kLongJumpOpcodeSize;
  // Size of an 8bit reach jump.
  static const size_t kLongJumpSize;

  // The maximum length a single instruction will assemble to.
  // No instruction on x86 can exceed 15 bytes, per specs.
  static const size_t kMaxInstructionLength = 15;

 private:
  class InstructionBuffer;

  // @name Nop instruction helpers.
  // @{
  // Each of these corresponds to a basic suggested NOP sequence. They
  // can each be extended by prefixing with 1 or more operand size (0x66)
  // prefixes. These are not exposed directly as the user should simply
  // call 'nop' instead.
  // @param prefix_count The number of operand size prefix bytes to apply.
  void nop1(size_t prefix_count);
  void nop4(size_t prefix_count);
  void nop5(size_t prefix_count);
  void nop7(size_t prefix_count);
  void nop8(size_t prefix_count);
  // @}

  // Output the instruction data in @p instr to our delegate.
  void Output(const InstructionBuffer& instr);

  // Stores the current location of assembly.
  uint32 location_;

  // The delegate we push instructions at.
  InstructionSerializer* serializer_;
};

}  // namespace core

#endif  // SYZYGY_CORE_ASSEMBLER_H_
