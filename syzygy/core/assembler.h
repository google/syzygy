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
//
// This file declares implementation classes to generate assembly code.
// The API to the assembler is intentionally very close to the API exposed
// by the V8 assembler.

#ifndef SYZYGY_CORE_ASSEMBLER_H_
#define SYZYGY_CORE_ASSEMBLER_H_

#include "base/basictypes.h"
#include "base/logging.h"

namespace core {

enum ScaleFactor;
enum RegisterCode;

enum RegisterCode {
  kRegisterNone = -1,
  kRegisterEax = 0,
  kRegisterEcx = 1,
  kRegisterEdx = 2,
  kRegisterEbx = 3,
  kRegisterEsp = 4,
  kRegisterEbp = 5,
  kRegisterEsi = 6,
  kRegisterEdi = 7,
};

// Each instance of this class names a register.
class Register {
 public:
  explicit Register(RegisterCode code) : code_(code) {
    DCHECK(code != kRegisterNone);
  }

  RegisterCode code() const { return code_; }
  void set_code(RegisterCode code) { code_ = code; }

 private:
  RegisterCode code_;
};

// Convenience constants for the x86 registers.
extern const Register eax;
extern const Register ecx;
extern const Register edx;
extern const Register ebx;
extern const Register esp;
extern const Register ebp;
extern const Register esi;
extern const Register edi;

// Selects a scale for the Operand addressing modes.
enum ScaleFactor {
  times_1 = 0,
  times_2 = 1,
  times_4 = 2,
  times_8 = 3,
};

// An operand implies indirection to memory through one of the myriad
// modes supported by IA32.
// TODO(siggi): As-is, this only supports 32 bit displacements, figure out
//     interface and implementation for 8 bit displacements.
class OperandImpl {
 public:
  // A register-indirect mode.
  explicit OperandImpl(Register base);

  // A register-indirect with displacement mode.
  OperandImpl(Register base,
              uint32 displacement,
              const void* displacement_ref);

  // A displacement-only mode.
  OperandImpl(uint32 displacement,
              const void* displacement_ref);

  // The full [base + index * scale + displ32] mode.
  // @note esp cannot be used as an index register.
  OperandImpl(Register base,
              Register index,
              ScaleFactor scale,
              uint32 displacement,
              void* displacement_ref);

  // @name Accessors.
  // @{
  RegisterCode base() const { return base_; }
  RegisterCode index() const { return index_; }
  ScaleFactor scale() const { return scale_; }
  const uint32 displacement() const { return displacement_; }
  const void* displacement_ref() const { return displacement_ref_; }
  // @}

 private:
  // The base register involved, or none.
  RegisterCode base_;
  // The index register involved, or none.
  RegisterCode index_;
  // The scaling factor, must be times_1 if no index register.
  ScaleFactor scale_;
  // The displacement, if any.
  uint32 displacement_;
  // The reference/relocation information for the displacement.
  const void* displacement_ref_;
};

// An instance of this class is an immediate operand.
// TODO(siggi): As-is, this only supports 32 bit immediate values, figure out
//     interface and implementation for 8 bit immediates.
class ImmediateImpl {
 public:
  explicit ImmediateImpl(uint32 imm);
  ImmediateImpl(uint32 imm, const void* imm_ref);

  // @name Accessors.
  // @{
  uint32 imm() const { return imm_; }
  const void* imm_ref() const { return imm_ref_; }
  // @}

 private:
  uint32 imm_;
  const void* imm_ref_;
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

  // @name mov in several varieties.
  // @{
  void mov(Register dst, Register src);
  void mov(Register dst, const OperandImpl& src);
  void mov(const OperandImpl& dst, Register src);
  void mov(Register dst, const ImmediateImpl& src);
  // @}

 private:
  class InstructionBuffer;
  // Output the instruction data in @p instr to our delegate.
  void Output(const InstructionBuffer& instr);

  // Encode the operands in @p op1 and @p op2 to ModR/W, SIB and displacement
  // bytes as appropriate, and append them to @p instr.
  static void EncodeOperands(Register op1,
                             const OperandImpl& op2,
                             InstructionBuffer* instr);

  // Stores the current location of assembly.
  uint32 location_;

  // The delegate we push instructions at.
  InstructionSerializer* serializer_;
};

}  // namespace core

#endif  // SYZYGY_CORE_ASSEMBLER_H_
