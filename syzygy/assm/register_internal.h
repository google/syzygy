// Copyright 2013 Google Inc. All Rights Reserved.
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
// This file declares the internal implementation details for classes that are
// used to represent general purpose X86 registers. They are intended to be used
// with the X86 assembly utilities declared in assembler.h, and are of no real
// use on their own.
//
// The design of the register class has been crafted to allow easy extension
// for X86-64 registers if the time comes.
//
// For converting between Syzygy registers and Distorm RegisterType refer to the
// utilities in disassembler_util.

#ifndef SYZYGY_ASSM_REGISTER_INTERNAL_H_
#define SYZYGY_ASSM_REGISTER_INTERNAL_H_

#include "base/logging.h"

namespace assm {

// An enum of known registers. The enums guarantee unique values for each
// register at each precision. These are not intended to be used directly, but
// can be used for iterating over known registers in static analysis, for
// example.
//
// This enum has been constructed such that the lower 3-bits represents the
// code associated with the register, which is used in ModR/M and SIB bytes.
enum RegisterId {
  kRegisterNone = -1,

  // 8-bit registers.
  kRegisterAl = 0,
  kRegisterCl = 1,
  kRegisterDl = 2,
  kRegisterBl = 3,
  kRegisterAh = 4,
  kRegisterCh = 5,
  kRegisterDh = 6,
  kRegisterBh = 7,

  // 16-bit registers.
  kRegisterAx = 8,
  kRegisterCx = 9,
  kRegisterDx = 10,
  kRegisterBx = 11,
  kRegisterSp = 12,
  kRegisterBp = 13,
  kRegisterSi = 14,
  kRegisterDi = 15,

  // 32-bit registers.
  kRegisterEax = 16,
  kRegisterEcx = 17,
  kRegisterEdx = 18,
  kRegisterEbx = 19,
  kRegisterEsp = 20,
  kRegisterEbp = 21,
  kRegisterEsi = 22,
  kRegisterEdi = 23,

  // Ranges for various register types. These come at the end so that
  // preferentially the debugger will show proper register IDs for overloaded
  // enum values.
  kRegisterMin = 0,
  kRegister8Min = 0,
  kRegister8Max = 8,
  kRegister16Min = 8,
  kRegister16Max = 16,
  kRegister32Min = 16,
  kRegister32Max = 24,
  kRegisterMax = 24
};

// We use another enum for register code simply for type safety. This makes it
// so that we can't accidentally use a RegisterId or a uint8_t as a
// RegisterCode.
enum RegisterCode {
  kRegisterCode000 = 0,
  kRegisterCode001 = 1,
  kRegisterCode010 = 2,
  kRegisterCode011 = 3,
  kRegisterCode100 = 4,
  kRegisterCode101 = 5,
  kRegisterCode110 = 6,
  kRegisterCode111 = 7
};

// Register sizes. The values double as the actual number of bits.
enum RegisterSize {
  kSizeNone = 0,
  kSize8Bit = 8,
  kSize16Bit = 16,
  kSize32Bit = 32,
};

// The base class of all registers.
class Register {
 public:
  // @returns the unique ID of this register.
  RegisterId id() const { return id_; }

  // @returns the size of this register.
  RegisterSize size() const { return size_; }

  // @returns the code associated with this register.
  // @note This is not unique, with multiple registers of different precisions
  //     having the same code.
  RegisterCode code() const { return Code(id_); }

  // Utility function for getting the code associated with the given register
  // ID.
  static const RegisterCode Code(RegisterId id) {
    return RegisterCode(id & 0x7);
  }

  // Utility function for getting the register with the given ID.
  static const Register& Get(RegisterId id);

  // @name Comparison operators.
  // @{
  bool operator==(const Register& reg) const {
    return id_ == reg.id_ && size_ == reg.size_;
  }
  bool operator!=(const Register& reg) const {
    return !operator==(reg);
  }
  // @}

 protected:
  Register(RegisterId id, RegisterSize size) : id_(id), size_(size) {
    DCHECK_NE(kRegisterNone, id);
    DCHECK_NE(kSizeNone, size);
  }

 private:
  RegisterId id_;
  RegisterSize size_;
};

// A templated implementation class for register objects. This is parameterized
// based on the register sizes so that registers of different sizes have
// different types.
// @tparam register_size The size of the register, in bits.
template<RegisterSize register_size>
class RegisterImpl : public Register {
 protected:
  // This class acts as registry factory in the .cc file.
  friend class RegisterBuilder;

  // Constructor. This is protected so that clients don't try to manually
  // construct register objects, but instead use the provided static register
  // objects.
  explicit RegisterImpl(RegisterId id) : Register(id, register_size) {
  }
};

// We declare different types for registers so that assembler functions can be
// type checked. Functions that can seamlessly handle registers of various sizes
// can simply accept object of type Register, and query them directly for size
// information.
typedef RegisterImpl<kSize8Bit> Register8;
typedef RegisterImpl<kSize16Bit> Register16;
typedef RegisterImpl<kSize32Bit> Register32;

}  // namespace assm

#endif  // SYZYGY_ASSM_REGISTER_INTERNAL_H_
