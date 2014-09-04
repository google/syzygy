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
// This file declares utility constants for dealing with registers. Clients of
// assembler and BB assembler shouldn't need to look beyond here. If you are
// implementing a transform or analysis that cares about the details of
// registers then you can find more details in register_internal.h.

#ifndef SYZYGY_ASSM_REGISTER_H_
#define SYZYGY_ASSM_REGISTER_H_

#include "syzygy/assm/register_internal.h"

namespace assm {

// Some utility constants.
static const size_t kRegister8Count = kRegister8Max - kRegister8Min;
static const size_t kRegister16Count = kRegister16Max - kRegister16Min;
static const size_t kRegister32Count = kRegister32Max - kRegister32Min;
static const size_t kRegisterCount = kRegisterMax - kRegisterMin;

// An array of all registers, sorted by their RegisterId.
extern const Register kRegisters[kRegisterCount];

// Slices of kRegisters, by register size. These actually refer to the same
// underlying data.
extern const Register8 (&kRegisters8)[kRegister8Count];
extern const Register16 (&kRegisters16)[kRegister16Count];
extern const Register32 (&kRegisters32)[kRegister32Count];

// Convenience constants for the 8-bit x86 registers.
extern const Register8& al;
extern const Register8& cl;
extern const Register8& dl;
extern const Register8& bl;
extern const Register8& ah;
extern const Register8& ch;
extern const Register8& dh;
extern const Register8& bh;

// Convenience constants for the 16-bit x86 registers.
extern const Register16& ax;
extern const Register16& cx;
extern const Register16& dx;
extern const Register16& bx;
extern const Register16& sp;
extern const Register16& bp;
extern const Register16& si;
extern const Register16& di;

// Convenience constants for the 32-bit x86 registers.
extern const Register32& eax;
extern const Register32& ecx;
extern const Register32& edx;
extern const Register32& ebx;
extern const Register32& esp;
extern const Register32& ebp;
extern const Register32& esi;
extern const Register32& edi;

// Utility functions for casting between registers at differing precisions. This
// is only safe to call if the object is of the requested derived type.
// @returns true if the conversion is possible, false otherwise.
const Register8& CastAsRegister8(const Register& reg);
const Register16& CastAsRegister16(const Register& reg);
const Register32& CastAsRegister32(const Register& reg);

}  // namespace assm

#endif  // SYZYGY_ASSM_REGISTER_H_
