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

#include "syzygy/assm/register.h"

namespace assm {

// A register factory.
class RegisterBuilder {
 public:
  static const Register8 Create8(RegisterId id) { return Register8(id); }
  static const Register16 Create16(RegisterId id) { return Register16(id); }
  static const Register32 Create32(RegisterId id) { return Register32(id); }
};

// An array of all registers.
const Register kRegisters[kRegisterCount] = {
    // 8-bit registers.
    RegisterBuilder::Create8(kRegisterAl),
    RegisterBuilder::Create8(kRegisterCl),
    RegisterBuilder::Create8(kRegisterDl),
    RegisterBuilder::Create8(kRegisterBl),
    RegisterBuilder::Create8(kRegisterAh),
    RegisterBuilder::Create8(kRegisterCh),
    RegisterBuilder::Create8(kRegisterDh),
    RegisterBuilder::Create8(kRegisterBh),

    // 16-bit registers.
    RegisterBuilder::Create16(kRegisterAx),
    RegisterBuilder::Create16(kRegisterCx),
    RegisterBuilder::Create16(kRegisterDx),
    RegisterBuilder::Create16(kRegisterBx),
    RegisterBuilder::Create16(kRegisterSp),
    RegisterBuilder::Create16(kRegisterBp),
    RegisterBuilder::Create16(kRegisterSi),
    RegisterBuilder::Create16(kRegisterDi),

    // 32-bit registers.
    RegisterBuilder::Create32(kRegisterEax),
    RegisterBuilder::Create32(kRegisterEcx),
    RegisterBuilder::Create32(kRegisterEdx),
    RegisterBuilder::Create32(kRegisterEbx),
    RegisterBuilder::Create32(kRegisterEsp),
    RegisterBuilder::Create32(kRegisterEbp),
    RegisterBuilder::Create32(kRegisterEsi),
    RegisterBuilder::Create32(kRegisterEdi)
};

// Slices into the array of all registers, by register size.
typedef const Register8 (&Register8Array)[kRegister8Count];
Register8Array kRegisters8 =
    reinterpret_cast<Register8Array>(kRegisters[kRegister8Min]);

typedef const Register16 (&Register16Array)[kRegister16Count];
Register16Array kRegisters16 =
    reinterpret_cast<Register16Array>(kRegisters[kRegister16Min]);

typedef const Register32 (&Register32Array)[kRegister32Count];
Register32Array kRegisters32 =
    reinterpret_cast<Register32Array>(kRegisters[kRegister32Min]);

// Convenience constants for each individual register.
const Register8& al = kRegisters8[0];
const Register8& cl = kRegisters8[1];
const Register8& dl = kRegisters8[2];
const Register8& bl = kRegisters8[3];
const Register8& ah = kRegisters8[4];
const Register8& ch = kRegisters8[5];
const Register8& dh = kRegisters8[6];
const Register8& bh = kRegisters8[7];

const Register16& ax = kRegisters16[0];
const Register16& cx = kRegisters16[1];
const Register16& dx = kRegisters16[2];
const Register16& bx = kRegisters16[3];
const Register16& sp = kRegisters16[4];
const Register16& bp = kRegisters16[5];
const Register16& si = kRegisters16[6];
const Register16& di = kRegisters16[7];

const Register32& eax = kRegisters32[0];
const Register32& ecx = kRegisters32[1];
const Register32& edx = kRegisters32[2];
const Register32& ebx = kRegisters32[3];
const Register32& esp = kRegisters32[4];
const Register32& ebp = kRegisters32[5];
const Register32& esi = kRegisters32[6];
const Register32& edi = kRegisters32[7];

const Register& Register::Get(RegisterId id) {
  DCHECK_LE(kRegisterMin, id);
  DCHECK_GT(kRegisterMax, id);
  return kRegisters[id];
}

const Register8& CastAsRegister8(const Register& reg) {
  DCHECK_EQ(kSize8Bit, reg.size());
  return reinterpret_cast<const Register8&>(reg);
}

const Register16& CastAsRegister16(const Register& reg) {
  DCHECK_EQ(kSize16Bit, reg.size());
  return reinterpret_cast<const Register16&>(reg);
}

const Register32& CastAsRegister32(const Register& reg) {
  DCHECK_EQ(kSize32Bit, reg.size());
  return reinterpret_cast<const Register32&>(reg);
}

}  // namespace assm
