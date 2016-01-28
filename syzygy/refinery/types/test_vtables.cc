// Copyright 2015 Google Inc. All Rights Reserved.
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

// A set of classes to experiment with object layout wrt vftables. To obtain
// Visual Studio's object layout use /d1reportAllClassLayout or
// /d1reportSingleClassLayout, eg:
//   cl /c /d1reportSingleClassLayoutNoVirtualMethodUDT test_vtables.cc

#include <cstdint>

#include "syzygy/refinery/types/alias.h"

namespace testing {

// Note: we declare different functions (return different integers) to avoid
// the possibility of vtables overlapping.

// Visual Studio expectation
// class NoVirtualMethodUDT        size(4):
//         +---
//  0      | a
//         +---
struct NoVirtualMethodUDT {
  int a;
  int f();
};

// class NoVirtualMethodChildUDT   size(12):
//         +---
//  0      | {vfptr}
//         | +--- (base class NoVirtualMethodUDT)
//  4      | | a
//         | +---
//  8      | a
//         +---
struct NoVirtualMethodChildUDT : public NoVirtualMethodUDT {
  int a;
  int f();
  virtual int g() { return 0; }
};

// Visual Studio expectation: a vftable pointer at offset 0.
// class VirtualMethodUDT  size(8):
//         +---
//  0      | {vfptr}
//  4      | a
//         +---
struct VirtualMethodUDT {
  int a;
  virtual int f() { return 1; }
};

// Visual Studio expectation: a vftable pointer at offset 0.
// class ChildUDT  size(12):
//         +---
//         | +--- (base class VirtualMethodUDT)
//  0      | | {vfptr}
//  4      | | a
//         | +---
//  8      | b
//         +---
struct ChildUDT : public VirtualMethodUDT {
  int b;
  int f() override { return 2; }
};

// Visual Studio expectation: a class that has virtual functions (possibly
// through inheritance) always has a vftable pointer at offset 0 unless it only
// has these due to virtual bases.

// class VirtualChildUDT   size(16):
//         +---
//  0      | {vbptr}
//  4      | b
//         +---
//         +--- (virtual base VirtualMethodUDT)
//  8      | {vfptr}
// 12      | a
//         +---
struct VirtualChildUDT : virtual VirtualMethodUDT {
  int b;
  int f() override { return 3; }
};

// class VirtualChildWithVirtualMethodUDT  size(20):
//         +---
//  0      | {vfptr}
//  4      | {vbptr}
//  8      | b
//         +---
//         +--- (virtual base VirtualMethodUDT)
// 12      | {vfptr}
// 16      | a
//         +---
struct VirtualChildWithVirtualMethodUDT : virtual VirtualMethodUDT {
  int b;
  int f() override { return 4; }
  virtual int g() { return 5; }
};

// class ComposedUDT       size(16):
//         +---
//  0      | {vfptr}
//  4      | a
//  8      | VirtualMethodUDT udt
//         +---
struct ComposedUDT {
  int a;
  VirtualMethodUDT udt;
  virtual int f() { return 6; }
};

// Interface implementation case.
// class InterfaceImplUDT  size(16):
//         +---
//         | +--- (base class IA)
//  0      | | {vfptr}
//         | +---
//         | +--- (base class IB)
//  4      | | {vfptr}
//         | +---
//         | +--- (base class SimpleBase)
//  8      | | member
//         | +---
// 12      | bar
//         +---
struct IA { virtual int one() = 0; };
struct IB { virtual int two() = 0; };
struct SimpleBase { int member; };
struct InterfaceImplUDT : public SimpleBase, public IA, public IB {
  int bar;
  int one() override { return 7; }
  int two() override { return 8; }
};

void AliasTypes() {
  NoVirtualMethodUDT no_virtual_method_udt = {};
  Alias(&no_virtual_method_udt);
}

// Gets the expected vftable virtual addresses.
// @param buffer_size size of @p vftable_vas
// @param vftable_vas on success, contains the expected vftable virtual
//     addresses.
// @param count on success, the count of returned vftable virtual addresses.
// @returns true on success, false otherwise.
extern "C" bool GetExpectedVftableVAs(unsigned buffer_size,
                                      uint64_t* vftable_vas,
                                      unsigned* count) {
  if (!vftable_vas || !count)
    return false;
  // Validate pointer size.
  if (sizeof(unsigned) != sizeof(unsigned*))
    return false;
  if (buffer_size < 3U)
    return false;

  unsigned cnt = 0U;

  {
    VirtualMethodUDT udt;
    vftable_vas[cnt] =
        static_cast<uint64_t>(*reinterpret_cast<uintptr_t*>(&udt));
    cnt++;
  }

  {
    ComposedUDT udt;
    vftable_vas[cnt] =
        static_cast<uint64_t>(*reinterpret_cast<uintptr_t*>(&udt));
    cnt++;
  }

  {
    VirtualChildWithVirtualMethodUDT udt;
    vftable_vas[cnt] =
        static_cast<uint64_t>(*reinterpret_cast<uintptr_t*>(&udt));
    cnt++;
  }

  // TODO(manzagop): handle the other cases.

  *count = cnt;
  return true;
}

}  // namespace testing
