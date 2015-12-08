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

#include <cstdint>

namespace testing {

// Note: we declare different functions (return different integers) to avoid
// the possibility of vtables overlapping.

struct NoVirtualMethodUDT {
  int a;
  int f();
};

struct VirtualMethodUDT {
  int a;
  virtual int f() { return 1; }
};

struct ComposedUDT {
  int a;
  VirtualMethodUDT udt;
  virtual int f() { return 2; }
};

// A class that only overrides virtual methods provided by its virtual base is
// expected to have its vftable pointer at offset 0 of its virtual base.
struct VirtualChildUDT : virtual VirtualMethodUDT {
  int b;
  int f() override { return 3; }
};

struct VirtualChildWithVirtualMethodUDT : virtual VirtualMethodUDT {
  int b;
  int f() override { return 4; }
  virtual int g() { return 5; }
};

// Another case where we expect no vftable at offset 0 (interfaces).
struct IA { virtual int one() = 0; };
struct IB { virtual int two() = 0; };
struct SimpleBase { int member; };
struct InterfaceImplUDT : public SimpleBase, public IA, public IB {
  int one() override { return 6; }
  int two() override { return 7; }
};

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
