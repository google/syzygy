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

#ifndef SYZYGY_REFINERY_CORE_ADDRESS_H_
#define SYZYGY_REFINERY_CORE_ADDRESS_H_

#include <stdint.h>

#include "syzygy/core/address_range.h"

namespace refinery {

// TODO(manzagop): consider making Address a class for stricter control on
// conversions. In particular, we've hit an issue where an int* being
// reinterpret_cast'ed to an Address triggered sign extension in the pointer.
typedef uint64_t Address;
typedef uint64_t RelativeAddress;
typedef uint32_t Size;

// AddressRange represents a range of memory with an address and a size.
// TODO(manzagop): incorporate a notion of validity wrt the process (eg 32 vs
// 64 bits).
class AddressRange : public core::AddressRange<Address, Size> {
 public:
  using Super = core::AddressRange<Address, Size>;

  AddressRange(Address addr, Size size) : Super(addr, size) {}
  AddressRange() {}

  // Determines the validity of the address range. All users of |AddressRange|
  // expect a valid range.
  // @returns true if the range is valid, false otherwise (empty range or
  //   overflow).
  bool IsValid() const;
};

}  // namespace refinery

#endif  // SYZYGY_REFINERY_CORE_ADDRESS_H_
