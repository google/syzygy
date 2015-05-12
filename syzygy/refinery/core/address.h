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

namespace refinery {

typedef uint64_t Address;
typedef uint32_t Size;

// AddressRange represents a range of memory with an address and a size.
// TODO(manzagop): incorporate a notion of validity wrt the process (eg 32 vs
// 64 bits).
class AddressRange {
 public:
  AddressRange(Address addr, Size size) : addr_(addr), size_(size) {}

  // Determines the validity of the address range. All users of |AddressRange|
  // expect a valid range.
  // @returns true if the range is valid, false otherwise (empty range or
  //   overflow).
  bool IsValid() const;

  // @name Accessors.
  // @{
  Address addr() const { return addr_; }
  Size size() const { return size_; }
  // @}

  Address start() const { return addr_; }
  // @pre address range must be valid.
  Address end() const;

  bool operator==(const AddressRange& other) const;

  // @pre IsValid returns true.
  // @pre @p range must be a valid range.
  // @returns true if this range intersects @p other.
  bool Intersects(const AddressRange& other) const;

  // @pre IsValid returns true.
  // @pre @p range must be a valid range.
  // @returns true if this range spans @p other.
  bool Spans(const AddressRange& other) const;

 private:
  Address addr_;
  Size size_;
};

}  // namespace refinery

#endif  // SYZYGY_REFINERY_CORE_ADDRESS_H_
