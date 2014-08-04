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

#ifndef SYZYGY_CORE_SECTION_OFFSET_ADDRESS_H_
#define SYZYGY_CORE_SECTION_OFFSET_ADDRESS_H_

#include <iosfwd>
#include "base/basictypes.h"
#include "syzygy/core/serialization.h"

namespace core {

// This class implements an address in a PE image file represented as a section
// index and an offset in the section. It has the same interface as AddressImpl,
// except for the operator- that accepts another address of the same type.
// The class is a lightweight wrapper for 2 integers, which can be freely
// copied.
class SectionOffsetAddress {
 public:
  static const SectionOffsetAddress kInvalidAddress;

  // A struct that contains all data from a SectionOffsetAddress and that is
  // returned by value().
  struct SectionOffset {
    SectionOffset(uint32 section_id, uint32 offset);

    bool operator<(const SectionOffset& other) const;
    bool operator<=(const SectionOffset& other) const;
    bool operator>(const SectionOffset& other) const;
    bool operator>=(const SectionOffset& other) const;
    bool operator==(const SectionOffset& other) const;
    bool operator!=(const SectionOffset& other) const;

    uint32 section_id;
    uint32 offset;
  };

  SectionOffsetAddress();
  SectionOffsetAddress(uint32 section_id, uint32 offset);

  // Non-explicit copy constructor, for STL container compatibility.
  SectionOffsetAddress(const SectionOffsetAddress& other);  // NOLINT

  bool operator<(const SectionOffsetAddress& other) const;
  bool operator<=(const SectionOffsetAddress& other) const;
  bool operator>(const SectionOffsetAddress& other) const;
  bool operator>=(const SectionOffsetAddress& other) const;
  bool operator==(const SectionOffsetAddress& other) const;
  bool operator!=(const SectionOffsetAddress& other) const;

  void operator=(const SectionOffsetAddress& other);
  void operator+=(int32 offset);
  void operator-=(int32 offset);

  SectionOffsetAddress operator+(size_t offset) const;
  SectionOffsetAddress operator-(size_t offset) const;

  const SectionOffset& value() const { return value_; }
  void set_value(const SectionOffset& value) { value_ = value; }

  uint32 section_id() const { return value_.section_id; }
  void set_section_id(uint32 section_id) { value_.section_id = section_id; }

  uint32 offset() const { return value_.offset; }
  void set_offset(uint32 offset) { value_.offset = offset; }

  // Aligns the address on a multiple of |alignment|.
  // @param alignment the alignment boundary to round the address up to.
  // @pre alignment != 0 && alignment <= 512.
  // @returns the aligned address.
  SectionOffsetAddress AlignUp(size_t alignment) const;

  // @param alignment The alignment boundary to test.
  // @pre alignment != 0 && alignment <= 512.
  // @returns true iff value is an even multiple of alignment.
  bool IsAligned(size_t alignment) const;

  // Determines the address alignment by counting the trailing zeros.
  // The returned value will be at most 512 because it is impossible to
  // guarantee an alignment on a greater power of 2 without knowing the
  // exact alignment of the section.
  // @returns the alignment of the address.
  uint32 GetAlignment() const;

  // For serialization.
  bool Save(OutArchive *out_archive) const;
  bool Load(InArchive *in_archive);

 private:
  SectionOffset value_;
};

std::ostream& operator<<(std::ostream& str, const SectionOffsetAddress& addr);

}  // namespace core

#endif  // SYZYGY_CORE_SECTION_OFFSET_ADDRESS_H_
