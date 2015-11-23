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

#ifndef SYZYGY_CORE_ADDRESS_RANGE_H_
#define SYZYGY_CORE_ADDRESS_RANGE_H_

#include "syzygy/core/address_space_internal.h"
#include "syzygy/core/serialization.h"

namespace core {

// An address range has a start address and a size.
// Both types must provide operator <, and it must be possible to
// add a SizeType to an AddressType.
template <typename AddressType, typename SizeType>
class AddressRange {
 public:
  typedef AddressType Address;
  typedef SizeType Size;

  AddressRange() : start_(0), size_(0) {
  }

  AddressRange(const AddressType &start, const SizeType& size)
      : start_(start), size_(size) {
  }

  AddressRange(const AddressRange &other)
      : start_(other.start_), size_(other.size_) {
  }

  void operator=(const AddressRange &other) {
    start_ = other.start_;
    size_ = other.size_;
  }

  // @returns true if this range is empty.
  bool IsEmpty() const { return size_ == 0; }

  // Determines if a given address range is contained within this range.
  // @param other The range to check.
  // @param addr Start address of the range to check.
  // @param size The size of the other range to check.
  // @returns true iff @p other is contained within this range.
  bool Contains(const AddressRange& other) const {
    if (other.start_ < start_ || other.end() > end())
      return false;

    return true;
  }
  bool Contains(AddressType addr, SizeType size = 1) const {
    return Contains(AddressRange(addr, size));
  }

  // Determines if a given range intersects this range.
  // @param other The range to test.
  // @param addr Start address of the range to check.
  // @param size The size of the other range to check.
  // @returns true iff @p other intersects this range.
  bool Intersects(const AddressRange& other) const {
    if (other.end() <= start_ || other.start_ >= end())
      return false;

    return true;
  }
  bool Intersects(AddressType addr, SizeType size = 1) const {
    return Intersects(AddressRange(addr, size));
  }

  // @name Comparison operators. These are for the purposes of the map that we
  //     use for tracking the address space.
  // @{
  bool operator<(const AddressRange& other) const {
    // This assumes the Address and Size types provide operator <.
    return internal::CompleteAddressRangeLess<AddressRange>()(*this, other);
  }

  bool operator==(const AddressRange& other) const {
    // If neither is less, they have to be equal. That is, they conflict as
    // far as the address-space is concerned.
    return !(other < *this) && !(*this < other);
  }

  bool operator!=(const AddressRange& other) const {
    return !operator==(other);
  }
  // @}

  // @returns A new AdressRange offsetted by @p offset.
  AddressRange Offset(SizeType offset) {
    return AddressRange(start_ + offset, size_);
  }

  AddressType start() const { return start_; }
  AddressType end() const { return start_ + size_; }
  SizeType size() const { return size_; }

  bool Save(OutArchive* out_archive) const {
    DCHECK(out_archive != NULL);
    return out_archive->Save(start_) && out_archive->Save(size_);
  }

  bool Load(InArchive* in_archive) {
    DCHECK(in_archive != NULL);
    return in_archive->Load(&start_) && in_archive->Load(&size_);
  }

 private:
  // Start of address range.
  AddressType start_;
  // Size of address range.
  SizeType size_;
};

}  // namespace core

#endif  // SYZYGY_CORE_ADDRESS_RANGE_H_
