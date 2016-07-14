// Copyright 2011 Google Inc. All Rights Reserved.
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

#ifndef SYZYGY_CORE_ADDRESS_H_
#define SYZYGY_CORE_ADDRESS_H_

#include <stdint.h>
#include <iosfwd>

#include "base/logging.h"
#include "syzygy/common/align.h"
#include "syzygy/core/serialization.h"

namespace core {

enum AddressType : uint8_t {
  kRelativeAddressType,
  kAbsoluteAddressType,
  kFileOffsetAddressType,
};

namespace detail {

// This class implements an address in a PE image file.
// Addresses are of three varieties:
// - Relative addresses are relative to the base of the image, and thus do not
//   change when the image is relocated. Bulk of the addresses in the PE image
//   format itself are of this variety, and that's where relative addresses
//   crop up most frequently.
// - Absolute addresses are as the name indicates absolute, and those change
//   when an image is relocated. Absolute addresses mostly occur in initialized
//   data, and for each absolute datum in an image file, there will be a
//   relocation entry calling out its location in the image.
// - File offset addresses occur only in the debug data directory that I'm
//   aware of, where the debug data is referred to both by a relative address
//   and (presumably for convenience) by a file offset address.
// This class is a lightweight wrapper for an integer, which can be freely
// copied. The different address types are deliberately assignment
// incompatible, which helps to avoid confusion when handling different
// types of addresses in implementation.
template <AddressType kType>
class AddressImpl {
 public:
  static const AddressImpl kInvalidAddress;

  AddressImpl() : value_(0) {}
  explicit AddressImpl(size_t value) : value_(value) {}
  AddressImpl(const AddressImpl<kType>& other)  // NOLINT
      : value_(other.value_) {}

  AddressImpl<kType>& operator=(const AddressImpl<kType>& other) {
    value_ = other.value_;
    return *this;
  }

  // Comparison operators to other concrete addresses.
  bool operator<(const AddressImpl<kType>& other) const {
    return value_ < other.value_;
  }
  bool operator<=(const AddressImpl<kType>& other) const {
    return value_ <= other.value_;
  }
  bool operator>(const AddressImpl<kType>& other) const {
    return value_ > other.value_;
  }
  bool operator>=(const AddressImpl<kType>& other) const {
    return value_ >= other.value_;
  }
  bool operator==(const AddressImpl<kType>& other) const {
    return value_ == other.value_;
  }
  bool operator!=(const AddressImpl<kType>& other) const {
    return value_ != other.value_;
  }

  // Arithmetic operators.
  void operator+=(intptr_t offset) { value_ += offset; }
  void operator-=(intptr_t offset) { value_ -= offset; }
  AddressImpl<kType> operator+(size_t offset) const {
    return AddressImpl<kType>(value_ + offset);
  }
  AddressImpl<kType> operator-(size_t offset) const {
    return AddressImpl<kType>(value_ - offset);
  }
  intptr_t operator-(const AddressImpl<kType>& other) const {
    return value_ - other.value_;
  }

  // Accessors and mutators.
  static AddressType type() { return kType; }
  uintptr_t value() const { return value_; }
  void set_value(uintptr_t value) { value_ = value; }

  // @param alignment the alignment to be provided.
  // @returns an address that has been increased minimally to have the requested
  //     @p alignment.
  AddressImpl<kType> AlignUp(size_t alignment) const {
    return AddressImpl<kType>(common::AlignUp(value_, alignment));
  }

  // Determines if this address has the provided @p alignment.
  // @param alignment the alignment to be tested against.
  // @returns true if the address is aligned to @p alignment, false otherwise.
  bool IsAligned(size_t alignment) const {
    return common::IsAligned(value_, alignment);
  }

  // Determines the address alignment. If the value of the address is 0 then we
  // return the maximum alignment for a 32-bit address (0x80000000).
  // @returns the alignment of the address.
  size_t GetAlignment() const { return common::GetAlignment(value_); }

  // For serialization.
  bool Save(OutArchive *out_archive) const {
    return out_archive->Save(value_);
  }
  bool Load(InArchive *in_archive) {
    return in_archive->Load(&value_);
  }

  friend std::ostream& operator<<(std::ostream& str,
                                  const AddressImpl<kType>& addr);

 private:
  uintptr_t value_;
};

}  // namespace detail

// These types represent the different addressing formats used in PE images.

// A virtual address relative to the image base, often termed RVA in
// documentation and in data structure comments.
using RelativeAddress = detail::AddressImpl<kRelativeAddressType>;
// An absolute address.
using AbsoluteAddress = detail::AddressImpl<kAbsoluteAddressType>;
// A file offset within an image file.
using FileOffsetAddress = detail::AddressImpl<kFileOffsetAddressType>;

// An address variant that can house any of the concrete address types.
class AddressVariant {
 public:
  AddressVariant() : type_(kRelativeAddressType), value_(0) {}
  AddressVariant(AddressType type, size_t value) : type_(type), value_(value) {}
  AddressVariant(const AddressVariant& other)  // NOLINT
      : type_(other.type_), value_(other.value_) {}
  template <AddressType kType>
  explicit AddressVariant(const detail::AddressImpl<kType>& other)
      : type_(kType), value_(other.value()) {}

  // Allow assignment from any address type.
  template <AddressType kType>
  AddressVariant& operator=(const detail::AddressImpl<kType>& other) {
    type_ = kType;
    value_ = other.value();
    return *this;
  }
  AddressVariant& operator=(const AddressVariant& other);

  // Accessors and mutators.
  AddressType type() const { return type_; }
  uintptr_t value() const { return value_; }
  void set_type(AddressType type) { type_ = type; }
  void set_value(uintptr_t value) { value_ = value; }

  // Comparison operators.
  bool operator<(const AddressVariant& other) const;
  bool operator<=(const AddressVariant& other) const;
  bool operator>(const AddressVariant& other) const;
  bool operator>=(const AddressVariant& other) const;
  bool operator==(const AddressVariant& other) const;
  bool operator!=(const AddressVariant& other) const;

  // Arithmetic operators.
  void operator+=(intptr_t offset) { value_ += offset; }
  void operator-=(intptr_t offset) { value_ -= offset; }
  AddressVariant operator+(size_t offset) const {
    return AddressVariant(type_, value_ + offset);
  }
  AddressVariant operator-(size_t offset) const {
    return AddressVariant(type_, value_ - offset);
  }

  // NOTE: No operator-(const AddressVariant&) is provided as the types may
  // not be consistent and the result may not make sense.

  // For extracting concrete address types.
  // @tparam kType the concrete address type.
  // @param addr the concrete address instance to be populated with the
  //     address in this variant.
  // @returns true on success (the type of this variant matches the type of
  //     the concrete class), false otherwise.
  template <AddressType kType>
  bool Extract(detail::AddressImpl<kType>* addr) const {
    DCHECK_NE(static_cast<detail::AddressImpl<kType>*>(nullptr), addr);
    if (kType != type_)
      return false;
    addr->set_value(value_);
    return true;
  }

  // @param alignment the alignment to be provided.
  // @returns an address that has been increased minimally to have the requested
  //     @p alignment.
  AddressVariant AlignUp(size_t alignment) const {
    return AddressVariant(type_, common::AlignUp(value_, alignment));
  }

  // Determines if this address has the provided @p alignment.
  // @param alignment the alignment to be tested against.
  // @returns true if the address is aligned to @p alignment, false otherwise.
  bool IsAligned(size_t alignment) const {
    return common::IsAligned(value_, alignment);
  }

  // Determines the address alignment. If the value of the address is 0 then we
  // return the maximum alignment for a 32-bit address (0x80000000).
  // @returns the alignment of the address.
  size_t GetAlignment() const { return common::GetAlignment(value_); }

  // For serialization.
  bool Save(OutArchive* out_archive) const;
  bool Load(InArchive* in_archive);

  friend std::ostream& operator<<(std::ostream& str,
                                  const AddressVariant& addr);

 private:
  AddressType type_;
  size_t value_;
};

}  // namespace core

#endif  // SYZYGY_CORE_ADDRESS_H_
