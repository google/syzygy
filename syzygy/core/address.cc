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

#include "syzygy/core/address.h"

#include <iostream>
#include "base/strings/stringprintf.h"

namespace core {

static_assert(sizeof(RelativeAddress) == sizeof(uintptr_t),
              "RelativeAddress has the wrong size.");
static_assert(sizeof(AbsoluteAddress) == sizeof(uintptr_t),
              "AbsoluteAddress has the wrong size.");
static_assert(sizeof(FileOffsetAddress) == sizeof(uintptr_t),
              "FileOffsetAddress has the wrong size.");

namespace detail {

template <>
const AddressImpl<kRelativeAddressType>
    AddressImpl<kRelativeAddressType>::kInvalidAddress(~0U);

template <>
const AddressImpl<kAbsoluteAddressType>
    AddressImpl<kAbsoluteAddressType>::kInvalidAddress(~0U);

template <>
const AddressImpl<kFileOffsetAddressType>
    AddressImpl<kFileOffsetAddressType>::kInvalidAddress(~0U);

std::ostream& operator<<(std::ostream& str,
                         const AddressImpl<kRelativeAddressType>& addr) {
  return str << base::StringPrintf("Relative(0x%08X)", addr.value_);
}

std::ostream& operator<<(std::ostream& str,
                         const AddressImpl<kAbsoluteAddressType>& addr) {
  return str << base::StringPrintf("Absolute(0x%08X)", addr.value_);
}

std::ostream& operator<<(std::ostream& str,
                         const AddressImpl<kFileOffsetAddressType>& addr) {
  return str << base::StringPrintf("FileOffset(0x%08X)", addr.value_);
}

}  // namespace detail

namespace {

int Compare(const AddressVariant& av1, const AddressVariant& av2) {
  if (av1.type() < av2.type())
    return -1;
  if (av1.type() > av2.type())
    return 1;
  if (av1.value() < av2.value())
    return -1;
  if (av1.value() > av2.value())
    return 1;
  return 0;
}

}  // namespace

AddressVariant& AddressVariant::operator=(const AddressVariant& other) {
  type_ = other.type_;
  value_ = other.value_;
  return *this;
}

bool AddressVariant::operator<(const AddressVariant& other) const {
  return Compare(*this, other) < 0;
}

bool AddressVariant::operator<=(const AddressVariant& other) const {
  return Compare(*this, other) <= 0;
}

bool AddressVariant::operator>(const AddressVariant& other) const {
  return Compare(*this, other) > 0;
}

bool AddressVariant::operator>=(const AddressVariant& other) const {
  return Compare(*this, other) >= 0;
}

bool AddressVariant::operator==(const AddressVariant& other) const {
  return Compare(*this, other) == 0;
}

bool AddressVariant::operator!=(const AddressVariant& other) const {
  return Compare(*this, other) != 0;
}

bool AddressVariant::Save(OutArchive* out_archive) const {
  uint8_t type = static_cast<uint8_t>(type_);
  return out_archive->Save(type) && out_archive->Save(value_);
}

bool AddressVariant::Load(InArchive* in_archive) {
  uint8_t type = 0;
  if (!in_archive->Load(&type))
    return false;
  type_ = static_cast<AddressType>(type);
  return in_archive->Load(&value_);
}

std::ostream& operator<<(std::ostream& str, const AddressVariant& addr) {
  static const char* kTypes[] = {"Relative", "Absolute", "FileOffset"};
  DCHECK_GT(arraysize(kTypes), addr.type_);
  return str << base::StringPrintf("AddressVariant(%s(0x%08X))",
                                   kTypes[addr.type_], addr.value_);
}

}  // namespace core
