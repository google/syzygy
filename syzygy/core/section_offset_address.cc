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

#include "syzygy/core/section_offset_address.h"

#include <iostream>
#include "base/logging.h"
#include "base/strings/stringprintf.h"
#include "syzygy/common/align.h"

namespace core {

namespace {

// The minimum alignment of a PE section.
// See http://msdn.microsoft.com/library/windows/desktop/ms680339.aspx
const uint32 kPESectionMinAlignment = 512;

// Host function for compile asserts.
void SectionOffsetAddressCompileAsserts() {
  COMPILE_ASSERT(sizeof(SectionOffsetAddress) == 2 * sizeof(uint32),
                 section_offset_address_must_be_8_bytes);
}

}  // namespace

const SectionOffsetAddress SectionOffsetAddress::kInvalidAddress(~0U, ~0U);

SectionOffsetAddress::SectionOffset::SectionOffset(
    uint32 section_id, uint32 offset)
    : section_id(section_id),
      offset(offset) {
}

bool SectionOffsetAddress::SectionOffset::operator<(
    const SectionOffset& other) const {
  if (section_id < other.section_id)
    return true;
  if (section_id > other.section_id)
    return false;
  return offset < other.offset;
}

bool SectionOffsetAddress::SectionOffset::operator<=(
    const SectionOffset& other) const {
  if (section_id < other.section_id)
    return true;
  if (section_id > other.section_id)
    return false;
  return offset <= other.offset;
}

bool SectionOffsetAddress::SectionOffset::operator>(
    const SectionOffset& other) const {
  if (section_id > other.section_id)
    return true;
  if (section_id < other.section_id)
    return false;
  return offset > other.offset;
}

bool SectionOffsetAddress::SectionOffset::operator>=(
    const SectionOffset& other) const {
  if (section_id > other.section_id)
    return true;
  if (section_id < other.section_id)
    return false;
  return offset >= other.offset;
}

bool SectionOffsetAddress::SectionOffset::operator==(
    const SectionOffset& other) const {
  return section_id == other.section_id && offset == other.offset;
}

bool SectionOffsetAddress::SectionOffset::operator!=(
    const SectionOffset& other) const {
  return section_id != other.section_id || offset != other.offset;
}

SectionOffsetAddress::SectionOffsetAddress() : value_(0, 0) {
}

SectionOffsetAddress::SectionOffsetAddress(uint32 section_id, uint32 offset)
    : value_(section_id, offset) {
}

SectionOffsetAddress::SectionOffsetAddress(const SectionOffsetAddress& other)
    : value_(other.value_) {
}

bool SectionOffsetAddress::operator<(const SectionOffsetAddress& other) const {
  return value_ < other.value_;
}

bool SectionOffsetAddress::operator<=(const SectionOffsetAddress& other) const {
  return value_ <= other.value_;
}

bool SectionOffsetAddress::operator>(const SectionOffsetAddress& other) const {
  return value_ > other.value_;
}

bool SectionOffsetAddress::operator>=(const SectionOffsetAddress& other) const {
  return value_ >= other.value_;
}

bool SectionOffsetAddress::operator==(const SectionOffsetAddress& other) const {
  return value_ == other.value_;
}

bool SectionOffsetAddress::operator!=(const SectionOffsetAddress& other) const {
  return value_ != other.value_;
}

void SectionOffsetAddress::operator=(const SectionOffsetAddress& other) {
  value_ = other.value_;
}

void SectionOffsetAddress::operator+=(int32 offset) {
  value_.offset += offset;
}

void SectionOffsetAddress::operator-=(int32 offset) {
  value_.offset -= offset;
}

SectionOffsetAddress SectionOffsetAddress::operator+(size_t offset) const {
  return SectionOffsetAddress(section_id(), value_.offset + offset);
}

SectionOffsetAddress SectionOffsetAddress::operator-(size_t offset) const {
  return SectionOffsetAddress(section_id(), value_.offset - offset);
}

SectionOffsetAddress SectionOffsetAddress::AlignUp(size_t alignment) const {
  DCHECK_NE(0U, alignment);
  // Sections are aligned on a power of 2 greater or equal to 512
  // (see http://msdn.microsoft.com/library/windows/desktop/ms680339.aspx).
  // Without knowing the exact alignment of the section, it is impossible to
  // guarantee an alignment on a power of 2 greater than 512.
  DCHECK_LE(alignment, kPESectionMinAlignment);

  return SectionOffsetAddress(
      section_id(), common::AlignUp(offset(), alignment));
}

bool SectionOffsetAddress::IsAligned(size_t alignment) const {
  DCHECK_NE(0U, alignment);
  DCHECK_LE(alignment, kPESectionMinAlignment);

  return common::IsAligned(offset(), alignment);
}

uint32 SectionOffsetAddress::GetAlignment() const {
  uint32 alignment = common::GetAlignment(offset());
  if (alignment > kPESectionMinAlignment)
    return kPESectionMinAlignment;
  return alignment;
}

bool SectionOffsetAddress::Save(OutArchive *out_archive) const {
  return out_archive->Save(section_id()) && out_archive->Save(offset());
}

bool SectionOffsetAddress::Load(InArchive *in_archive) {
  return in_archive->Load(&value_.section_id) &&
      in_archive->Load(&value_.offset);
}

std::ostream& operator<<(std::ostream& str, const SectionOffsetAddress& addr) {
  str << base::StringPrintf(
      "SectionOffset(0x%08X, 0x%08X)", addr.section_id(), addr.offset());
  return str;
}

}  // namespace core
