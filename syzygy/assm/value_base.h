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
//
// This file declares implementation classes to generate assembly code.
// The API to the assembler is intentionally very close to the API exposed
// by the V8 assembler (see src/ia32/assembler-ia32.* in V8 repository).

#ifndef SYZYGY_ASSM_VALUE_BASE_H_
#define SYZYGY_ASSM_VALUE_BASE_H_

#include "syzygy/assm/register.h"

namespace assm {

// We use the same enum for value sizes.
typedef RegisterSize ValueSize;

// An instance of this class is an explicit value, which is either
// an immediate or a displacement.
template <class ReferenceType, class SubclassType>
class ValueBase {
 public:
  ValueBase();
  ValueBase(uint32_t value, ValueSize size);
  ValueBase(uint32_t value, ValueSize size, ReferenceType imm_ref);

  // @name Accessors.
  // @{
  uint32_t value() const { return value_; }
  const ReferenceType& reference() const { return reference_; }
  ValueSize size() const { return size_; }
  // @}

  // Comparison operator.
  bool operator==(const ValueBase& rhs) const;

 private:
  uint32_t value_;
  ReferenceType reference_;
  ValueSize size_;
};

template <class ReferenceType>
class ImmediateBase
    : public ValueBase<ReferenceType, ImmediateBase<ReferenceType>> {
 public:
  typedef ValueBase<ReferenceType, ImmediateBase<ReferenceType>> Super;

  ImmediateBase() {
  }
  ImmediateBase(uint32_t value, ValueSize size) : Super(value, size) {}
  ImmediateBase(uint32_t value, ValueSize size, ReferenceType imm_ref)
      : Super(value, size, imm_ref) {}
};

template <class ReferenceType>
class DisplacementBase
    : public ValueBase<ReferenceType, DisplacementBase<ReferenceType>> {
 public:
  typedef ValueBase<ReferenceType, DisplacementBase<ReferenceType>> Super;

  DisplacementBase() {
  }
  DisplacementBase(uint32_t value, ValueSize size) : Super(value, size) {}
  DisplacementBase(uint32_t value, ValueSize size, ReferenceType imm_ref)
      : Super(value, size, imm_ref) {}
};

template <class ReferenceType, class SubclassType>
ValueBase<ReferenceType, SubclassType>::ValueBase()
    : value_(0), reference_(), size_(kSizeNone) {
}

template <class ReferenceType, class SubclassType>
ValueBase<ReferenceType, SubclassType>::ValueBase(uint32_t value,
                                                  ValueSize size)
    : value_(value), reference_(), size_(size) {
}

template <class ReferenceType, class SubclassType>
ValueBase<ReferenceType, SubclassType>::ValueBase(uint32_t value,
                                                  ValueSize size,
                                                  ReferenceType value_ref)
    : value_(value), reference_(value_ref), size_(size) {
  // We can't have a 16-bit value *and* a reference, as there are no
  // addressing modes that accept 16-bit input.

  DCHECK(!details::IsValidReference(value_ref) || size != kSize16Bit);
}

template <class ReferenceType, class SubclassType>
bool ValueBase<ReferenceType, SubclassType>::operator==(
    const ValueBase& rhs) const {
  return value_ == rhs.value_ &&
      reference_ == rhs.reference_ &&
      size_ == rhs.size_;
}

}  // namespace assm

#endif  // SYZYGY_ASSM_VALUE_BASE_H_
