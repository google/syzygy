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

#ifndef SYZYGY_ASSM_OPERAND_BASE_H_
#define SYZYGY_ASSM_OPERAND_BASE_H_

#include "syzygy/assm/value_base.h"

namespace assm {

// Selects a scale for the Operand addressing modes.
// The values match the encoding in the x86 SIB bytes.
enum ScaleFactor {
  kTimes1 = 0,
  kTimes2 = 1,
  kTimes4 = 2,
  kTimes8 = 3,
};

// An operand implies indirection to memory through one of the myriad
// modes supported by IA32.
template <class ReferenceType>
class OperandBase {
 public:
  typedef DisplacementBase<ReferenceType> DisplacementBase;

  // A register-indirect mode.
  explicit OperandBase(const Register32& base);

  // A register-indirect with displacement mode.
  OperandBase(const Register32& base, const DisplacementBase& displ);

  // A displacement-only mode.
  explicit OperandBase(const DisplacementBase& displ);

  // The full [base + index * scale + displ32] mode.
  // @note esp cannot be used as an index register.
  OperandBase(const Register32& base,
              const Register32& index,
              ScaleFactor scale,
              const DisplacementBase& displ);

  // The [base + index * scale] mode.
  // @note esp cannot be used as an index register.
  OperandBase(const Register32& base,
              const Register32& index,
              ScaleFactor scale);

  // The [index * scale + displ32] mode - e.g. no base.
  // @note esp cannot be used as an index register.
  OperandBase(const Register32& index,
              ScaleFactor scale,
              const DisplacementBase& displ);

  // Low-level constructor, none of the parameters are checked.
  OperandBase(RegisterId base,
              RegisterId index,
              ScaleFactor scale,
              const DisplacementBase& displacement);

  // @name Accessors.
  // @{
  RegisterId base() const { return base_; }
  RegisterId index() const { return index_; }
  ScaleFactor scale() const { return scale_; }
  const DisplacementBase& displacement() const { return displacement_; }
  // @}

 private:
  // The base register involved, or none.
  RegisterId base_;
  // The index register involved, or none.
  RegisterId index_;
  // The scaling factor, must be kTimes1 if no index register.
  ScaleFactor scale_;
  // The displacement, if any.
  DisplacementBase displacement_;
};

template <class ReferenceType>
OperandBase<ReferenceType>::OperandBase(const Register32& base)
    : base_(base.id()),
      index_(kRegisterNone),
      scale_(kTimes1) {
}

template <class ReferenceType>
OperandBase<ReferenceType>::OperandBase(
    const Register32& base, const DisplacementBase& displacement) :
        base_(base.id()),
        index_(kRegisterNone),
        scale_(kTimes1),
        displacement_(displacement) {
  // There must be a base register.
  DCHECK_NE(kRegisterNone, base_);
}

template <class ReferenceType>
OperandBase<ReferenceType>::OperandBase(const DisplacementBase& displacement) :
    base_(kRegisterNone),
    index_(kRegisterNone),
    scale_(kTimes1),
    displacement_(displacement) {
  DCHECK_NE(kSizeNone, displacement.size());
}

template <class ReferenceType>
OperandBase<ReferenceType>::OperandBase(
    const Register32& base, const Register32& index,
    ScaleFactor scale, const DisplacementBase& displacement) :
        base_(base.id()),
        index_(index.id()),
        scale_(scale),
        displacement_(displacement) {
  // ESP cannot be used as an index register.
  DCHECK_NE(kRegisterEsp, index.id());
  DCHECK_NE(kSizeNone, displacement.size());
}

template <class ReferenceType>
OperandBase<ReferenceType>::OperandBase(
    const Register32& base, const Register32& index, ScaleFactor scale) :
        base_(base.id()), index_(index.id()), scale_(scale) {
  // ESP cannot be used as an index register.
  DCHECK_NE(kRegisterEsp, index.id());
  DCHECK_EQ(kSizeNone, displacement_.size());
}

template <class ReferenceType>
OperandBase<ReferenceType>::OperandBase(
    const Register32& index, ScaleFactor scale,
    const DisplacementBase& displacement) :
        base_(kRegisterNone), index_(index.id()), scale_(scale),
        displacement_(displacement) {
  // ESP cannot be used as an index register.
  DCHECK_NE(kRegisterEsp, index.id());
  DCHECK_NE(kSizeNone, displacement.size());
}

template <class ReferenceType>
OperandBase<ReferenceType>::OperandBase(
    RegisterId base, RegisterId index, ScaleFactor scale,
    const DisplacementBase& displacement) :
        base_(base), index_(index), scale_(scale),
        displacement_(displacement) {
}

}  // namespace assm

#endif  // SYZYGY_ASSM_OPERAND_BASE_H_
