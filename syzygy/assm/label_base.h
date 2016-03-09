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
//
// Declares the assembler's label.

#ifndef SYZYGY_ASSM_LABEL_BASE_H_
#define SYZYGY_ASSM_LABEL_BASE_H_

#include <stdint.h>
#include <vector>

#include "base/macros.h"

namespace assm {

// Fwd.
template <class ReferenceType>
class AssemblerBase;

// A label comes into existence unbound, and must be bound to the current
// location at some point. Typical usage might go:
//
// Label success(&assm);
// assm.cmp(...)
// assm.j(kNotZero, &success);
// ...
// success.Bind();  // Binds the label to the assembler's current location.
// ...
template <class ReferenceType>
class LabelBase {
 public:
  typedef AssemblerBase<ReferenceType> Assembler;

  explicit LabelBase(Assembler* assm);
  ~LabelBase();

  // Binds the label to the current assembly address.
  // @returns true on success.
  // @note binding can fail if the assembler's serializer doesn't support it,
  //     or if any use of the label is out of range for a PC-relative reference
  //     to the current address.
  bool Bind();

 private:
  friend class Assembler;

  struct LabelUsage {
    // The location of the use.
    uint32_t location;
    // The size of the
    RegisterSize size;
  };

  bool bound() const { return bound_; }
  uint32_t location() const { return location_; }

  // Interface for assembler to declare usage of unbound labels.
  void Use(uint32_t location, RegisterSize size);

  // Revisits label usages and writes them with the correct value.
  bool Finalize();

  // The assembler this label belongs to.
  Assembler* assm_;

  // True iff the label is bound.
  bool bound_;

  // The location this label is bound to. Valid iff bound_ is true;
  uint32_t location_;

  // Keeps track of where the unbound label has been used.
  std::vector<LabelUsage> uses_;

  DISALLOW_COPY_AND_ASSIGN(LabelBase);
};

template <class ReferenceType>
LabelBase<ReferenceType>::LabelBase(Assembler* assm) :
    assm_(assm), bound_(false), location_(0) {
  DCHECK(assm != NULL);
}

template <class ReferenceType>
LabelBase<ReferenceType>::~LabelBase() {
  DCHECK_EQ(0U, uses_.size());
}

template <class ReferenceType>
bool LabelBase<ReferenceType>::Bind() {
  bound_ = true;
  location_ = assm_->location();

  return Finalize();
}

template <class ReferenceType>
void LabelBase<ReferenceType>::Use(uint32_t location, RegisterSize size) {
  DCHECK(!bound_);
  LabelUsage usage = { location, size };
  uses_.push_back(usage);
}

template <class ReferenceType>
bool LabelBase<ReferenceType>::Finalize() {
  bool success = true;
  for (auto usage: uses_) {
    success = assm_->FinalizeLabel(usage.location, location_, usage.size);
    if (!success)
      break;
  }
  uses_.clear();

  return success;
}

}  // namespace assm

#endif  // SYZYGY_ASSM_LABEL_BASE_H_
