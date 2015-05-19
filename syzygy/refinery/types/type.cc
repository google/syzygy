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
#include "syzygy/refinery/types/type.h"

namespace refinery {

Type::Type(TypeKind kind,
           const base::string16& name,
           size_t size,
           Flags flags) :
    kind_(kind), name_(name), size_(size), flags_(flags) {
}

Type::~Type() {
}

UserDefinedType::UserDefinedType(const base::string16& name,
                                 size_t size,
                                 Flags flags,
                                 const Fields& fields) :
    Type(UserDefinedKind, name, size, flags), fields_(fields) {
}

BasicType::BasicType(const base::string16& name, size_t size, Flags flags) :
    Type(BasicKind, name, size, flags) {
}

BitfieldType::BitfieldType(const base::string16& name,
                           size_t size,
                           Flags flags,
                           size_t bit_length,
                           size_t bit_offset) :
    Type(BitfieldKind, name,  size, flags),
    bit_length_(bit_length),
    bit_offset_(bit_offset) {
}

UserDefinedType::Field::Field(const base::string16& name,
                              ptrdiff_t offset,
                              const TypePtr& type) :
    name_(name), offset_(offset), type_(type) {
}

PointerType::PointerType(const base::string16& name,
                         size_t size,
                         Flags flags,
                         const TypePtr& type)
    : Type(PointerKind, name, size, flags), type_(type) {
}

}  // namespace refinery
