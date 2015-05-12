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

Type::Type(const base::string16& name, size_t size, TypeKind kind) :
    name_(name), size_(size), kind_(kind) {
}

Type::~Type() {
}

void UserDefinedType::AddField(const Field& field) {
  fields_.push_back(field);
}

UserDefinedType::Field::Field(const base::string16& name,
                              size_t offset,
                              size_t size,
                              uint32_t flags,
                              const TypePtr& type) :
    name_(name),
    offset_(offset),
    size_(size),
    flags_(flags),
    type_(type) {
}

PointerType::PointerType(const base::string16& name,
                         size_t size,
                         const TypePtr& type)
    : Type(name, size, PointerKind), type_(type) {
}

}  // namespace refinery
