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

#include "base/md5.h"
#include "base/strings/string_piece.h"
#include "syzygy/refinery/types/type_repository.h"

namespace refinery {

Type::Type(TypeKind kind, const base::string16& name, size_t size)
    : repository_(nullptr),
      type_id_(kNoTypeId),
      kind_(kind),
      name_(name),
      size_(size) {
}

Type::~Type() {
}

void Type::SetRepository(TypeRepository* repository, TypeId type_id) {
  DCHECK(repository);
  DCHECK(!repository_);
  DCHECK_EQ(kNoTypeId, type_id_);
  DCHECK_NE(kNoTypeId, type_id);

  repository_ = repository;
  type_id_ = type_id;
}

UserDefinedType::UserDefinedType(const base::string16& name, size_t size) :
    Type(USER_DEFINED_TYPE_KIND, name, size) {
}

TypePtr UserDefinedType::GetFieldType(size_t field_no) const {
  DCHECK(repository());
  DCHECK_GT(fields_.size(), field_no);

  return repository()->GetType(fields_[field_no].type_id());
}

BasicType::BasicType(const base::string16& name, size_t size) :
    Type(BASIC_TYPE_KIND, name, size) {
}

void UserDefinedType::Finalize(const Fields& fields) {
  DCHECK_EQ(0U, fields_.size());
  for (auto field : fields)
    fields_.push_back(field);
}

UserDefinedType::Field::Field(const base::string16& name,
                              ptrdiff_t offset,
                              Flags flags,
                              size_t bit_pos,
                              size_t bit_len,
                              TypeId type_id)
    : name_(name),
      offset_(offset),
      flags_(flags),
      bit_pos_(bit_pos),
      bit_len_(bit_len),
      type_id_(type_id) {
  DCHECK_GE(63u, bit_pos);
  DCHECK_GE(63u, bit_len);
  DCHECK_NE(kNoTypeId, type_id);
}

PointerType::PointerType(size_t size)
    : Type(POINTER_TYPE_KIND, L"", size),
      flags_(0),
      content_type_id_(kNoTypeId) {
}

TypePtr PointerType::GetContentType() const {
  DCHECK(repository());

  return repository()->GetType(content_type_id());
}

void PointerType::Finalize(Flags flags, TypeId content_type_id) {
  DCHECK_EQ(0, flags_);
  DCHECK_EQ(kNoTypeId, content_type_id_);
  DCHECK_NE(kNoTypeId, content_type_id);

  flags_ = flags;
  content_type_id_ = content_type_id;
}

WildcardType::WildcardType(const base::string16& name, size_t size)
    : Type(WILDCARD_TYPE_KIND, name, size) {
}

}  // namespace refinery
