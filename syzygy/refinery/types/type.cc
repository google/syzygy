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
    : Type(kind, name, name, size) {
}

Type::Type(TypeKind kind,
           const base::string16& name,
           const base::string16& decorated_name,
           size_t size)
    : repository_(nullptr),
      type_id_(kNoTypeId),
      kind_(kind),
      name_(name),
      decorated_name_(decorated_name),
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

UserDefinedType::UserDefinedType(const base::string16& name,
                                 const base::string16& decorated_name,
                                 size_t size)
    : Type(USER_DEFINED_TYPE_KIND, name, decorated_name, size) {
}

TypePtr UserDefinedType::GetFieldType(size_t field_no) const {
  DCHECK(repository());
  DCHECK_GT(fields_.size(), field_no);

  return repository()->GetType(fields_[field_no].type_id());
}

BasicType::BasicType(const base::string16& name, size_t size)
    : Type(BASIC_TYPE_KIND, name, name, size) {
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

bool UserDefinedType::Field::operator==(const Field& o) const {
  return name_ == o.name_ && offset_ == o.offset_ && flags_ == o.flags_ &&
         bit_pos_ == o.bit_pos_ && bit_len_ == o.bit_len_ &&
         type_id_ == o.type_id_;
}

PointerType::PointerType(size_t size)
    : Type(POINTER_TYPE_KIND, L"", size),
      flags_(0),
      content_type_id_(kNoTypeId) {
}

PointerType::PointerType(const base::string16& name,
                         const base::string16& decorated_name,
                         size_t size)
    : flags_(0),
      content_type_id_(kNoTypeId),
      Type(POINTER_TYPE_KIND, name, decorated_name, size) {
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

void PointerType::SetName(const base::string16& name) {
  DCHECK_EQ(L"", name_);
  name_ = name;
}

void PointerType::SetDecoratedName(const base::string16& decorated_name) {
  DCHECK_EQ(L"", decorated_name_);
  decorated_name_ = decorated_name;
}

ArrayType::ArrayType(size_t size)
    : Type(ARRAY_TYPE_KIND, L"", L"", size),
      index_type_id_(kNoTypeId),
      num_elements_(0),
      element_type_id_(kNoTypeId) {
}

TypePtr ArrayType::GetIndexType() const {
  DCHECK(repository());

  return repository()->GetType(index_type_id_);
}

TypePtr ArrayType::GetElementType() const {
  DCHECK(repository());

  return repository()->GetType(element_type_id_);
}

void ArrayType::Finalize(Flags flags,
                         TypeId index_type_id,
                         size_t num_elements,
                         TypeId element_type_id) {
  DCHECK_EQ(kNoTypeId, index_type_id_);
  DCHECK_EQ(0U, num_elements_);
  DCHECK_EQ(kNoTypeId, element_type_id_);

  flags_ = flags;
  index_type_id_ = index_type_id;
  num_elements_ = num_elements;
  element_type_id_ = element_type_id;
}

void ArrayType::SetName(const base::string16& name) {
  DCHECK_EQ(L"", name_);
  name_ = name;
}

void ArrayType::SetDecoratedName(const base::string16& decorated_name) {
  DCHECK_EQ(L"", decorated_name_);
  decorated_name_ = decorated_name;
}

WildcardType::WildcardType(const base::string16& name, size_t size)
    : Type(WILDCARD_TYPE_KIND, name, size) {
}

WildcardType::WildcardType(const base::string16& name,
                           const base::string16& decorated_name,
                           size_t size)
    : Type(WILDCARD_TYPE_KIND, name, size) {
}

}  // namespace refinery
