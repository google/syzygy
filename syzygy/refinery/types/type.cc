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

namespace {

class CompoundHash {
 public:
  CompoundHash();

  template <typename DataType>
  void Update(const DataType& datum) {
    Update(&datum, sizeof(datum));
  }
  void Update(const void* data, size_t size);
  void Update(const base::string16& str);

  size_t Finalize();

 private:
  base::MD5Context context_;
};

CompoundHash::CompoundHash() {
  base::MD5Init(&context_);
}

void CompoundHash::Update(const void* data, size_t size) {
  base::MD5Update(
      &context_,
      base::StringPiece(reinterpret_cast<const char*>(data), size));
}

void CompoundHash::Update(const base::string16& str) {
  Update(str.data(), str.size() * sizeof(*str.data()));
}

size_t CompoundHash::Finalize() {
  base::MD5Digest digest = {};
  base::MD5Final(&digest, &context_);

  COMPILE_ASSERT(sizeof(size_t) <= sizeof(digest),
                 digest_smaller_than_size_t);
  // Return the first bytes of the digest.
  return *reinterpret_cast<size_t*>(&digest);
}

}  // namespace

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

size_t TypeHash::operator()(const TypePtr& type) {
  CompoundHash hash;

  hash.Update(type->name());
  hash.Update(type->size());
  hash.Update(type->kind());

  switch (type->kind()) {
    case Type::BASIC_TYPE_KIND:
      break;

    case Type::BITFIELD_TYPE_KIND: {
      BitfieldTypePtr bf;
      type->CastTo(&bf);
      DCHECK(bf);

      hash.Update(bf->bit_length());
      hash.Update(bf->bit_offset());
      break;
    }

    case Type::USER_DEFINED_TYPE_KIND: {
      UserDefinedTypePtr udt;
      type->CastTo(&udt);
      DCHECK(udt);

      hash.Update(udt->fields().size());
      for (const auto& field : udt->fields()) {
        hash.Update(field.name());
        hash.Update(field.offset());
        hash.Update(field.is_const());
        hash.Update(field.is_volatile());

        // Use the identity of the type rather than its value as
        // it's already unique.
        hash.Update(field.type_id());
      }
      break;
    }

    case Type::POINTER_TYPE_KIND: {
      PointerTypePtr ptr;
      type->CastTo(&ptr);
      DCHECK(ptr);

      hash.Update(ptr->is_const());
      hash.Update(ptr->is_volatile());

      // Use the identity of the type rather than its value as
      // it's already unique.
      hash.Update(ptr->content_type_id());
      break;
    }

    case Type::WILDCARD_TYPE_KIND:
      // No additional fields to hash.
      break;

    default:
      NOTREACHED();
      break;
  }

  return hash.Finalize();
}

bool TypeIsEqual::operator()(const TypePtr& a, const TypePtr& b) {
  // If a and b point to the same instance, they're trivially equal.
  if (a.get() == b.get())
    return true;

  if (a->kind() != b->kind() ||
      a->size() != b->size() ||
      a->name() != b->name()) {
    return false;
  }

  DCHECK_EQ(a->kind(), b->kind());
  switch (a->kind()) {
    case Type::BASIC_TYPE_KIND:
      return true;

    case Type::BITFIELD_TYPE_KIND: {
      BitfieldTypePtr a1, b1;
      a->CastTo(&a1);
      b->CastTo(&b1);
      DCHECK(a1 && b1);

      return a1->bit_length() == b1->bit_length() &&
              a1->bit_offset() == b1->bit_offset();
    }

    case Type::USER_DEFINED_TYPE_KIND: {
      UserDefinedTypePtr a1, b1;
      a->CastTo(&a1);
      b->CastTo(&b1);
      DCHECK(a1 && b1);

      if (a1->fields().size() != b1->fields().size())
        return false;

      for (size_t i = 0; i < a1->fields().size(); ++i) {
        const auto& af = a1->fields()[i];
        const auto& bf = b1->fields()[i];

        if (af.offset() != bf.offset() ||
            af.is_const() != bf.is_const() ||
            af.is_volatile() != bf.is_volatile() ||
            af.name() != bf.name() ||
            af.type_id() != bf.type_id()) {
          return false;
        }
      }

      return true;
    }

    case Type::POINTER_TYPE_KIND: {
      PointerTypePtr a1, b1;
      a->CastTo(&a1);
      b->CastTo(&b1);
      DCHECK(a1 && b1);

      return a1->is_const() == b1->is_const() &&
          a1->is_volatile() == b1->is_volatile() &&
          a1->content_type_id() == b1->content_type_id();
    }

    case Type::WILDCARD_TYPE_KIND:
      // No fields beyond the superclass'.
      return true;

    default:
      NOTREACHED();
      break;
  }

  return false;
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

BitfieldType::BitfieldType(const base::string16& name,
                           size_t size,
                           size_t bit_length,
                           size_t bit_offset) :
    Type(BITFIELD_TYPE_KIND, name,  size),
    bit_length_(bit_length),
    bit_offset_(bit_offset) {
}

void UserDefinedType::Finalize(const Fields& fields) {
  DCHECK_EQ(0U, fields_.size());
  for (auto field : fields)
    fields_.push_back(field);
}

UserDefinedType::Field::Field(const base::string16& name,
                              ptrdiff_t offset,
                              Flags flags,
                              TypeId type_id) :
    name_(name), offset_(offset), flags_(flags), type_id_(type_id) {
  DCHECK_NE(kNoTypeId, type_id);
}

PointerType::PointerType(
    const base::string16& name,
    size_t size,
    Flags flags,
    TypeId content_type_id)
    : Type(POINTER_TYPE_KIND, name, size),
      flags_(flags),
      content_type_id_(content_type_id) {
}

TypePtr PointerType::GetContentType() const {
  DCHECK(repository());

  return repository()->GetType(content_type_id());
}

WildcardType::WildcardType(const base::string16& name, size_t size)
    : Type(WILDCARD_TYPE_KIND, name, size) {
}

}  // namespace refinery
