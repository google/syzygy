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

Type::Type(TypeKind kind, const base::string16& name, size_t size) :
    kind_(kind), name_(name), size_(size) {
}

Type::~Type() {
}

size_t TypeHash::operator()(const TypePtr& type) {
  CompoundHash hash;

  hash.Update(type->name());
  hash.Update(type->size());
  hash.Update(type->kind());

  switch (type->kind()) {
    case Type::BasicKind:
      break;

    case Type::BitfieldKind: {
        BitfieldTypePtr bf;
        type->CastTo(&bf);
        DCHECK(bf);

        hash.Update(bf->bit_length());
        hash.Update(bf->bit_offset());
      }
      break;

    case Type::UserDefinedKind: {
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
          hash.Update(field.type().get());
        }
      }
      break;

    case Type::PointerKind: {
        PointerTypePtr ptr;
        type->CastTo(&ptr);
        DCHECK(ptr);

        hash.Update(ptr->is_const());
        hash.Update(ptr->is_volatile());

        // Use the identity of the type rather than its value as
        // it's already unique.
        hash.Update(ptr->type().get());
      }
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
    case Type::BasicKind:
      return true;

    case Type::BitfieldKind: {
        BitfieldTypePtr a1, b1;
        a->CastTo(&a1);
        b->CastTo(&b1);
        DCHECK(a1 && b1);

        return a1->bit_length() == b1->bit_length() &&
               a1->bit_offset() == b1->bit_offset();
      }
      break;

    case Type::UserDefinedKind: {
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
              af.name() != bf.name()) {
            return false;
          }

          if (!(*this)(af.type(), bf.type()))
            return false;
        }

        return true;
      }
      break;

    case Type::PointerKind: {
        PointerTypePtr a1, b1;
        a->CastTo(&a1);
        b->CastTo(&b1);
        DCHECK(a1 && b1);

        return a1->is_const() == b1->is_const() &&
            a1->is_volatile() == b1->is_volatile() &&
            (*this)(a1->type(), b1->type());
      }
      break;
    default:
      NOTREACHED();
      break;
  }

  return false;
}

UserDefinedType::UserDefinedType(const base::string16& name,
                                 size_t size,
                                 const Fields& fields) :
    Type(UserDefinedKind, name, size), fields_(fields) {
}

BasicType::BasicType(const base::string16& name, size_t size) :
    Type(BasicKind, name, size) {
}

BitfieldType::BitfieldType(const base::string16& name,
                           size_t size,
                           size_t bit_length,
                           size_t bit_offset) :
    Type(BitfieldKind, name,  size),
    bit_length_(bit_length),
    bit_offset_(bit_offset) {
}

UserDefinedType::Field::Field(const base::string16& name,
                              ptrdiff_t offset,
                              Flags flags,
                              const TypePtr& type) :
    name_(name), offset_(offset), flags_(flags), type_(type) {
}

PointerType::PointerType(const base::string16& name,
                         size_t size,
                         Flags flags,
                         const TypePtr& type)
    : Type(PointerKind, name, size), flags_(flags), type_(type) {
}

}  // namespace refinery
