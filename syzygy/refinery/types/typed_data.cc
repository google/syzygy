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
#include "syzygy/refinery/types/typed_data.h"

namespace refinery {

TypedData::TypedData() : bit_source_(nullptr) {
}

TypedData::TypedData(BitSource* bit_source,
                     TypePtr type,
                     const AddressRange& range)
    : bit_source_(bit_source), type_(type), range_(range) {
  DCHECK(bit_source_);
  DCHECK(type_);
  DCHECK(range_.IsValid());
}

bool TypedData::IsPrimitiveType() const {
  DCHECK(type_);
  return type_->kind() != Type::USER_DEFINED_TYPE_KIND;
}

bool TypedData::IsPointerType() const {
  DCHECK(type_);
  return type_->kind() == Type::POINTER_TYPE_KIND;
}

bool TypedData::GetNamedField(const base::StringPiece16& name, TypedData* out) {
  DCHECK(out);
  // TODO(siggi): Does it ever make sense to request a nameless field?
  DCHECK(!name.empty());

  UserDefinedTypePtr udt;
  if (!type_->CastTo(&udt))
    return false;

  for (size_t i = 0; i < udt->fields().size(); ++i) {
    const UserDefinedType::Field& field = udt->fields()[i];
    if (name == field.name()) {
      TypePtr field_type = udt->GetFieldType(i);
      DCHECK(field_type);
      AddressRange slice(range_.addr() + field.offset(), field_type->size());
      *out = TypedData(bit_source_, field_type, slice);
      return true;
    }
  }

  return false;
}

bool TypedData::GetField(size_t num_field, TypedData* out) {
  DCHECK(out);

  UserDefinedTypePtr udt;
  if (!type_->CastTo(&udt))
    return false;

  if (udt->fields().size() < num_field)
    return false;

  const UserDefinedType::Field& field = udt->fields()[num_field];
  TypePtr field_type = udt->GetFieldType(num_field);
  AddressRange slice(range_.addr() + field.offset(), field_type->size());
  *out = TypedData(bit_source_, field_type, slice);
  return true;
}

bool TypedData::GetValueImpl(void* data, size_t data_size) {
  DCHECK(IsPrimitiveType());
  DCHECK(bit_source_);

  if (data_size != range_.size())
    return false;

  return bit_source_->GetAll(range_, data);
}

bool TypedData::Dereference(TypedData* referenced_data) {
  DCHECK(IsPointerType());
  DCHECK(referenced_data);
  DCHECK(bit_source_);

  PointerTypePtr ptr_type;
  if (!type_->CastTo(&ptr_type))
    return false;

  TypePtr content_type = ptr_type->GetContentType();
  if (!content_type)
    return false;

  // Cater for 32 and 64 bit pointers.
  Address addr = 0;
  if (ptr_type->size() == sizeof(uint32_t)) {
    // The pointer size is 32 bit.
    uint32_t addr_32 = 0;
    if (!GetValue(&addr_32))
      return false;
    addr = addr_32;
  } else if (ptr_type->size() == sizeof(uint64_t)) {
    // The pointer size is 64 bit.
    if (!GetValue(&addr))
      return false;
  } else {
    // The pointer size is strange - bail.
    return false;
  }

  *referenced_data = TypedData(bit_source_, content_type,
                               AddressRange(addr, content_type->size()));

  return true;
}

}  // namespace refinery
