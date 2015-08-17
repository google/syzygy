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

#include "base/logging.h"
#include "syzygy/refinery/types/type_repository.h"

namespace refinery {

namespace {

bool IsFieldOf(TypePtr type, const UserDefinedType::Field& field) {
  UserDefinedTypePtr udt;
  if (!type->CastTo(&udt))
    return false;

  for (auto f : udt->fields()) {
    if (f == field)
      return true;
  }

  return false;
}

}  // namespace

TypedData::TypedData() : bit_source_(nullptr) {
}

TypedData::TypedData(BitSource* bit_source,
                     TypePtr type,
                     const AddressRange& range)
    : bit_source_(bit_source),
      type_(type),
      range_(range),
      bit_pos_(0),
      bit_len_(0) {
  DCHECK(bit_source_);
  DCHECK(type_);
  DCHECK(range_.IsValid());
}

TypedData::TypedData(BitSource* bit_source,
                     TypePtr type,
                     const AddressRange& range,
                     size_t bit_pos,
                     size_t bit_len)
    : bit_source_(bit_source),
      type_(type),
      range_(range),
      bit_pos_(bit_pos),
      bit_len_(bit_len) {
  DCHECK(bit_source_);
  DCHECK(type_);
  DCHECK(range_.IsValid());
  DCHECK(bit_pos >= 0 && bit_pos < range.size() * 8);
  DCHECK(bit_len >= 0 && bit_len < range.size() * 8);
}

bool TypedData::IsPrimitiveType() const {
  DCHECK(type_);
  switch (type_->kind()) {
    case Type::BASIC_TYPE_KIND:
    case Type::POINTER_TYPE_KIND:
      return true;

    default:
      return false;
  }
}

bool TypedData::IsPointerType() const {
  DCHECK(type_);
  return type_->kind() == Type::POINTER_TYPE_KIND;
}

bool TypedData::IsArrayType() const {
  DCHECK(type_);
  return type_->kind() == Type::ARRAY_TYPE_KIND;
}

bool TypedData::GetNamedField(const base::StringPiece16& name, TypedData* out) {
  DCHECK(out);
  // TODO(siggi): Does it ever make sense to request a nameless field?
  DCHECK(!name.empty());
  DCHECK(type_);

  UserDefinedTypePtr udt;
  if (!type_->CastTo(&udt))
    return false;

  for (size_t i = 0; i < udt->fields().size(); ++i) {
    const UserDefinedType::Field& field = udt->fields()[i];
    if (name == field.name()) {
      TypePtr field_type = udt->GetFieldType(i);
      DCHECK(field_type);
      AddressRange slice(range_.addr() + field.offset(), field_type->size());
      *out = TypedData(bit_source_, field_type, slice, field.bit_pos(),
                       field.bit_len());
      return true;
    }
  }

  return false;
}

bool TypedData::GetField(const UserDefinedType::Field& field, TypedData* out) {
  DCHECK(out);
  DCHECK(type_);
  DCHECK(!IsPrimitiveType());
  DCHECK(IsFieldOf(type_, field));

  TypePtr field_type = type_->repository()->GetType(field.type_id());
  AddressRange slice(range_.addr() + field.offset(), field_type->size());
  *out = TypedData(bit_source_, field_type, slice);
  return true;
}

bool TypedData::GetSignedValue(int64_t* value) {
  DCHECK(value);
  DCHECK(IsPrimitiveType());
  DCHECK(bit_source_);

  int64 ret = 0;
  switch (type_->size()) {
    case sizeof(int8_t): {
      int8_t v8 = 0;
      if (!GetData(&v8))
        return false;

      ret = v8;
      break;
    }

    case sizeof(int16_t): {
      int16_t v16 = 0;
      if (!GetData(&v16))
        return false;

      ret = v16;
      break;
    }

    case sizeof(int32_t): {
      int32_t v32 = 0;
      if (!GetData(&v32))
        return false;

      ret = v32;
      break;
    }

    case sizeof(int64_t): {
      int64_t v64 = 0;
      if (!GetData(&v64))
        return false;

      ret = v64;
      break;
    }

    default:
      // Wonky size - no can do this. Maybe this type is a float or such?
      return false;
  }

  // Shift, mask and sign-extend bit fields.
  if (bit_len_ != 0) {
    // Shift the bits into place.
    ret >>= bit_pos_;

    // Mask to the used bits.
    const uint64_t mask = (1ll << bit_len_) - 1;
    ret &= mask;

    // Check the sign bit and extend out if set.
    if (ret & (mask ^ (mask >> 1)))
      ret |= (-1ll & ~mask);
  }

  *value = ret;
  return true;
}

bool TypedData::GetUnsignedValue(uint64_t* value) {
  DCHECK(value);
  DCHECK(IsPrimitiveType());
  DCHECK(bit_source_);

  uint64 ret = 0;
  switch (type_->size()) {
    case sizeof(uint8_t): {
      uint8_t v8 = 0;
      if (!GetData(&v8))
        return false;

      ret = v8;
      break;
    }

    case sizeof(uint16_t): {
      uint16_t v16 = 0;
      if (!GetData(&v16))
        return false;

      ret = v16;
      break;
    }

    case sizeof(uint32_t): {
      uint32_t v32 = 0;
      if (!GetData(&v32))
        return false;

      ret = v32;
      break;
    }

    case sizeof(uint64_t): {
      uint64_t v64 = 0;
      if (!GetData(&v64))
        return false;

      ret = v64;
      break;
    }

    default:
      // Wonky size - no can do this. Maybe this type is a float or such?
      return false;
  }

  // Shift & mask bit fields.
  if (bit_len_ != 0) {
    // Shift the bits uinto place.
    ret >>= bit_pos_;

    // Mask to the used bits.
    const uint64_t mask = (1ull << bit_len_) - 1;
    ret &= mask;
  }

  *value = ret;
  return true;
}

bool TypedData::GetPointerValue(Address* value) {
  DCHECK(value);
  DCHECK(IsPointerType());
  DCHECK_EQ(0, bit_len_);  // Bitfields need not apply for pointer.
  DCHECK(bit_source_);

  PointerTypePtr ptr_type;
  if (!type_->CastTo(&ptr_type))
    return false;

  // Cater for 32- and 64-bit pointers.
  if (ptr_type->size() == sizeof(uint32_t)) {
    // The pointer size is 32 bit.
    uint32_t addr_32 = 0;
    if (GetData(&addr_32)) {
      *value = addr_32;
      return true;
    }
  } else if (ptr_type->size() == sizeof(uint64_t)) {
    // The pointer size is 64 bit.
    if (GetData(value))
      return true;
  }

  // The pointer size is strange or we failed on retrieving the value.
  return false;
}

bool TypedData::Dereference(TypedData* referenced_data) {
  DCHECK(referenced_data);
  DCHECK(IsPointerType());
  DCHECK(bit_source_);

  PointerTypePtr ptr_type;
  if (!type_->CastTo(&ptr_type))
    return false;

  TypePtr content_type = ptr_type->GetContentType();
  if (!content_type)
    return false;

  Address addr = 0;
  if (!GetPointerValue(&addr))
    return false;

  *referenced_data = TypedData(bit_source_, content_type,
                               AddressRange(addr, content_type->size()));

  return true;
}

bool TypedData::GetArrayElement(size_t index, TypedData* element_data) {
  DCHECK(element_data);
  DCHECK(IsArrayType());
  DCHECK(bit_source_);

  ArrayTypePtr array_ptr;
  if (!type_->CastTo(&array_ptr))
    return false;

  if (index >= array_ptr->num_elements())
    return false;

  TypePtr element_type = array_ptr->GetElementType();
  if (!element_type)
    return false;

  Address element_addr = range_.addr() + index * element_type->size();
  *element_data = TypedData(bit_source_, element_type,
                            AddressRange(element_addr, element_type->size()));

  return true;
}

bool TypedData::GetDataImpl(void* data, size_t data_size) {
  DCHECK(data);
  DCHECK(IsPrimitiveType());
  DCHECK(bit_source_);

  if (data_size != range_.size())
    return false;

  return bit_source_->GetAll(range_, data);
}

}  // namespace refinery
