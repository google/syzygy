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

bool IsFieldOf(TypePtr type, FieldPtr field) {
  DCHECK(type); DCHECK(field);

  UserDefinedTypePtr udt;
  if (!type->CastTo(&udt))
    return false;

  for (FieldPtr f : udt->fields()) {
    if (*f == *field)
      return true;
  }

  return false;
}

}  // namespace

TypedData::TypedData() : bit_source_(nullptr) {
}

TypedData::TypedData(BitSource* bit_source, TypePtr type, Address addr)
    : bit_source_(bit_source),
      type_(type),
      addr_(addr),
      bit_pos_(0),
      bit_len_(0) {
  DCHECK(bit_source_);
  DCHECK(type_);
}

TypedData::TypedData(BitSource* bit_source,
                     TypePtr type,
                     Address addr,
                     uint8_t bit_pos,
                     uint8_t bit_len)
    : bit_source_(bit_source),
      type_(type),
      addr_(addr),
      bit_pos_(bit_pos),
      bit_len_(bit_len) {
  DCHECK(bit_source_);
  DCHECK(type_);
  DCHECK(bit_pos >= 0 && bit_pos < type_->size() * 8);
  DCHECK(bit_len >= 0 && bit_len < type_->size() * 8);
}

bool TypedData::IsValid() const {
  return bit_source_ != nullptr && type_ != nullptr;
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

bool TypedData::IsUserDefinedType() const {
  DCHECK(type_);
  return type_->kind() == Type::USER_DEFINED_TYPE_KIND;
}

bool TypedData::GetNamedField(const base::StringPiece16& name,
                              TypedData* out) const {
  DCHECK(out);
  // TODO(siggi): Does it ever make sense to request a nameless field?
  DCHECK(!name.empty());
  DCHECK(type_);

  UserDefinedTypePtr udt;
  if (!type_->CastTo(&udt))
    return false;

  const UserDefinedType::Fields& fields = udt->fields();
  for (size_t i = 0; i < fields.size(); ++i) {
    FieldPtr field = fields[i];

    MemberFieldPtr member;
    if (!field->CastTo(&member))
      continue;

    if (name == member->name())
      return GetField(i, out);
  }

  return false;
}

bool TypedData::GetField(size_t field_no, TypedData* out) const {
  DCHECK(type_);
  DCHECK(IsUserDefinedType());
  DCHECK(out);

  FieldPtr field;
  if (!GetField(field_no, &field))
    return false;

  uint8_t bit_pos = 0U;
  uint8_t bit_len = 0U;
  MemberFieldPtr member;
  if (field->CastTo(&member)) {
    bit_pos = static_cast<uint8_t>(member->bit_pos());
    bit_len = static_cast<uint8_t>(member->bit_len());
  }

  *out = TypedData(bit_source_, field->GetType(), addr() + field->offset(),
                   bit_pos, bit_len);
  return true;
}

bool TypedData::GetField(size_t field_no, FieldPtr* out) const {
  DCHECK(type_);
  DCHECK(IsUserDefinedType());
  DCHECK(out);

  UserDefinedTypePtr udt;
  if (!type_->CastTo(&udt))
    return false;
  if (field_no >= udt->fields().size())
    return false;

  *out = udt->fields()[field_no];
  return true;
}

bool TypedData::GetFieldCount(size_t* count) const {
  DCHECK(type_);
  DCHECK(IsUserDefinedType());

  UserDefinedTypePtr udt;
  if (!type_->CastTo(&udt))
    return false;

  *count = udt->fields().size();
  return true;
}

bool TypedData::GetSignedValue(int64_t* value) const {
  DCHECK(value);
  DCHECK(IsPrimitiveType());
  DCHECK(bit_source_);

  int64_t ret = 0;
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

bool TypedData::GetUnsignedValue(uint64_t* value) const {
  DCHECK(value);
  DCHECK(IsPrimitiveType());
  DCHECK(bit_source_);

  uint64_t ret = 0;
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

bool TypedData::GetPointerValue(Address* value) const {
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

bool TypedData::Dereference(TypedData* referenced_data) const {
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

  *referenced_data = TypedData(bit_source_, content_type, addr);

  return true;
}

bool TypedData::GetArrayElement(size_t index, TypedData* element_data) const {
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

  *element_data = TypedData(bit_source_, element_type,
                            addr() + index * element_type->size());

  return true;
}

bool TypedData::OffsetAndCast(ptrdiff_t offs,
                              TypePtr new_type,
                              TypedData* output) const {
  DCHECK(output);
  if (!new_type)
    return false;
  if (!IsValid())
    return false;

  return OffsetBytesAndCast(offs * type()->size(), new_type, output);
}

bool TypedData::OffsetBytesAndCast(ptrdiff_t offs,
                                   TypePtr new_type,
                                   TypedData* output) const {
  DCHECK(output);
  if (!new_type)
    return false;
  if (!IsValid())
    return false;

  // TODO(siggi): Validate the new range against the bit source with a new
  //     interface.
  *output = TypedData(bit_source(), new_type, addr() + offs);
  return true;
}

AddressRange TypedData::GetRange() const {
  return AddressRange(addr(), type()->size());
}

bool TypedData::GetDataImpl(void* data, size_t data_size) const {
  DCHECK(data);
  DCHECK(IsPrimitiveType());
  DCHECK(bit_source_);

  if (data_size != type_->size())
    return false;

  return bit_source_->GetAll(GetRange(), data);
}

}  // namespace refinery
