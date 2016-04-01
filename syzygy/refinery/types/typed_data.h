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

#ifndef SYZYGY_REFINERY_TYPES_TYPED_DATA_H_
#define SYZYGY_REFINERY_TYPES_TYPED_DATA_H_

#include "base/logging.h"
#include "base/strings/string_piece.h"
#include "syzygy/refinery/core/address.h"
#include "syzygy/refinery/core/bit_source.h"
#include "syzygy/refinery/types/type.h"

namespace refinery {

// Represents a range of memory with an associated type. The range of memory
// may or may not be backed with memory contents, depending on the associated
// BitSource.
// If the range of memory is backed with contents, those can be retrieved for
// primitive types, or for pointer types can be dereferenced to a new typed
// data instance.
class TypedData {
 public:
  TypedData();
  // TODO(siggi): Maybe BitSource can be a const ptr?
  TypedData(BitSource* bit_source, TypePtr type, Address address);

  // Returns true if this instance is valid - e.g. has a bit_source and a type.
  bool IsValid() const;

  // Returns true iff type()->kind() != UDT.
  // TODO(siggi): This doesn't feel right somehow.
  bool IsPrimitiveType() const;

  // Returns true if type() a pointer.
  bool IsPointerType() const;

  // Returns true if type() an array.
  bool IsArrayType() const;

  // Returns true if type() a user defined type.
  bool IsUserDefinedType() const;

  // Retrieves a named field of the UDT.
  // @pre IsPrimitiveType() == false.
  // @param name the name of the field to retrieve.
  // @param out on success returns a TypedData covering the field.
  // @returns true on success.
  bool GetNamedField(const base::StringPiece16& name, TypedData* out) const;

  // Retrieves typed data for the field of a UDT.
  // @pre IsUserDefinedType().
  // @param field_no the index of the field to retrieve.
  // @param out on success returns a TypedData covering the field.
  // @returns true on success.
  bool GetField(size_t field_no, TypedData* out) const;

  // Retrieves field information for the field of a UDT.
  // @pre IsUserDefinedType().
  // @param field_no the index of the field to retrieve.
  // @param out on success returns a FieldPtr containing the field.
  // @returns true on success.
  bool GetField(size_t field_no, FieldPtr* out) const;

  // Retrieves the number of fields.
  // @pre IsUserDefinedType().
  // @param count on success returns the number of fields.
  // @returns true on success, false otherwise.
  bool GetFieldCount(size_t* count) const;

  // Retrieves the value of the type promoted to a large integer.
  // @pre IsPrimitiveType() == true.
  // @param data on success contains the value of the data pointed to by this
  //     instance.
  // @returns true on success.
  bool GetSignedValue(int64_t* value) const;

  // Retrieves the value of the type promoted to a large unsigned integer.
  // @pre IsPrimitiveType() == true.
  // @param data on success contains the value of the data pointed to by this
  //     instance.
  // @returns true on success.
  bool GetUnsignedValue(uint64_t* value) const;

  // Retrieves the value of a pointer type promoted to a 64 bit value.
  // @pre IsPointerType() == true.
  // @param data on success contains the value of the data pointed to by this
  //     instance.
  // @returns true on success.
  bool GetPointerValue(Address* value) const;

  // Dereferences the type for pointer types.
  // @pre IsPointerType() == true.
  // @param referenced_data on success contains the pointed-to data.
  // @returns true on success.
  bool Dereference(TypedData* referenced_data) const;

  // Retrieves an array element.
  // @pre IsArrayType() == true.
  // @param index the zero-based index of the requested element.
  // @param element_data on success contains the pointed-to data.
  // @returns true on success.
  bool GetArrayElement(size_t index, TypedData* element_data) const;

  // Offsets the address of this instance by @p off times of the size of
  // this instance, and casts the result to @p new_type.
  // @note OffsetAndCast(1, some_type, &output) casts the memory immediately
  //     adjoining this instance to "some_type".
  // @param offs how much to offset.
  // @param new_type the type to cast to.
  // @param output on success returns the result.
  // @returns true on success.
  bool OffsetAndCast(ptrdiff_t offs, TypePtr new_type, TypedData* output) const;

  // Offsets the address of this instance by @p off bytes, and casts the
  // result to @p new_type.
  // @param offs how many bytes to offset.
  // @param type the type to cast to.
  // @param output on success returns the result.
  // @returns true on success.
  bool OffsetBytesAndCast(ptrdiff_t offs,
                          TypePtr new_type,
                          TypedData* output) const;

  // Retrieves the address range covered by this instance.
  // @pre IsValid() == true.
  AddressRange GetRange() const;

  // @name Accessors
  // @{
  BitSource* bit_source() const { return bit_source_; }
  const TypePtr& type() const { return type_; }
  Address addr() const { return addr_; }
  size_t bit_pos() { return bit_pos_; }
  size_t bit_len() { return bit_len_; }
  // @}

 private:
  TypedData(BitSource* bit_source,
            TypePtr type,
            Address addr,
            uint8_t bit_pos,
            uint8_t bit_len);

  template <typename DataType>
  bool GetData(DataType* data) const;

  bool GetDataImpl(void* data, size_t data_size) const;

  BitSource* bit_source_;
  TypePtr type_;
  Address addr_;

  // For bitfields these denote the bit position and length of the data.
  uint8_t bit_pos_;
  // The value zero denotes non-bitfield.
  uint8_t bit_len_;
};

template <typename DataType>
bool TypedData::GetData(DataType* data) const {
  return GetDataImpl(data, sizeof(*data));
}

}  // namespace refinery

#endif  // SYZYGY_REFINERY_TYPES_TYPED_DATA_H_
