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
  TypedData(BitSource* bit_source, TypePtr type, const AddressRange& range);

  // Returns true iff type()->kind() != UDT.
  // TODO(siggi): This doesn't feel right somehow.
  bool IsPrimitiveType() const;

  // Returns true if type() a pointer.
  bool IsPointerType() const;

  // Retrieves a named field of the UDT.
  // @pre IsPrimitiveType() == false.
  // @param name the name of the field to retrieve.
  // @param out on success returns a TypedData covering the field.
  // @returns true on success.
  bool GetNamedField(const base::StringPiece16& name, TypedData* out);

  // Retrieves a numbered field of the UDT.
  // @pre !IsPrimitiveType().
  // @param num_field the index of the field to retrieve.
  // @param out on success returns a TypedData covering the field.
  // @returns true on success.
  bool GetField(size_t num_field, TypedData* out);

  // Retrieves the value of the type.
  // @pre IsPrimitiveType() == true.
  // @param data on success contains the value of the data pointed to by this
  //     instance.
  // @returns true on success.
  // @note sizeof(DataType) must be equal to the type's ranges size.
  template <typename DataType>
  bool GetValue(DataType* data);

  // Dereferences the type for pointer types.
  // @pre IsPointerType() == true.
  // @param referenced_data on success contains the pointed-to data.
  // @returns true on success.
  bool Dereference(TypedData* referenced_data);

  // @name Accessors
  // @{
  BitSource* bit_source() const { return bit_source_; }
  const TypePtr& type() const { return type_; }
  const AddressRange& range() const { return range_; }
  // @}

 private:
  bool GetValueImpl(void* data, size_t data_size);

  // TODO(siggi): this class needs to be bit-granular to cater for bitfields.
  BitSource* bit_source_;
  TypePtr type_;
  AddressRange range_;
};

template <typename DataType>
bool TypedData::GetValue(DataType* data) {
  return GetValueImpl(data, sizeof(*data));
}

}  // namespace refinery

#endif  // SYZYGY_REFINERY_TYPES_TYPED_DATA_H_
