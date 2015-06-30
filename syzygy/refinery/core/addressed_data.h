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

#ifndef SYZYGY_REFINERY_CORE_ADDRESSED_DATA_H_
#define SYZYGY_REFINERY_CORE_ADDRESSED_DATA_H_

#include "base/numerics/safe_math.h"
#include "syzygy/common/buffer_parser.h"
#include "syzygy/refinery/core/address.h"

namespace refinery {

// A view on a buffer located at a given address. The underlying data must
// outlive this class. Methods are provided to copy data from the underlying
// buffer; copies are preferred to avoid memory alignment issues.
class AddressedData {
 public:
  // Creates an empty address range.
  AddressedData();

  // @param range the address range spanned by the data.
  // @param data a pointer to data of at least size specified by @p range.
  AddressedData(const AddressRange& range, const void* data);

  // Retrieve a @p data_type located at @p addr.
  // @param addr the address to copy from.
  // @param data_type on success, the returned data.
  // @returns true iff the buffer contains a range of sizeof(DataType) bytes
  //    from @p addr.
  template <class DataType>
  bool GetAt(Address addr, DataType* data_type) {
    return GetAt(AddressRange(addr, sizeof(DataType)),
                 reinterpret_cast<void*>(data_type));
  }

  // Retrieve bytes from an address range.
  // @pre @p range must be a valid range.
  // @param range the requested range.
  // @param data_ptr a buffer of size at least that of @p range. On success,
  //    contains the returned data.
  // @returns true iff the buffer spans @p range.
  bool GetAt(const AddressRange& range, void* data_ptr);

  // Retrieve a slice of the address range.
  // @param index the start of the slice to create.
  // @param len the length of the slice range to create.
  // @param slice the output slice.
  // @returns true if [index, index + len] are in this range.
  bool Slice(size_t index, size_t len, AddressedData* slice);

 private:
  AddressRange range_;
  common::BinaryBufferParser buffer_parser_;
};

}  // namespace refinery

#endif  // SYZYGY_REFINERY_CORE_ADDRESSED_DATA_H_
