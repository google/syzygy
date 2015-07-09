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

#ifndef SYZYGY_REFINERY_CORE_BIT_SOURCE_H_
#define SYZYGY_REFINERY_CORE_BIT_SOURCE_H_

#include "base/logging.h"
#include "base/macros.h"
#include "syzygy/refinery/core/address.h"

namespace refinery {

// An interface to the contents of an address space. Typically, the address
// space's contents are only partially known. Access to the memory is
// copy-based to avoid any alignment issues.
class BitSource {
 public:
  virtual ~BitSource() = 0 {}

  // Retrieves all bytes from a range.
  // @pre @p range must be a valid range.
  // @param range the requested range.
  // @param data_ptr a buffer of size at least that of @p range. On success,
  //    contains the returned data.
  // @returns true iff the full contents of @p range are available.
  virtual bool GetAll(const AddressRange& range, void* data_ptr) = 0;

  // Determine how many bytes are available from the head of a range and
  // optionally retrieve them.
  // @pre @p range must be a valid range.
  // @param range the requested range.
  // @param data_cnt on success, contains the number of bytes returned from the
  //   head of @p range.
  // @param data_ptr a buffer of size at least that of @p range or nullptr. On
  //   success, a valid buffer contains the returned data.
  // @returns true iff some data is available from the head of @p range.
  virtual bool GetFrom(const AddressRange& range,
                       size_t* data_cnt,
                       void* data_ptr) = 0;

  // Determines whether any bytes are available for a range.
  // @param range the range.
  // @returns true iff some data is available in the desired range.
  virtual bool HasSome(const AddressRange& range) = 0;
};

}  // namespace refinery

#endif  // SYZYGY_REFINERY_CORE_BIT_SOURCE_H_
