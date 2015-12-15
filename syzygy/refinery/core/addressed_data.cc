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

#include "syzygy/refinery/core/addressed_data.h"

#include <stdint.h>

namespace refinery {

AddressedData::AddressedData() : buffer_parser_(nullptr, 0) {
}

AddressedData::AddressedData(const AddressRange& range, const void* data) :
  range_(range), buffer_parser_(data, range.size()) {
}

bool AddressedData::GetAt(const AddressRange& range, void* data_ptr) {
  DCHECK(range.IsValid());

  // Ensure the desired range is fully contained.
  if (!range_.Contains(range))
    return false;

  // Determine offset into the backing buffer.
  Address offset = range.start() - range_.start();
  base::CheckedNumeric<size_t> checked_offset =
      base::CheckedNumeric<size_t>::cast(offset);
  if (!checked_offset.IsValid())
    return false;

  // Copy bytes.
  const void* buffer_ptr;
  if (!buffer_parser_.GetAt(checked_offset.ValueOrDie(), range.size(),
                            &buffer_ptr)) {
    return false;
  }
  memcpy(data_ptr, buffer_ptr, range.size());
  return true;
}

bool AddressedData::Slice(size_t index, size_t len, AddressedData* slice) {
  const void* inner_ptr = nullptr;
  if (!buffer_parser_.GetAt(index, len, &inner_ptr))
    return false;

  *slice = AddressedData(AddressRange(range_.start() + index, len), inner_ptr);
  return true;
}

}  // namespace refinery
