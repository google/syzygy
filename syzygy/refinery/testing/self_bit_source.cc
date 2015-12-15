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
//
// Implements a bit source that reads its own process' memory.
#include "syzygy/refinery/testing/self_bit_source.h"

#include <Windows.h>

namespace testing {

SelfBitSource::~SelfBitSource() {
}

bool SelfBitSource::GetAll(const refinery::AddressRange& range,
                           void* data_ptr) {
  DCHECK(range.IsValid());
  DCHECK(data_ptr);

  size_t read_bytes = 0;
  if (!GetFrom(range, &read_bytes, data_ptr))
    return false;
  if (read_bytes != range.size())
    return false;

  return true;
}

bool SelfBitSource::GetFrom(const refinery::AddressRange& range,
                            size_t* data_cnt,
                            void* data_ptr) {
  DCHECK(range.IsValid());
  DCHECK(data_cnt);
  DCHECK(data_ptr);

  *data_cnt = 0;

  DWORD read_bytes = 0;
  BOOL succeeded = ::ReadProcessMemory(
      ::GetCurrentProcess(), reinterpret_cast<const void*>(range.start()),
      data_ptr, range.size(), &read_bytes);
  if (!succeeded)
    return false;
  *data_cnt = read_bytes;

  return read_bytes != 0;
}

bool SelfBitSource::HasSome(const refinery::AddressRange& range) {
  // TODO(siggi): Fixme!
  return true;
}

}  // namespace testing
