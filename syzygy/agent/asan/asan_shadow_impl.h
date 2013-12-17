// Copyright 2013 Google Inc. All Rights Reserved.
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
// Contains the implementation details of the templated functions of ASAN's
// shadow memory. See 'asan_shadow.h' for more information. This file is not
// meant to be included directly, but is brought in by asan_shadow.h.
#ifndef SYZYGY_AGENT_ASAN_ASAN_SHADOW_IMPL_H_
#define SYZYGY_AGENT_ASAN_ASAN_SHADOW_IMPL_H_

template<typename type>
bool Shadow::GetNullTerminatedArraySize(const void* addr,
                                        size_t max_size,
                                        size_t* size) {
  DCHECK_NE(reinterpret_cast<const void*>(NULL), addr);
  DCHECK_NE(reinterpret_cast<size_t*>(NULL), size);

  uintptr_t index = reinterpret_cast<uintptr_t>(addr);
  const type* addr_value = reinterpret_cast<const type*>(addr);
  index >>= 3;
  *size = 0;

  // Scan the input array 8 bytes at a time until we've found a NULL value or
  // we've reached the end of an accessible memory block.
  // TODO(sebmarchand): Look into doing this more efficiently.
  while (true) {
    uint8 shadow = shadow_[index++];
    if ((shadow & kHeapNonAccessibleByteMask) != 0)
      return false;

    uint8 max_index = shadow ? shadow : kShadowGranularity;
    DCHECK_EQ(0U, max_index % sizeof(type));
    max_index /=  sizeof(type);
    while (max_index-- > 0) {
      (*size) += sizeof(type);
      if (*size == max_size || *addr_value == 0)
        return true;
      addr_value++;
    }

    if (shadow != 0)
      return false;
  }
}

#endif  // SYZYGY_AGENT_ASAN_ASAN_SHADOW_IMPL_H_
