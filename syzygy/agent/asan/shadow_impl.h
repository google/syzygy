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
// Contains the implementation details of the templated functions of Asan's
// shadow memory. See 'shadow.h' for more information. This file is not
// meant to be included directly, but is brought in by shadow.h.
#ifndef SYZYGY_AGENT_ASAN_SHADOW_IMPL_H_
#define SYZYGY_AGENT_ASAN_SHADOW_IMPL_H_

template <typename type>
bool Shadow::GetNullTerminatedArraySize(const void* addr,
                                        size_t max_size,
                                        size_t* size) const {
  DCHECK_NE(reinterpret_cast<const void*>(NULL), addr);
  DCHECK_NE(reinterpret_cast<size_t*>(NULL), size);

  uintptr_t index = reinterpret_cast<uintptr_t>(addr);
  const type* addr_value = reinterpret_cast<const type*>(addr);
  index >>= 3;
  *size = 0;

  if (index > length_)
    return false;

  // Scan the input array 8 bytes at a time until we've found a NULL value or
  // we've reached the end of an accessible memory block.
  // TODO(sebmarchand): Look into doing this more efficiently.
  while (true) {
    uint8_t shadow = shadow_[index++];
    if (ShadowMarkerHelper::IsRedzone(shadow))
      return false;

    uint8_t max_index = shadow ? shadow : kShadowRatio;
    DCHECK_EQ(0U, max_index % sizeof(type));
    max_index /= sizeof(type);
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

namespace internal {

template <typename AccessType>
const AccessType* AlignDown(const uint8_t* ptr) {
  DCHECK(::common::IsPowerOfTwo(sizeof(AccessType)));
  return reinterpret_cast<const AccessType*>(reinterpret_cast<uintptr_t>(ptr) &
                                             ~(sizeof(AccessType) - 1));
}

template <typename AccessType>
const AccessType* AlignUp(const uint8_t* ptr) {
  DCHECK(::common::IsPowerOfTwo(sizeof(AccessType)));

  return reinterpret_cast<const AccessType*>(
      reinterpret_cast<uintptr_t>(ptr + sizeof(AccessType) - 1) &
      ~(sizeof(AccessType) - 1));
}

// Returns true iff every byte in the range [@p start, @p end) is zero.
// This function reads sizeof(AccessType) bytes at a time from memory at
// natural alignment for AccessType. Note this may under- and over-read the
// provided buffer by sizeof(AccessType)-1 bytes, but will never cross
// sizeof(AccessType) boundary. The implementation is intended to allow the
// compiler to inline it to the usage.
// @param start the first byte to test.
// @param end the byte after the last byte to test.
// @returns true iff every byte from @p *start to @p *(end - 1) is zero.
// @note this function is templatized to allow easily performance testing
//     it with different AccessType parameters.
template <typename AccessType>
bool IsZeroBufferImpl(const uint8_t* start_in, const uint8_t* end_in) {
  if (start_in == end_in)
    return true;

  // Round the start address downwards, and the end address upwards.
  const AccessType* start = AlignDown<AccessType>(start_in);
  const AccessType* end = AlignUp<AccessType>(end_in);

  // Assuming start_in != end_in the alignment should leave us at least one
  // element to check.
  DCHECK_NE(start, end);
  AccessType val = *start;

  // Mask out the bytes read due to starting alignment.
  const AccessType kMask = static_cast<AccessType>(-1LL);
  val &= kMask << ((start_in - reinterpret_cast<const uint8_t*>(start)) * 8);
  ++start;
  while (start != end) {
    if (val != 0U)
      return false;
    val = *start++;
  }

  // Mask out the bytes read due to end alignment.
  val &= kMask >> ((reinterpret_cast<const uint8_t*>(end) - end_in) * 8);
  if (val != 0U)
    return false;

  return true;
}

}  // namespace internal

#endif  // SYZYGY_AGENT_ASAN_SHADOW_IMPL_H_
