// Copyright 2012 Google Inc. All Rights Reserved.
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
#include "syzygy/agent/asan/asan_shadow.h"

#include "base/stringprintf.h"
#include "syzygy/common/align.h"

namespace agent {
namespace asan {

namespace {

// The first 64k of the memory are not addressable.
const size_t kAddressLowerBound = 0x10000;

// The upper bound of the addressable memory.
const size_t kAddressUpperBound =
    Shadow::kShadowSize << Shadow::kShadowGranularityLog;

}  // namespace

uint8 Shadow::shadow_[kShadowSize];

void Shadow::SetUp() {
  // Poison the shadow memory.
  Poison(shadow_, kShadowSize, kAsanMemoryByte);
  // Poison the first 64k of the memory as they're not addressable.
  Poison(0, kAddressLowerBound, kInvalidAddress);
}

void Shadow::TearDown() {
  // Unpoison the shadow memory.
  Unpoison(shadow_, kShadowSize);
  // Unpoison the first 64k of the memory.
  Unpoison(0, kAddressLowerBound);
}

void Shadow::Reset() {
  memset(shadow_, 0, kShadowSize);
}

void Shadow::Poison(const void* addr, size_t size, ShadowMarker shadow_val) {
  uintptr_t index = reinterpret_cast<uintptr_t>(addr);
  uintptr_t start = index & 0x7;
  DCHECK_EQ(0U, (index + size) & 0x7);

  index >>= 3;
  if (start)
    shadow_[index++] = start;

  size >>= 3;
  DCHECK_GT(arraysize(shadow_), index + size);
  memset(shadow_ + index, shadow_val, size);
}

void Shadow::Unpoison(const void* addr, size_t size) {
  uintptr_t index = reinterpret_cast<uintptr_t>(addr);
  DCHECK_EQ(0U, index & 0x7);

  uint8 remainder = size & 0x7;
  index >>= 3;
  size >>= 3;
  DCHECK_GT(arraysize(shadow_), index + size);
  memset(shadow_ + index, kHeapAddressableByte, size);

  if (remainder != 0)
    shadow_[index + size] = remainder;
}

void Shadow::MarkAsFreed(const void* addr, size_t size) {
  uintptr_t index = reinterpret_cast<uintptr_t>(addr);
  uintptr_t start = index & 0x7;

  index >>= 3;
  if (start)
    shadow_[index++] = kHeapFreedByte;

  size_t size_shadow = size >> 3;
  DCHECK_GT(arraysize(shadow_), index + size_shadow);
  memset(shadow_ + index, kHeapFreedByte, size_shadow);
  if ((size & 0x7) != 0)
    shadow_[index + size_shadow] = kHeapFreedByte;
}

bool Shadow::IsAccessible(const void* addr) {
  uintptr_t index = reinterpret_cast<uintptr_t>(addr);
  uintptr_t start = index & 0x7;

  index >>= 3;

  DCHECK_GT(arraysize(shadow_), index);
  uint8 shadow = shadow_[index];
  if (shadow == 0)
    return true;

  if ((shadow & kHeapNonAccessibleByteMask) != 0)
    return false;

  return start < shadow;
}

Shadow::ShadowMarker Shadow::GetShadowMarkerForAddress(const void* addr) {
  uintptr_t index = reinterpret_cast<uintptr_t>(addr);
  index >>= 3;

  DCHECK_GT(arraysize(shadow_), index);
  return static_cast<ShadowMarker>(shadow_[index]);
}

void Shadow::CloneShadowRange(const void* src_pointer,
                              void* dst_pointer,
                              size_t size) {
  DCHECK_EQ(0U, size & 0x7);

  uintptr_t src_index = reinterpret_cast<uintptr_t>(src_pointer);
  DCHECK_EQ(0U, src_index & 0x7);
  src_index >>= 3;

  uintptr_t dst_index = reinterpret_cast<uintptr_t>(dst_pointer);
  DCHECK_EQ(0U, dst_index & 0x7);
  dst_index >>= 3;

  size_t size_shadow = size >> 3;

  memcpy(shadow_ + dst_index, shadow_ + src_index, size_shadow);
}

void Shadow::AppendShadowByteText(const char *prefix,
                                  uintptr_t index,
                                  std::string* output,
                                  size_t bug_index) {
  base::StringAppendF(
      output, "%s0x%08x:", prefix, reinterpret_cast<void*>(index << 3));
  char separator = ' ';
  for (uint32 i = 0; i < 8; i++) {
    if (index + i == bug_index)
      separator = '[';
    uint8 shadow_value = shadow_[index + i];
    base::StringAppendF(
        output, "%c%x%x", separator, shadow_value >> 4, shadow_value & 15);
    if (separator == '[')
      separator = ']';
    else if (separator == ']')
      separator = ' ';
  }
  if (separator == ']')
    base::StringAppendF(output, "]");
  base::StringAppendF(output, "\n");
}

void Shadow::AppendShadowArrayText(const void* addr, std::string* output) {
  uintptr_t index = reinterpret_cast<uintptr_t>(addr);
  index >>= 3;
  size_t index_start = index;
  index_start &= ~0x7;
  for (int i = -4; i <= 4; i++) {
    const char * const prefix = (i == 0) ? "=>" : "  ";
    AppendShadowByteText(prefix, (index_start + i * 8), output, index);
  }
}

void Shadow::AppendShadowMemoryText(const void* addr, std::string* output) {
  base::StringAppendF(output, "Shadow bytes around the buggy address:\n");
  AppendShadowArrayText(addr, output);
  base::StringAppendF(output,
      "Shadow byte legend (one shadow byte represents 8 application bytes):\n");
  base::StringAppendF(output, "  Addressable:           %x%x\n",
      kHeapAddressableByte >> 4, kHeapAddressableByte & 15);
  base::StringAppendF(output,
    "  Partially addressable: 01 02 03 04 05 06 07\n");
  base::StringAppendF(output, "  Heap left redzone:     %x%x\n",
      kHeapLeftRedzone >> 4, kHeapLeftRedzone & 15);
  base::StringAppendF(output, "  Heap righ redzone:     %x%x\n",
      kHeapRightRedzone >> 4, kHeapRightRedzone & 15);
  base::StringAppendF(output, "  Freed Heap region:     %x%x\n",
      kHeapFreedByte >> 4, kHeapFreedByte & 15);
}


const uint8* Shadow::FindBlockBeginning(const uint8* mem) {
  mem = reinterpret_cast<uint8*>(common::AlignDown(
      reinterpret_cast<size_t>(mem), kShadowGranularity));
  // Start by checking if |mem| points inside a block.
  if (GetShadowMarkerForAddress(mem) != kHeapLeftRedzone &&
      GetShadowMarkerForAddress(mem) != kHeapRightRedzone) {
    do {
      mem -= kShadowGranularity;
    } while (GetShadowMarkerForAddress(mem) != kHeapLeftRedzone &&
             GetShadowMarkerForAddress(mem) != kHeapRightRedzone &&
             mem > reinterpret_cast<uint8*>(kAddressLowerBound));
    // If the shadow marker for |mem| corresponds to a right redzone then this
    // means that its original value was pointing after a block.
    if (GetShadowMarkerForAddress(mem) == kHeapRightRedzone ||
        mem <= reinterpret_cast<uint8*>(kAddressLowerBound)) {
      return NULL;
    }
  }

  // Look for the beginning of the memory block.
  while (GetShadowMarkerForAddress(mem) != kHeapLeftRedzone ||
      GetShadowMarkerForAddress(mem - kShadowGranularity) == kHeapLeftRedzone &&
      mem > reinterpret_cast<uint8*>(kAddressLowerBound)) {
    mem -= kShadowGranularity;
  }
  if (mem <= reinterpret_cast<uint8*>(kAddressLowerBound))
    return NULL;

  return mem;
}

size_t Shadow::GetAllocSize(const uint8* mem) {
  size_t alloc_size = 0;
  const uint8* aligned_mem = reinterpret_cast<uint8*>(common::AlignDown(
      reinterpret_cast<size_t>(mem), kShadowGranularity));
  size_t alignment_offset = mem - aligned_mem;
  const uint8* mem_begin = FindBlockBeginning(mem);

  if (mem_begin == NULL)
    return 0;

  // Look for the heap right redzone.
  while (GetShadowMarkerForAddress(mem) != kHeapRightRedzone &&
         mem < reinterpret_cast<uint8*>(kAddressUpperBound)) {
    mem += kShadowGranularity;
  }

  if (mem >= reinterpret_cast<uint8*>(kAddressUpperBound))
    return 0;

  // Find the end of the block.
  while (GetShadowMarkerForAddress(mem) == kHeapRightRedzone  &&
         mem < reinterpret_cast<uint8*>(kAddressUpperBound)) {
    mem += kShadowGranularity;
  }

  if (mem >= reinterpret_cast<uint8*>(kAddressUpperBound))
    return 0;

  return mem - mem_begin - alignment_offset;
}

}  // namespace asan
}  // namespace agent
