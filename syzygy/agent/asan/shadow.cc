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

#include "syzygy/agent/asan/shadow.h"

#include <windows.h>
#include <algorithm>

#include "base/strings/stringprintf.h"
#include "base/win/pe_image.h"
#include "syzygy/common/align.h"

namespace agent {
namespace asan {

namespace {

static const size_t kPageSize = GetPageSize();

// Converts an address to a page index and bit mask.
inline void AddressToPageMask(const void* address,
                              size_t* index,
                              uint8_t* mask) {
  DCHECK_NE(static_cast<size_t*>(nullptr), index);
  DCHECK_NE(static_cast<uint8_t*>(nullptr), mask);

  size_t i = reinterpret_cast<uintptr_t>(address) / kPageSize;
  *index = i / 8;
  *mask = 1 << (i % 8);
}

}  // namespace

Shadow::Shadow() : own_memory_(false), shadow_(nullptr), length_(0) {
  Init(RequiredLength());
}

Shadow::Shadow(size_t length)
    : own_memory_(false), shadow_(nullptr), length_(0) {
  Init(length);
}

Shadow::Shadow(void* shadow, size_t length)
    : own_memory_(false), shadow_(nullptr), length_(0) {
  Init(false, shadow, length);
}

Shadow::~Shadow() {
  if (own_memory_)
    CHECK(::VirtualFree(shadow_, 0, MEM_RELEASE));
  own_memory_ = false;
  shadow_ = nullptr;
  length_ = 0;
}

// static
size_t Shadow::RequiredLength() {
  MEMORYSTATUSEX mem_status = {};
  mem_status.dwLength = sizeof(mem_status);
  CHECK(::GlobalMemoryStatusEx(&mem_status));

  // Because of the way the interceptors work we only support 2GB or 4GB
  // virtual memory sizes, even if the actual is 3GB (32-bit windows, LAA,
  // and 4GT kernel option enabled).
  uint64_t mem_size = ::common::AlignUp64(mem_status.ullTotalVirtual,
                                          2UL << 30);  // 2GB.

  return mem_size >> kShadowRatioLog;
}

void Shadow::SetUp() {
  // Poison the shadow object itself.
  const void* self = nullptr;
  size_t self_size = 0;
  GetPointerAndSize(&self, &self_size);
  DCHECK(::common::IsAligned(self, kShadowRatio));
  DCHECK(::common::IsAligned(self_size, kShadowRatio));
  Poison(self, self_size, kAsanMemoryMarker);

  // Poison the shadow memory.
  Poison(shadow_, length_, kAsanMemoryMarker);
  // Poison the first 64k of the memory as they're not addressable.
  Poison(0, kAddressLowerBound, kInvalidAddressMarker);
  // Poison the protection bits array.
  Poison(page_bits_.data(), page_bits_.size(), kAsanMemoryMarker);
}

void Shadow::TearDown() {
  // Unpoison the shadow object itself.
  const void* self = nullptr;
  size_t self_size = 0;
  GetPointerAndSize(&self, &self_size);
  DCHECK(::common::IsAligned(self, kShadowRatio));
  DCHECK(::common::IsAligned(self_size, kShadowRatio));
  Unpoison(self, self_size);

  // Unpoison the shadow memory.
  Unpoison(shadow_, length_);
  // Unpoison the first 64k of the memory.
  Unpoison(0, kAddressLowerBound);
  // Unpoison the protection bits array.
  Unpoison(page_bits_.data(), page_bits_.size());
}

bool Shadow::IsClean() const {
  const size_t innac_end = kAddressLowerBound >> kShadowRatioLog;

  const size_t shadow_begin =
      reinterpret_cast<uintptr_t>(shadow_) >> kShadowRatioLog;
  const size_t shadow_end =
      reinterpret_cast<uintptr_t>(shadow_ + length_) >> kShadowRatioLog;

  const size_t page_bits_begin =
      reinterpret_cast<uintptr_t>(page_bits_.data()) >> kShadowRatioLog;
  const size_t page_bits_end =
      reinterpret_cast<uintptr_t>(page_bits_.data() + page_bits_.size()) >>
          kShadowRatioLog;

  void const* self = nullptr;
  size_t self_size = 0;
  GetPointerAndSize(&self, &self_size);
  const size_t this_begin =
      reinterpret_cast<uintptr_t>(self) >> kShadowRatioLog;
  const size_t this_end =
      (reinterpret_cast<uintptr_t>(self) + self_size + kShadowRatio - 1) >>
          kShadowRatioLog;

  size_t i = 0;
  for (; i < innac_end; ++i) {
    if (shadow_[i] != kInvalidAddressMarker)
      return false;
  }

  for (; i < length_; ++i) {
    if ((i >= shadow_begin && i < shadow_end) ||
        (i >= page_bits_begin && i < page_bits_end) ||
        (i >= this_begin && i < this_end)) {
      if (shadow_[i] != kAsanMemoryMarker)
        return false;
    } else {
      if (shadow_[i] != kHeapAddressableMarker)
        return false;
    }
  }

  return true;
}

void Shadow::SetShadowMemory(const void* address,
                             size_t length,
                             ShadowMarker marker) {
  // Default implementation does absolutely nothing.
  return;
}

void Shadow::GetPointerAndSize(void const** self, size_t* size) const {
  DCHECK_NE(static_cast<void**>(nullptr), self);
  DCHECK_NE(static_cast<size_t*>(nullptr), size);
  GetPointerAndSizeImpl(self, size);
  const uint8_t* begin = ::common::AlignDown(
      reinterpret_cast<const uint8_t*>(*self), kShadowRatio);
  const uint8_t* end = ::common::AlignUp(
      reinterpret_cast<const uint8_t*>(*self) + *size, kShadowRatio);
  *self = begin;
  *size = end - begin;
}

void Shadow::GetPointerAndSizeImpl(void const** self, size_t* size) const {
  DCHECK_NE(static_cast<void**>(nullptr), self);
  DCHECK_NE(static_cast<size_t*>(nullptr), size);
  *self = this;
  *size = sizeof(*this);
}

void Shadow::Init(size_t length) {
  DCHECK_LT(0u, length);

  // The allocation may fail and it needs to be handled gracefully.
  void* mem = ::VirtualAlloc(nullptr, length, MEM_COMMIT, PAGE_READWRITE);
  Init(true, mem, length);
}

void Shadow::Init(bool own_memory, void* shadow, size_t length) {
  // Handle the case of a failed allocation.
  if (shadow == nullptr) {
    own_memory_ = false;
    shadow_ = nullptr;
    length = 0;
    return;
  }

  DCHECK_LT(0u, length);
  DCHECK(::common::IsAligned(shadow, kShadowRatio));

  own_memory_ = own_memory;
  shadow_ = reinterpret_cast<uint8_t*>(shadow);
  length_ = length;

  // Initialize the page bits array.
  uint64_t memory_size = static_cast<uint64_t>(length) << kShadowRatioLog;
  DCHECK_EQ(0u, memory_size % kPageSize);
  size_t page_count = memory_size / kPageSize;
  size_t page_bytes = page_count / 8;
  page_bits_.resize(page_bytes);

  // Zero the memory.
  Reset();
}

void Shadow::Reset() {
  ::memset(shadow_, 0, length_);
  ::memset(page_bits_.data(), 0, page_bits_.size());

  SetShadowMemory(0, kShadowRatio * length_, kHeapAddressableMarker);
}

void Shadow::Poison(const void* addr, size_t size, ShadowMarker shadow_val) {
  uintptr_t index = reinterpret_cast<uintptr_t>(addr);
  uintptr_t start = index & (kShadowRatio - 1);
  DCHECK_EQ(0U, (index + size) & (kShadowRatio - 1));

  SetShadowMemory(addr, size, shadow_val);

  index >>= kShadowRatioLog;
  if (start)
    shadow_[index++] = start;

  size >>= kShadowRatioLog;
  DCHECK_GT(length_, index + size);
  ::memset(shadow_ + index, shadow_val, size);
}

void Shadow::Unpoison(const void* addr, size_t size) {
  uintptr_t index = reinterpret_cast<uintptr_t>(addr);
  DCHECK_EQ(0u, index & (kShadowRatio - 1));

  SetShadowMemory(addr, size, kHeapAddressableMarker);

  uint8_t remainder = size & (kShadowRatio - 1);
  index >>= kShadowRatioLog;
  size >>= kShadowRatioLog;
  DCHECK_GT(length_, index + size);
  ::memset(shadow_ + index, kHeapAddressableMarker, size);

  if (remainder != 0)
    shadow_[index + size] = remainder;
}

namespace {

// An array of kFreedMarkers. This is used for constructing uint16_t, uint32_t
// and
// uint64_t byte variants of kHeapFreedMarker.
static const uint8_t kFreedMarkers[] = {kHeapFreedMarker,
                                        kHeapFreedMarker,
                                        kHeapFreedMarker,
                                        kHeapFreedMarker,
                                        kHeapFreedMarker,
                                        kHeapFreedMarker,
                                        kHeapFreedMarker,
                                        kHeapFreedMarker};
static_assert(sizeof(kFreedMarkers) == sizeof(uint64_t),
              "Wrong number of freed markers.");
static const uint64_t& kFreedMarker64 =
    *reinterpret_cast<const uint64_t*>(kFreedMarkers);
static const uint32_t& kFreedMarker32 =
    *reinterpret_cast<const uint32_t*>(kFreedMarkers);
static const uint16_t& kFreedMarker16 =
    *reinterpret_cast<const uint16_t*>(kFreedMarkers);
static const uint8_t& kFreedMarker8 =
    *reinterpret_cast<const uint8_t*>(kFreedMarkers);

// Marks the given range of shadow bytes as freed, preserving left and right
// redzone bytes.
inline void MarkAsFreedImpl8(uint8_t* cursor, uint8_t* cursor_end) {
  for (; cursor != cursor_end; ++cursor) {
    // Preserve block beginnings/ends/redzones as they were originally.
    // This is necessary to preserve information about nested blocks.
    if (ShadowMarkerHelper::IsActiveLeftRedzone(*cursor) ||
        ShadowMarkerHelper::IsActiveRightRedzone(*cursor)) {
      continue;
    }

    // Anything else gets marked as freed.
    *cursor = kHeapFreedMarker;
  }
}

// Marks the given range of shadow bytes as freed, preserving left and right
// redzone bytes. |cursor| and |cursor_end| must be 8-byte aligned.
inline void MarkAsFreedImplAligned64(uint64_t* cursor, uint64_t* cursor_end) {
  DCHECK(::common::IsAligned(cursor, sizeof(uint64_t)));
  DCHECK(::common::IsAligned(cursor_end, sizeof(uint64_t)));

  for (; cursor != cursor_end; ++cursor) {
    // If the block of shadow memory is entirely green then mark as freed.
    // Otherwise go check its contents byte by byte.
    if (*cursor == 0) {
      *cursor = kFreedMarker64;
    } else {
      MarkAsFreedImpl8(reinterpret_cast<uint8_t*>(cursor),
                       reinterpret_cast<uint8_t*>(cursor + 1));
    }
  }
}

inline void MarkAsFreedImpl64(uint8_t* cursor, uint8_t* cursor_end) {
  if (cursor_end - cursor >= 2 * sizeof(uint64_t)) {
    uint8_t* cursor_aligned = ::common::AlignUp(cursor, sizeof(uint64_t));
    uint8_t* cursor_end_aligned =
        ::common::AlignDown(cursor_end, sizeof(uint64_t));
    MarkAsFreedImpl8(cursor, cursor_aligned);
    MarkAsFreedImplAligned64(reinterpret_cast<uint64_t*>(cursor_aligned),
                             reinterpret_cast<uint64_t*>(cursor_end_aligned));
    MarkAsFreedImpl8(cursor_end_aligned, cursor_end);
  } else {
    MarkAsFreedImpl8(cursor, cursor_end);
  }
}

}  // namespace

void Shadow::MarkAsFreed(const void* addr, size_t size) {
  DCHECK_LE(kAddressLowerBound, reinterpret_cast<uintptr_t>(addr));
  DCHECK(::common::IsAligned(addr, kShadowRatio));

  SetShadowMemory(addr, size, kHeapFreedMarker);

  size_t index = reinterpret_cast<uintptr_t>(addr) / kShadowRatio;
  size_t length = (size + kShadowRatio - 1) / kShadowRatio;
  DCHECK_LE(index, length_);
  DCHECK_LE(index + length, length_);

  uint8_t* cursor = shadow_ + index;
  uint8_t* cursor_end = static_cast<uint8_t*>(cursor) + length;

  // This isn't as simple as a memset because we need to preserve left and
  // right redzone padding bytes that may be found in the range.
  MarkAsFreedImpl64(cursor, cursor_end);
}

bool Shadow::IsAccessible(const void* addr) const {
  uintptr_t index = reinterpret_cast<uintptr_t>(addr);
  uintptr_t start = index & 0x7;

  index >>= kShadowRatioLog;
  if (index > length_)
    return false;

  DCHECK_GT(length_, index);
  uint8_t shadow = shadow_[index];
  if (shadow == 0)
    return true;

  if (ShadowMarkerHelper::IsRedzone(shadow))
    return false;

  return start < shadow;
}

bool Shadow::IsRangeAccessible(const void* addr, size_t size) const {
  DCHECK_NE(static_cast<const void*>(nullptr), addr);

  // A zero byte access is always valid.
  if (size == 0U)
    return true;

  uintptr_t start_addr = reinterpret_cast<uintptr_t>(addr);
  uintptr_t start = start_addr;
  start >>= kShadowRatioLog;

  DCHECK_EQ(reinterpret_cast<uintptr_t>(addr),
            (start << kShadowRatioLog) + (start_addr & (kShadowRatio - 1)));
  if (start > length_)
    return false;

  // Validate that the start point is accessible.
  uint8_t shadow = shadow_[start];
  if (shadow != 0U) {
    if (ShadowMarkerHelper::IsRedzone(shadow))
      return false;
    if (start < shadow)
      return false;
  }

  uintptr_t end = reinterpret_cast<uintptr_t>(addr) + size;
  // Overflow on addr + size.
  if (start_addr > end)
    return false;

  size_t end_offs = end & (kShadowRatio - 1);
  end >>= kShadowRatioLog;
  if (end > length_)
    return false;

  // Now run over the shadow bytes from start to end, which all need to be
  // zero.
  // TODO(siggi): Optimize this loop to minimize the number of memory acesses.
  for (size_t i = start; i < end; ++i) {
    if (shadow_[i] != 0U)
      return false;
  }

  // Finally test the end point if there's a tail offset.
  if (end_offs == 0U)
    return true;

  shadow = shadow_[end];
  if (shadow == 0U)
    return true;

  if (ShadowMarkerHelper::IsRedzone(shadow))
    return false;
  if (end_offs > shadow)
    return false;

  return true;
}

bool Shadow::IsLeftRedzone(const void* address) const {
  return ShadowMarkerHelper::IsActiveLeftRedzone(
      GetShadowMarkerForAddress(address));
}

bool Shadow::IsRightRedzone(const void* address) const {
  uintptr_t index = reinterpret_cast<uintptr_t>(address);
  uintptr_t start = index & 0x7;

  index >>= kShadowRatioLog;

  DCHECK_GT(length_, index);
  uint8_t marker = shadow_[index];

  // If the marker is for accessible memory then some addresses may be part
  // of a right redzone, assuming that the *next* marker in the shadow is for
  // a right redzone.
  if (marker == 0)
    return false;
  if (marker <= kHeapPartiallyAddressableByte7) {
    if (index == length_)
      return false;
    if (!ShadowMarkerHelper::IsActiveRightRedzone(shadow_[index + 1]))
      return false;
    return start >= marker;
  }

  // Otherwise, check the marker directly.
  return ShadowMarkerHelper::IsActiveRightRedzone(marker);
}

bool Shadow::IsBlockStartByte(const void* address) const {
  uintptr_t index = reinterpret_cast<uintptr_t>(address);
  uintptr_t start = index & 0x7;

  index >>= kShadowRatioLog;

  DCHECK_GT(length_, index);
  uint8_t marker = shadow_[index];

  if (start != 0)
    return false;
  if (!ShadowMarkerHelper::IsActiveBlockStart(marker))
    return false;

  return true;
}

const uint8_t* Shadow::GetShadowMemoryForAddress(const void* addr) const {
  uintptr_t index = reinterpret_cast<uintptr_t>(addr);
  index >>= kShadowRatioLog;
  DCHECK_GE(length_, index);
  return shadow_ + index;
}

ShadowMarker Shadow::GetShadowMarkerForAddress(const void* addr) const {
  return static_cast<ShadowMarker>(*GetShadowMemoryForAddress(addr));
}

void Shadow::PoisonAllocatedBlock(const BlockInfo& info) {
  static_assert((sizeof(BlockHeader) % kShadowRatio) == 0, "Bad header size.");
  DCHECK(info.header->state == ALLOCATED_BLOCK);

  // Translate the block address to an offset. Sanity check a whole bunch
  // of things that we require to be true for the shadow to have 100%
  // fidelity.
  uintptr_t index = reinterpret_cast<uintptr_t>(info.header);
  DCHECK(::common::IsAligned(index, kShadowRatio));
  DCHECK(::common::IsAligned(info.header_padding_size, kShadowRatio));
  DCHECK(::common::IsAligned(info.block_size, kShadowRatio));
  index /= kShadowRatio;

  // Determine the distribution of bytes in the shadow.
  size_t left_redzone_bytes = info.TotalHeaderSize() / kShadowRatio;
  size_t body_bytes = (info.body_size + kShadowRatio - 1) / kShadowRatio;
  size_t block_bytes = info.block_size / kShadowRatio;
  size_t right_redzone_bytes = block_bytes - left_redzone_bytes - body_bytes;

  // Determine the marker byte for the header. This encodes the length of the
  // body of the allocation modulo the shadow ratio, so that the exact length
  // can be inferred from inspecting the shadow memory.
  uint8_t body_size_mod = info.body_size % kShadowRatio;
  uint8_t header_marker = ShadowMarkerHelper::BuildBlockStart(
      true, info.header->is_nested, body_size_mod);

  // Determine the marker byte for the trailer.
  uint8_t trailer_marker =
      ShadowMarkerHelper::BuildBlockEnd(true, info.header->is_nested);

  // Poison the header and left padding.
  uint8_t* cursor = shadow_ + index;
  ::memset(cursor, header_marker, 1);
  ::memset(cursor + 1, kHeapLeftPaddingMarker, left_redzone_bytes - 1);
  cursor += left_redzone_bytes;
  ::memset(cursor, kHeapAddressableMarker, body_bytes);
  cursor += body_bytes;

  // Poison the right padding and the trailer.
  if (body_size_mod > 0)
    cursor[-1] = body_size_mod;
  ::memset(cursor, kHeapRightPaddingMarker, right_redzone_bytes - 1);
  ::memset(cursor + right_redzone_bytes - 1, trailer_marker, 1);

  SetShadowMemory(info.header,
                  info.TotalHeaderSize(),
                  kHeapLeftPaddingMarker);
  SetShadowMemory(info.body, info.body_size, kHeapAddressableMarker);
  SetShadowMemory(info.trailer_padding,
                  info.TotalTrailerSize(),
                  kHeapRightPaddingMarker);
}

bool Shadow::BlockIsNested(const BlockInfo& info) const {
  uint8_t marker = GetShadowMarkerForAddress(info.header);
  DCHECK(ShadowMarkerHelper::IsActiveBlockStart(marker));
  return ShadowMarkerHelper::IsNestedBlockStart(marker);
}

bool Shadow::BlockInfoFromShadow(
    const void* addr, CompactBlockInfo* info) const {
  DCHECK_NE(static_cast<void*>(NULL), addr);
  DCHECK_NE(static_cast<CompactBlockInfo*>(NULL), info);
  if (!BlockInfoFromShadowImpl(0, addr, info))
    return false;
  return true;
}

bool Shadow::BlockInfoFromShadow(const void* addr, BlockInfo* info) const {
  DCHECK_NE(static_cast<void*>(NULL), addr);
  DCHECK_NE(static_cast<BlockInfo*>(NULL), info);
  CompactBlockInfo compact = {};
  if (!BlockInfoFromShadow(addr, &compact))
    return false;
  ConvertBlockInfo(compact, info);
  return true;
}

bool Shadow::ParentBlockInfoFromShadow(const BlockInfo& nested,
                                       BlockInfo* info) const {
  DCHECK_NE(static_cast<BlockInfo*>(NULL), info);
  if (!BlockIsNested(nested))
    return false;
  CompactBlockInfo compact = {};
  if (!BlockInfoFromShadowImpl(1, nested.header, &compact))
    return false;
  ConvertBlockInfo(compact, info);
  return true;
}

bool Shadow::IsBeginningOfBlockBody(const void* addr) const {
  DCHECK_NE(static_cast<void*>(NULL), addr);
  // If the block has a non-zero body size then the beginning of the body will
  // be accessible or tagged as freed.
  // If the block has an empty body then the beginning of the body will be a
  // right redzone.
  if (IsAccessible(addr) || IsRightRedzone(addr) ||
      GetShadowMarkerForAddress(addr) == kHeapFreedMarker) {
    return IsLeftRedzone(reinterpret_cast<const uint8_t*>(addr) - 1);
  }
  return false;
}

bool Shadow::PageIsProtected(const void* addr) const {
  // Since the page bit is read very frequently this is not performed
  // under a lock. The values change quite rarely, so this will almost always
  // be correct. However, consumers of this knowledge have to be robust to
  // getting incorrect data.
  size_t index = 0;
  uint8_t mask = 0;
  AddressToPageMask(addr, &index, &mask);
  return (page_bits_[index] & mask) == mask;
}

void Shadow::MarkPageProtected(const void* addr) {
  size_t index = 0;
  uint8_t mask = 0;
  AddressToPageMask(addr, &index, &mask);

  base::AutoLock lock(page_bits_lock_);
  page_bits_[index] |= mask;
}

void Shadow::MarkPageUnprotected(const void* addr) {
  size_t index = 0;
  uint8_t mask = 0;
  AddressToPageMask(addr, &index, &mask);
  mask = ~mask;

  base::AutoLock lock(page_bits_lock_);
  page_bits_[index] &= mask;
}

void Shadow::MarkPagesProtected(const void* addr, size_t size) {
  const uint8_t* page = reinterpret_cast<const uint8_t*>(addr);
  const uint8_t* page_end = page + size;
  size_t index = 0;
  uint8_t mask = 0;

  base::AutoLock lock(page_bits_lock_);
  while (page < page_end) {
    AddressToPageMask(page, &index, &mask);
    page_bits_[index] |= mask;
    page += kPageSize;
  }
}

void Shadow::MarkPagesUnprotected(const void* addr, size_t size) {
  const uint8_t* page = reinterpret_cast<const uint8_t*>(addr);
  const uint8_t* page_end = page + size;
  size_t index = 0;
  uint8_t mask = 0;

  base::AutoLock lock(page_bits_lock_);
  while (page < page_end) {
    AddressToPageMask(page, &index, &mask);
    page_bits_[index] &= ~mask;
    page += kPageSize;
  }
}

void Shadow::AppendShadowByteText(const char *prefix,
                                  uintptr_t index,
                                  std::string* output,
                                  size_t bug_index) const {
  base::StringAppendF(
      output,
      "%s0x%08x:",
      prefix,
      reinterpret_cast<void*>(index << kShadowRatioLog));
  char separator = ' ';
  for (uint32_t i = 0; i < kShadowBytesPerLine; i++) {
    if (index + i == bug_index)
      separator = '[';
    uint8_t shadow_value = shadow_[index + i];
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

void Shadow::AppendShadowArrayText(
    const void* addr, std::string* output) const {
  uintptr_t index = reinterpret_cast<uintptr_t>(addr);
  index >>= kShadowRatioLog;
  size_t index_start = index;
  index_start /= kShadowBytesPerLine;
  index_start *= kShadowBytesPerLine;
  for (int i = -static_cast<int>(kShadowContextLines);
       i <= static_cast<int>(kShadowContextLines); i++) {
    const char * const prefix = (i == 0) ? "=>" : "  ";
    AppendShadowByteText(
        prefix, (index_start + i * kShadowBytesPerLine), output, index);
  }
}

void Shadow::AppendShadowMemoryText(
    const void* addr, std::string* output) const {
  base::StringAppendF(output, "Shadow bytes around the buggy address:\n");
  AppendShadowArrayText(addr, output);
  base::StringAppendF(output, "Shadow byte legend (one shadow byte represents "
                              "8 application bytes):\n");
  base::StringAppendF(output, "  Addressable:           00\n");
  base::StringAppendF(output, "  Partially addressable: 01 - 07\n");
  base::StringAppendF(output, "  Block start redzone:   %02x - %02x\n",
                      kHeapBlockStartMarker0, kHeapBlockStartMarker7);
  base::StringAppendF(output, "  Nested block start:    %02x - %02x\n",
                      kHeapNestedBlockStartMarker0,
                      kHeapNestedBlockStartMarker7);
  base::StringAppendF(output, "  Asan memory byte:      %02x\n",
                      kAsanMemoryMarker);
  base::StringAppendF(output, "  Invalid address:       %02x\n",
                      kInvalidAddressMarker);
  base::StringAppendF(output, "  User redzone:          %02x\n",
                      kUserRedzoneMarker);
  base::StringAppendF(output, "  Block end redzone:     %02x\n",
                      kHeapBlockEndMarker);
  base::StringAppendF(output, "  Nested block end:      %02x\n",
                      kHeapNestedBlockEndMarker);
  base::StringAppendF(output, "  Heap left redzone:     %02x\n",
                      kHeapLeftPaddingMarker);
  base::StringAppendF(output, "  Heap right redzone:    %02x\n",
                      kHeapRightPaddingMarker);
  base::StringAppendF(output, "  Asan reserved byte:    %02x\n",
                      kAsanReservedMarker);
  base::StringAppendF(output, "  Freed heap region:     %02x\n",
                      kHeapFreedMarker);
}

size_t Shadow::GetAllocSize(const uint8_t* mem) const {
  BlockInfo block_info = {};
  if (!Shadow::BlockInfoFromShadow(mem, &block_info))
    return 0;
  return block_info.block_size;
}

bool Shadow::ScanLeftForBracketingBlockStart(
    size_t initial_nesting_depth, size_t cursor, size_t* location) const {
  DCHECK_NE(static_cast<size_t*>(NULL), location);

  static const size_t kLowerBound = kAddressLowerBound / kShadowRatio;

  size_t left = cursor;
  int nesting_depth = static_cast<int>(initial_nesting_depth);
  if (ShadowMarkerHelper::IsBlockEnd(shadow_[left]))
    --nesting_depth;
  while (true) {
    if (ShadowMarkerHelper::IsBlockStart(shadow_[left])) {
      if (nesting_depth == 0) {
        *location = left;
        return true;
      }
      // If this is not a nested block then there's no hope of finding a
      // block containing the original cursor.
      if (!ShadowMarkerHelper::IsNestedBlockStart(shadow_[left]))
        return false;
      --nesting_depth;
    } else if (ShadowMarkerHelper::IsBlockEnd(shadow_[left])) {
      ++nesting_depth;

      // If we encounter the end of a non-nested block there's no way for
      // a block to bracket us.
      if (nesting_depth > 0 &&
          !ShadowMarkerHelper::IsNestedBlockEnd(shadow_[left])) {
        return false;
      }
    }
    if (left <= kLowerBound)
      return false;
    --left;
  }

  NOTREACHED();
}

namespace {

// This handles an unaligned input cursor. It can potentially read up to 7
// bytes past the end of the cursor, but only up to an 8 byte boundary. Thus
// this out of bounds access is safe.
inline const uint8_t* ScanRightForPotentialHeaderBytes(const uint8_t* pos,
                                                       const uint8_t* end) {
  DCHECK(::common::IsAligned(end, 8));

  // Handle the first few bytes that aren't aligned. If pos == end then
  // it is already 8-byte aligned and we'll simply fall through to the end.
  // This is a kind of Duffy's device that takes bytes 'as large as possible'
  // until we reach an 8 byte alignment.
  switch (reinterpret_cast<uintptr_t>(pos) & 0x7) {
    case 1:
      if (*pos != 0 && *pos != kFreedMarker8)
        return pos;
      pos += 1;
    case 2:
      if (*reinterpret_cast<const uint16_t*>(pos) != 0 &&
          *reinterpret_cast<const uint16_t*>(pos) != kFreedMarker16) {
        return pos;
      }
      pos += 2;
    case 4:
      if (*reinterpret_cast<const uint32_t*>(pos) != 0 &&
          *reinterpret_cast<const uint32_t*>(pos) != kFreedMarker32) {
        return pos;
      }
      pos += 4;
      break;

    case 3:
      if (*pos != 0 && *pos != kFreedMarker8)
        return pos;
      pos += 1;
      // Now have alignment of 4.
      if (*reinterpret_cast<const uint32_t*>(pos) != 0 &&
          *reinterpret_cast<const uint32_t*>(pos) != kFreedMarker32) {
        return pos;
      }
      pos += 4;
      break;

    case 5:
      if (*pos != 0 && *pos != kFreedMarker8)
        return pos;
      pos += 1;
    case 6:
      if (*reinterpret_cast<const uint16_t*>(pos) != 0 &&
          *reinterpret_cast<const uint16_t*>(pos) != kFreedMarker16) {
        return pos;
      }
      pos += 2;
      break;

    case 7:
      if (*pos != 0 && *pos != kFreedMarker8)
        return pos;
      pos += 1;

    case 0:
    default:
      // Do nothing, as we're already 8 byte aligned.
      break;
  }

  // Handle the 8-byte aligned bytes as much as we can.
  while (pos < end) {
    if (*reinterpret_cast<const uint64_t*>(pos) != 0 &&
        *reinterpret_cast<const uint64_t*>(pos) != kFreedMarker64) {
      return pos;
    }
    pos += 8;
  }

  return pos;
}

}  // namespace

bool Shadow::ScanRightForBracketingBlockEnd(
    size_t initial_nesting_depth, size_t cursor, size_t* location) const {
  DCHECK_NE(static_cast<size_t*>(NULL), location);

  const uint8_t* shadow_end = shadow_ + length_;
  const uint8_t* pos = shadow_ + cursor;
  int nesting_depth = static_cast<int>(initial_nesting_depth);
  if (ShadowMarkerHelper::IsBlockStart(*pos))
    --nesting_depth;
  while (pos < shadow_end) {
    // Skips past as many addressable and freed bytes as possible.
    pos = ScanRightForPotentialHeaderBytes(pos, shadow_end);
    if (pos == shadow_end)
      return false;

    // When the above loop exits early then somewhere in the next 8 bytes
    // there's non-addressable data that isn't 'freed'. Look byte by byte to
    // see what's up.

    if (ShadowMarkerHelper::IsBlockEnd(*pos)) {
      if (nesting_depth == 0) {
        *location = pos - shadow_;
        return true;
      }
      if (!ShadowMarkerHelper::IsNestedBlockEnd(*pos))
        return false;
      --nesting_depth;
    } else if (ShadowMarkerHelper::IsBlockStart(*pos)) {
      ++nesting_depth;

      // If we encounter the beginning of a non-nested block then there's
      // clearly no way for any block to bracket us.
      if (nesting_depth > 0 &&
          !ShadowMarkerHelper::IsNestedBlockStart(*pos)) {
        return false;
      }
    }
    ++pos;
  }
  return false;
}

bool Shadow::BlockInfoFromShadowImpl(
    size_t initial_nesting_depth,
    const void* addr,
    CompactBlockInfo* info) const {
  DCHECK_NE(static_cast<void*>(NULL), addr);
  DCHECK_NE(static_cast<CompactBlockInfo*>(NULL), info);

  // Convert the address to an offset in the shadow memory.
  size_t left = reinterpret_cast<uintptr_t>(addr) / kShadowRatio;
  size_t right = left;

  if (!ScanLeftForBracketingBlockStart(initial_nesting_depth, left, &left))
    return false;
  if (!ScanRightForBracketingBlockEnd(initial_nesting_depth, right, &right))
    return false;
  ++right;

  uint8_t* block = reinterpret_cast<uint8_t*>(left * kShadowRatio);
  info->header = reinterpret_cast<BlockHeader*>(block);
  info->block_size = (right - left) * kShadowRatio;

  // Get the length of the body modulo the shadow ratio.
  size_t body_size_mod = ShadowMarkerHelper::GetBlockStartData(shadow_[left]);
  info->is_nested = ShadowMarkerHelper::IsNestedBlockStart(shadow_[left]);

  // Find the beginning of the body (end of the left redzone).
  ++left;
  while (left < right && shadow_[left] == kHeapLeftPaddingMarker)
    ++left;

  // Find the beginning of the right redzone (end of the body).
  --right;
  while (right > left && shadow_[right - 1] == kHeapRightPaddingMarker)
    --right;

  // Calculate the body location and size.
  uint8_t* body = reinterpret_cast<uint8_t*>(left * kShadowRatio);
  size_t body_size = (right - left) * kShadowRatio;
  if (body_size_mod > 0) {
    DCHECK_LE(8u, body_size);
    body_size = body_size - kShadowRatio + body_size_mod;
  }

  // Fill out header and trailer sizes.
  info->header_size = body - block;
  info->trailer_size = info->block_size - body_size - info->header_size;

  return true;
}

ShadowWalker::ShadowWalker(const Shadow* shadow,
                           bool recursive,
                           const void* lower_bound,
                           const void* upper_bound)
    : shadow_(shadow), recursive_(recursive), lower_bound_(0), upper_bound_(0),
      cursor_(nullptr), shadow_cursor_(nullptr), nesting_depth_(0) {
  DCHECK_NE(static_cast<Shadow*>(nullptr), shadow);
  DCHECK_LE(Shadow::kAddressLowerBound, reinterpret_cast<size_t>(lower_bound));
  DCHECK_GE(shadow->memory_size(), reinterpret_cast<size_t>(upper_bound));
  DCHECK_LE(lower_bound, upper_bound);

  lower_bound_ = ::common::AlignDown(
      reinterpret_cast<const uint8_t*>(lower_bound), kShadowRatio);
  upper_bound_ = ::common::AlignUp(
      reinterpret_cast<const uint8_t*>(upper_bound), kShadowRatio);
  Reset();
}

void ShadowWalker::Reset() {
  // Walk to the beginning of the first non-nested block, or to the end
  // of the range, whichever comes first.
  nesting_depth_ = -1;
  for (cursor_ = lower_bound_; cursor_ != upper_bound_;
       cursor_ += kShadowRatio) {
    uint8_t marker = shadow_->GetShadowMarkerForAddress(cursor_);
    if (ShadowMarkerHelper::IsBlockStart(marker) &&
        !ShadowMarkerHelper::IsNestedBlockStart(marker)) {
      break;
    }
  }

  shadow_cursor_ = shadow_->GetShadowMemoryForAddress(cursor_);
}

bool ShadowWalker::Next(BlockInfo* info) {
  DCHECK_NE(static_cast<BlockInfo*>(NULL), info);

  // Iterate until a reportable block is encountered, or the slab is exhausted.
  for (; cursor_ != upper_bound_; cursor_ += kShadowRatio) {
    uint8_t marker = shadow_->GetShadowMarkerForAddress(cursor_);

    // Update the nesting depth when block end markers are encountered.
    if (ShadowMarkerHelper::IsBlockEnd(marker)) {
      DCHECK_LE(0, nesting_depth_);
      --nesting_depth_;
      continue;
    }

    // Look for a block start marker.
    if (ShadowMarkerHelper::IsBlockStart(marker)) {
      // Update the nesting depth when block start bytes are encountered.
      ++nesting_depth_;

      // Non-nested blocks should only be encountered at depth 0.
      bool is_nested = ShadowMarkerHelper::IsNestedBlockStart(marker);
      DCHECK(is_nested || nesting_depth_ == 0);

      // Determine if the block is to be reported.
      if (!is_nested || recursive_) {
        // This can only fail if the shadow memory is malformed.
        CHECK(shadow_->BlockInfoFromShadow(cursor_, info));

        // In a recursive descent we have to process body contents.
        if (recursive_) {
          cursor_ += kShadowRatio;
        } else {
          // Otherwise we can skip the body of the block we just reported.
          // We skip directly to the end marker (but not past it so that depth
          // bookkeeping works properly).
          cursor_ += info->block_size - kShadowRatio;
        }

        shadow_cursor_ = shadow_->GetShadowMemoryForAddress(cursor_);
        return true;
      }
      continue;
    }
  }

  return false;
}

}  // namespace asan
}  // namespace agent
