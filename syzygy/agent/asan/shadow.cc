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

#include "base/stringprintf.h"
#include "syzygy/common/align.h"

namespace agent {
namespace asan {


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

bool Shadow::IsBlockStartByteMarker(uint8 marker) {
  return marker >= kHeapBlockStartByte0 && marker <= kHeapBlockStartByte7;
}

bool Shadow::IsBlockStartByte(const void* addr) {
  Shadow::ShadowMarker marker = Shadow::GetShadowMarkerForAddress(addr);
  if (IsBlockStartByteMarker(marker))
    return true;
  return false;
}

bool Shadow::IsLeftRedzone(const void* addr) {
  Shadow::ShadowMarker marker = Shadow::GetShadowMarkerForAddress(addr);
  if (marker == kHeapLeftRedzone || IsBlockStartByteMarker(marker))
    return true;
  return false;
}

bool Shadow::IsRightRedzone(const void* addr) {
  Shadow::ShadowMarker marker = Shadow::GetShadowMarkerForAddress(addr);
  if (marker == kHeapRightRedzone || marker == kHeapBlockEndByte)
    return true;
  return false;
}

void Shadow::PoisonAllocatedBlock(const BlockInfo& info) {
  COMPILE_ASSERT((sizeof(BlockHeader) % kShadowRatio) == 0, bad_header_size);

  // Translate the block address to an offset. Sanity check a whole bunch
  // of things that we require to be true for the shadow to have 100%
  // fidelity.
  uintptr_t index = reinterpret_cast<uintptr_t>(info.block);
  DCHECK(common::IsAligned(index, kShadowRatio));
  DCHECK(common::IsAligned(info.header_padding_size, kShadowRatio));
  DCHECK(common::IsAligned(info.block_size, kShadowRatio));
  index /= kShadowRatio;

  // Determine the distribution of bytes in the shadow.
  size_t left_redzone_bytes = (info.body - info.block) / kShadowRatio;
  size_t body_bytes = (info.body_size + kShadowRatio - 1) / kShadowRatio;
  size_t block_bytes = info.block_size / kShadowRatio;
  size_t right_redzone_bytes = block_bytes - left_redzone_bytes - body_bytes;

  // Determine the marker byte for the header. This encodes the length of the
  // body of the allocation modulo the shadow ratio, so that the exact length
  // can be inferred from inspecting the shadow memory.
  uint8 body_size_mod = info.body_size % kShadowRatio;
  uint8 header_marker = Shadow::kHeapBlockStartByte0 | body_size_mod;

  // Poison the header and left redzone.
  uint8* cursor = shadow_ + index;
  ::memset(cursor, header_marker, 1);
  ::memset(cursor + 1, kHeapLeftRedzone, left_redzone_bytes - 1);
  cursor += left_redzone_bytes;
  cursor += body_bytes;

  // Poison the right redzone and the trailer.
  if (body_size_mod > 0)
    cursor[-1] = body_size_mod;
  ::memset(cursor, kHeapRightRedzone, right_redzone_bytes - 1);
  ::memset(cursor + right_redzone_bytes - 1, kHeapBlockEndByte, 1);
}

bool Shadow::BlockInfoFromShadow(const void* addr, BlockInfo* info) {
  DCHECK_NE(static_cast<void*>(NULL), addr);
  DCHECK_NE(static_cast<BlockInfo*>(NULL), info);

  static const size_t kLowerBound = kAddressLowerBound / kShadowRatio;

  // Convert the address to an offset in the shadow memory.
  size_t left = reinterpret_cast<uintptr_t>(addr) / kShadowRatio;
  size_t right = left;

  // Scan left until we find a header. We support nested blocks by looking
  // for a header that is balanced with respect to trailers.
  int nesting_depth = 0;
  if (shadow_[left] == kHeapBlockEndByte)
    --nesting_depth;
  while (true) {
    if (IsBlockStartByteMarker(shadow_[left])) {
      if (nesting_depth == 0)
        break;
      --nesting_depth;
    } else if (shadow_[left] == kHeapBlockEndByte) {
      ++nesting_depth;
    }
    if (left <= kLowerBound)
      return false;
    --left;
  }
  if (nesting_depth != 0 && !IsBlockStartByteMarker(shadow_[left]))
    return false;

  // Scan right until we find a (balanced) trailer.
  DCHECK_EQ(0, nesting_depth);
  if (IsBlockStartByteMarker(shadow_[right]))
    --nesting_depth;
  while (true) {
    if (shadow_[right] == kHeapBlockEndByte) {
      if (nesting_depth == 0)
        break;
      --nesting_depth;
    } else if (IsBlockStartByteMarker(shadow_[right])) {
      ++nesting_depth;
    }
    if (right + 1 == kShadowSize)
      return false;
    ++right;
  }
  if (nesting_depth != 0 && shadow_[right] != kHeapBlockEndByte)
    return false;
  ++right;

  // Set up the block, header and trailer pointers.
  info->block = reinterpret_cast<uint8*>(left * kShadowRatio);
  info->block_size = (right - left) * kShadowRatio;
  info->header = reinterpret_cast<BlockHeader*>(info->block);
  info->header_padding = info->block + sizeof(BlockHeader);
  info->trailer = reinterpret_cast<BlockTrailer*>(
      info->block + info->block_size) - 1;

  // Get the length of the body modulo the shadow ratio.
  size_t body_size_mod = shadow_[left] % kShadowRatio;

  // Find the beginning of the body (end of the left redzone).
  ++left;
  while (left < right && shadow_[left] == kHeapLeftRedzone)
    ++left;

  // Find the beginning of the right redzone (end of the body).
  --right;
  while (right > left && shadow_[right - 1] == kHeapRightRedzone)
    --right;

  // Fill out the body and padding sizes.
  info->body = reinterpret_cast<uint8*>(left * kShadowRatio);
  info->body_size = (right - left) * kShadowRatio;
  if (body_size_mod > 0) {
    DCHECK_LE(8u, info->body_size);
    info->body_size = info->body_size - kShadowRatio + body_size_mod;
  }
  info->header_padding_size = info->body - info->header_padding;
  info->trailer_padding = info->body + info->body_size;
  info->trailer_padding_size =
      reinterpret_cast<uint8*>(info->trailer) - info->trailer_padding;

  // Fill out page information.
  BlockIdentifyWholePages(info);

  return true;
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
  base::StringAppendF(output, "Shadow byte legend (one shadow byte represents "
                              "8 application bytes):\n");
  base::StringAppendF(output, "  Addressable:           00\n");
  base::StringAppendF(output, "  Partially addressable: 01 - 07\n");
  base::StringAppendF(output, "  Block start redzone:   %02x - %02x\n",
                      kHeapBlockStartByte0, kHeapBlockStartByte7);
  base::StringAppendF(output, "  ASan memory byte:      %02x\n",
                      kAsanMemoryByte);
  base::StringAppendF(output, "  Invalid address:       %02x\n",
                      kInvalidAddress);
  base::StringAppendF(output, "  User redzone:          %02x\n",
                      kUserRedzone);
  base::StringAppendF(output, "  Block end redzone:     %02x\n",
                      kHeapBlockEndByte);
  base::StringAppendF(output, "  Heap left redzone:     %02x\n",
                      kHeapLeftRedzone);
  base::StringAppendF(output, "  Heap right redzone:    %02x\n",
                      kHeapRightRedzone);
  base::StringAppendF(output, "  ASan reserved byte:    %02x\n",
                      kAsanReservedByte);
  base::StringAppendF(output, "  Freed Heap region:     %02x\n",
                      kHeapFreedByte);
}

const uint8* Shadow::FindBlockBeginning(const uint8* mem) {
  mem = reinterpret_cast<uint8*>(common::AlignDown(
      reinterpret_cast<size_t>(mem), kShadowRatio));
  // Start by checking if |mem| points inside a block.
  if (!IsLeftRedzone(mem) && !IsRightRedzone(mem)) {
    do {
      mem -= kShadowRatio;
    } while (!IsLeftRedzone(mem) && !IsRightRedzone(mem) &&
             mem > reinterpret_cast<uint8*>(kAddressLowerBound));
    // If the shadow marker for |mem| corresponds to a right redzone then this
    // means that its original value was pointing after a block.
    if (IsRightRedzone(mem) ||
        mem <= reinterpret_cast<uint8*>(kAddressLowerBound)) {
      return NULL;
    }
  }

  // Look for the beginning of the memory block.
  while (!IsLeftRedzone(mem) || IsLeftRedzone(mem - kShadowRatio) &&
      mem > reinterpret_cast<uint8*>(kAddressLowerBound)) {
    mem -= kShadowRatio;
  }
  if (mem <= reinterpret_cast<uint8*>(kAddressLowerBound))
    return NULL;

  return mem;
}

size_t Shadow::GetAllocSize(const uint8* mem) {
  size_t alloc_size = 0;
  const uint8* aligned_mem = reinterpret_cast<uint8*>(common::AlignDown(
      reinterpret_cast<size_t>(mem), kShadowRatio));
  size_t alignment_offset = mem - aligned_mem;
  const uint8* mem_begin = FindBlockBeginning(mem);

  if (mem_begin == NULL)
    return 0;

  // Look for the heap right redzone.
  while (!IsRightRedzone(mem) &&
         mem < reinterpret_cast<uint8*>(kAddressUpperBound)) {
    mem += kShadowRatio;
  }

  if (mem >= reinterpret_cast<uint8*>(kAddressUpperBound))
    return 0;

  // Find the end of the block.
  while (IsRightRedzone(mem) &&
         mem < reinterpret_cast<uint8*>(kAddressUpperBound)) {
    mem += kShadowRatio;
  }

  if (mem >= reinterpret_cast<uint8*>(kAddressUpperBound))
    return 0;

  return mem - mem_begin - alignment_offset;
}

const uint8* Shadow::AsanPointerToBlockHeader(const uint8* asan_pointer) {
  if (!IsLeftRedzone(asan_pointer))
    return NULL;
  while (!IsBlockStartByte(asan_pointer))
    asan_pointer += kShadowRatio;
  return asan_pointer;
}

ShadowWalker::ShadowWalker(const uint8* lower_bound, const uint8* upper_bound)
    : lower_bound_(lower_bound), upper_bound_(upper_bound) {
  DCHECK_GE(reinterpret_cast<size_t>(lower_bound), Shadow::kAddressLowerBound);
  DCHECK_LT(reinterpret_cast<size_t>(lower_bound), Shadow::kAddressUpperBound);
  Reset();
}

void ShadowWalker::Reset() {
  next_block_ = lower_bound_;
  // Look for the first block.
  while (next_block_ < upper_bound_ && !Shadow::IsLeftRedzone(next_block_))
    next_block_ += kShadowRatio;
}

void ShadowWalker::Advance() {
  DCHECK_LT(next_block_, upper_bound_);
  // Skip the current block left zone.
  while (next_block_ < upper_bound_ && Shadow::IsLeftRedzone(next_block_))
    next_block_ += kShadowRatio;
  // Look for the next block.
  while (next_block_ < upper_bound_ && !Shadow::IsLeftRedzone(next_block_))
    next_block_ += kShadowRatio;
}

bool ShadowWalker::Next(const uint8** block_begin) {
  DCHECK_NE(reinterpret_cast<const uint8**>(NULL), block_begin);
  *block_begin = next_block_;
  // |upper_bound_| or |next_block_| might have a different alignment, so
  // |next_block_| might be superior to |upper_bound_|.
  if (next_block_ >= upper_bound_)
    return false;
  Advance();
  return true;
}

}  // namespace asan
}  // namespace agent
