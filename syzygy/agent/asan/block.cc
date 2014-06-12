// Copyright 2014 Google Inc. All Rights Reserved.
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

#include "syzygy/agent/asan/block.h"

#include <windows.h>

#include <algorithm>

#include "base/hash.h"
#include "base/logging.h"
#include "syzygy/agent/asan/stack_capture_cache.h"
#include "syzygy/common/align.h"

namespace agent {
namespace asan {

namespace {

using common::IsAligned;

// Declares a function that returns the maximum value representable by
// the given bitfield.
#define DECLARE_GET_MAX_BITFIELD_VALUE_FUNCTION(Type, FieldName)   \
  size_t GetMaxValue ## Type ## _ ## FieldName() {  \
    Type t = {};  \
    t.FieldName = 0;  \
    --t.FieldName;  \
    size_t value = t.FieldName;  \
    return value;  \
  }
DECLARE_GET_MAX_BITFIELD_VALUE_FUNCTION(BlockHeader, body_size);
#undef DECLARE_GET_MAX_BITFIELD_VALUE_FUNCTION

const size_t kMaxBlockHeaderBodySize = GetMaxValueBlockHeader_body_size();

// Gets the page size from the OS.
size_t GetPageSize() {
  SYSTEM_INFO system_info = {};
  ::GetSystemInfo(&system_info);
  return system_info.dwPageSize;
}

// Identifies whole pages in the given block_info.
// TODO(chrisha): This will be useful when walking through blocks using the
//     shadow memory. Expose this somewhere!
void IdentifyWholePages(BlockInfo* block_info) {
  DCHECK_NE(static_cast<BlockInfo*>(NULL), block_info);

  if (block_info->block_size < kPageSize)
    return;

  uint32 alloc_start = reinterpret_cast<uint32>(block_info->block);
  uint32 alloc_end = alloc_start + block_info->block_size;
  alloc_start = common::AlignUp(alloc_start, kPageSize);
  alloc_end = common::AlignDown(alloc_end, kPageSize);
  if (alloc_start >= alloc_end)
    return;

  block_info->block_pages = reinterpret_cast<uint8*>(alloc_start);
  block_info->block_pages_size = alloc_end - alloc_start;

  uint32 left_redzone_end = reinterpret_cast<uint32>(block_info->body);
  uint32 right_redzone_start = left_redzone_end + block_info->body_size;
  left_redzone_end = common::AlignDown(left_redzone_end, kPageSize);
  right_redzone_start = common::AlignUp(right_redzone_start, kPageSize);

  if (alloc_start < left_redzone_end) {
    block_info->left_redzone_pages = reinterpret_cast<uint8*>(alloc_start);
    block_info->left_redzone_pages_size = left_redzone_end - alloc_start;
  }

  if (right_redzone_start < alloc_end) {
    block_info->right_redzone_pages =
        reinterpret_cast<uint8*>(right_redzone_start);
    block_info->right_redzone_pages_size = alloc_end - right_redzone_start;
  }
}

void InitializeBlockHeader(BlockInfo* block_info) {
  DCHECK_NE(static_cast<BlockInfo*>(NULL), block_info);
  DCHECK_NE(static_cast<BlockHeader*>(NULL), block_info->header);
  ::memset(block_info->header, 0, sizeof(BlockHeader));
  block_info->header->magic = kBlockHeaderMagic;
  block_info->header->has_header_padding = block_info->header_padding_size > 0;
  block_info->header->has_excess_trailer_padding =
      block_info->trailer_padding_size > sizeof(uint32);
  block_info->header->state = ALLOCATED_BLOCK;
  block_info->header->body_size = block_info->body_size;
}

void InitializeBlockHeaderPadding(BlockInfo* block_info) {
  DCHECK_NE(static_cast<BlockInfo*>(NULL), block_info);
  if (block_info->header_padding_size == 0)
    return;
  DCHECK(IsAligned(block_info->header_padding_size, kShadowRatio));
  DCHECK(IsAligned(block_info->header_padding_size,
                   2 * sizeof(uint32)));

  ::memset(block_info->header_padding + sizeof(uint32),
           kBlockHeaderPaddingByte,
           block_info->header_padding_size - 2 * sizeof(uint32));
  uint32* head = reinterpret_cast<uint32*>(block_info->header_padding);
  uint32* tail = reinterpret_cast<uint32*>(
      block_info->header_padding + block_info->header_padding_size -
          sizeof(uint32));
  *head = block_info->header_padding_size;
  *tail = block_info->header_padding_size;
}

void InitializeBlockTrailerPadding(BlockInfo* block_info) {
  DCHECK_NE(static_cast<BlockInfo*>(NULL), block_info);
  if (block_info->trailer_padding_size == 0)
    return;
  ::memset(block_info->trailer_padding, kBlockTrailerPaddingByte,
           block_info->trailer_padding_size);
  if (block_info->trailer_padding_size > (kShadowRatio / 2)) {
    // This is guaranteed by kShadowRatio being >= 8, but we double check
    // for sanity's sake.
    DCHECK_LE(sizeof(uint32), block_info->trailer_padding_size);
    uint32* head = reinterpret_cast<uint32*>(block_info->trailer_padding);
    *head = block_info->trailer_padding_size;
  }
}

void InitializeBlockTrailer(BlockInfo* block_info) {
  DCHECK_NE(static_cast<BlockInfo*>(NULL), block_info);
  ::memset(block_info->trailer, 0, sizeof(BlockTrailer));
  block_info->trailer->alloc_ticks = ::GetTickCount();
  block_info->trailer->alloc_tid = ::GetCurrentThreadId();
}

// Combines the bits of a uint32 into the number of bits used to store the
// block checksum.
uint32 CombineUInt32IntoBlockChecksum(uint32 val) {
  uint32 checksum = 0;
  while (val != 0) {
    checksum ^= val;
    val >>= kBlockHeaderChecksumBits;
  }
  checksum &= ((1 << kBlockHeaderChecksumBits) - 1);
  return checksum;
}

// An exception filter that only catches access violations.
DWORD AccessViolationFilter(EXCEPTION_POINTERS* e) {
  if (e->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION)
    return EXCEPTION_EXECUTE_HANDLER;
  return EXCEPTION_CONTINUE_SEARCH;
}

BlockHeader* BlockGetHeaderFromBodyImpl(const void* const_body) {
  DCHECK_NE(static_cast<void*>(NULL), const_body);

  void* body = const_cast<void*>(const_body);

  // The header must be appropriately aligned.
  if (!IsAligned(reinterpret_cast<uint32>(body), kShadowRatio))
    return NULL;

  // First assume that there is no padding, and check if a valid block header
  // is found there.
  BlockHeader* header = reinterpret_cast<BlockHeader*>(body) - 1;
  if (header->magic == kBlockHeaderMagic && header->has_header_padding == 0)
    return header;

  // Otherwise assume there is padding. The padding must be formatted
  // correctly and have a valid length.
  uint32* tail = reinterpret_cast<uint32*>(body) - 1;
  if (*tail == 0 || !IsAligned(*tail, kShadowRatio))
    return NULL;
  uint32* head = (tail + 1) - ((*tail) / sizeof(uint32));
  if (*head != *tail)
    return NULL;

  // Expect there to be a valid block header.
  header = reinterpret_cast<BlockHeader*>(head) - 1;
  if (header->magic == kBlockHeaderMagic && header->has_header_padding == 1)
    return header;

  // No valid block header was found before the provided body address.
  return NULL;
}

}  // namespace

const size_t kPageSize = GetPageSize();

void BlockPlanLayout(size_t chunk_size,
                     size_t alignment,
                     size_t size,
                     size_t min_left_redzone_size,
                     size_t min_right_redzone_size,
                     BlockLayout* layout) {
  DCHECK_LE(kShadowRatio, chunk_size);
  DCHECK(common::IsPowerOfTwo(chunk_size));
  DCHECK_LE(kShadowRatio, alignment);
  DCHECK_GE(chunk_size, alignment);
  DCHECK(common::IsPowerOfTwo(alignment));

  // Calculate minimum redzone sizes that respect the parameters.
  size_t left_redzone_size = common::AlignUp(
      std::max(min_left_redzone_size, sizeof(BlockHeader)),
      alignment);
  size_t right_redzone_size = std::max(min_right_redzone_size,
                                       sizeof(BlockTrailer));

  // Calculate the total size of the allocation.
  size_t total_size = common::AlignUp(
      left_redzone_size + size + right_redzone_size, chunk_size);

  // Now figure out the sizes of things such that the body of the allocation is
  // aligned as close as possible to the beginning of the right redzone while
  // respecting the body alignment requirements. This favors catching overflows
  // vs underflows when page protection mechanisms are active.
  size_t body_trailer_size = size + right_redzone_size;
  size_t body_trailer_size_aligned = common::AlignUp(body_trailer_size,
                                                     alignment);
  size_t body_padding_size = body_trailer_size_aligned - body_trailer_size;
  right_redzone_size += body_padding_size;

  // The left redzone takes up the rest of the space.
  left_redzone_size = total_size - right_redzone_size - size;

  // Make sure the basic layout invariants are satisfied.
  DCHECK_LE(min_left_redzone_size, left_redzone_size);
  DCHECK_LE(min_right_redzone_size, right_redzone_size);
  DCHECK_EQ(total_size, (left_redzone_size + size + right_redzone_size));
  DCHECK(IsAligned(total_size, chunk_size));
  DCHECK(IsAligned(left_redzone_size, alignment));

  // Fill out the layout structure.
  layout->block_alignment = chunk_size;
  layout->block_size = total_size;
  layout->header_size = sizeof(BlockHeader);
  layout->header_padding_size = left_redzone_size - sizeof(BlockHeader);
  layout->body_size = size;
  layout->trailer_padding_size = right_redzone_size - sizeof(BlockTrailer);
  layout->trailer_size = sizeof(BlockTrailer);
}

void BlockInitialize(const BlockLayout& layout,
                     void* allocation,
                     BlockInfo* block_info) {
  DCHECK_NE(static_cast<void*>(NULL), allocation);
  DCHECK(IsAligned(reinterpret_cast<uint32>(allocation),
                   layout.block_alignment));

  // If no output structure is provided then use a local one. We need the data
  // locally, but the caller might not be interested in it.
  BlockInfo local_block_info = {};
  if (block_info == NULL) {
    block_info = &local_block_info;
  } else {
    ::memset(block_info, 0, sizeof(BlockInfo));
  }

  // Get pointers to the various components of the block.
  uint8* cursor = reinterpret_cast<uint8*>(allocation);
  block_info->block = reinterpret_cast<uint8*>(cursor);
  block_info->block_size = layout.block_size;
  block_info->header = reinterpret_cast<BlockHeader*>(cursor);
  cursor += sizeof(BlockHeader);
  block_info->header_padding = cursor;
  cursor += layout.header_padding_size;
  block_info->header_padding_size = layout.header_padding_size;
  block_info->body = reinterpret_cast<uint8*>(cursor);
  cursor += layout.body_size;
  block_info->body_size = layout.body_size;
  block_info->trailer_padding = cursor;
  cursor += layout.trailer_padding_size;
  block_info->trailer_padding_size = layout.trailer_padding_size;
  block_info->trailer = reinterpret_cast<BlockTrailer*>(cursor);

  // If the block information is being returned to the user then determine
  // the extents of whole pages within it.
  if (block_info != &local_block_info)
    IdentifyWholePages(block_info);

  // Initialize the various portions of the memory. The body is not initialized
  // as this is an unnecessary performance hit.
  InitializeBlockHeader(block_info);
  InitializeBlockHeaderPadding(block_info);
  InitializeBlockTrailerPadding(block_info);
  InitializeBlockTrailer(block_info);
}

bool BlockInfoFromMemory(void* raw_block, BlockInfo* block_info) {
  DCHECK_NE(static_cast<void*>(NULL), raw_block);
  DCHECK_NE(static_cast<BlockInfo*>(NULL), block_info);

  // The raw_block header must be minimally aligned and begin with the expected
  // magic.
  if (!IsAligned(reinterpret_cast<uint32>(raw_block), kShadowRatio))
    return false;
  BlockHeader* header = reinterpret_cast<BlockHeader*>(raw_block);
  if (header->magic != kBlockHeaderMagic)
    return false;

  // Parse the header padding if present.
  uint32 header_padding_size = 0;
  if (header->has_header_padding) {
    uint8* padding = reinterpret_cast<uint8*>(header + 1);
    uint32* head = reinterpret_cast<uint32*>(padding);
    header_padding_size = *head;
    if (!IsAligned(header_padding_size, kShadowRatio))
      return false;
    uint32* tail = reinterpret_cast<uint32*>(
        padding + header_padding_size - sizeof(uint32));
    if (*head != *tail)
      return false;
  }

  // Parse the body.
  uint8* body = reinterpret_cast<uint8*>(header + 1) + header_padding_size;

  // Parse the trailer padding.
  uint32 trailer_padding_size = (kShadowRatio / 2) -
      (header->body_size % (kShadowRatio / 2));
  if (header->has_excess_trailer_padding) {
    uint32* head = reinterpret_cast<uint32*>(body + header->body_size);
    if ((*head % (kShadowRatio / 2)) != trailer_padding_size)
      return false;
    trailer_padding_size = *head;
  }

  // Parse the trailer. The end of it must be 8 aligned.
  BlockTrailer* trailer = reinterpret_cast<BlockTrailer*>(
      body + header->body_size + trailer_padding_size);
  if (!IsAligned(reinterpret_cast<uint32>(trailer + 1), kShadowRatio))
    return false;

  block_info->block = reinterpret_cast<uint8*>(raw_block);
  block_info->block_size = reinterpret_cast<uint8*>(trailer + 1)
      - reinterpret_cast<uint8*>(header);
  block_info->header = header;
  block_info->header_padding_size = header_padding_size;
  block_info->header_padding = block_info->block + sizeof(BlockHeader);
  block_info->body = body;
  block_info->body_size = header->body_size;
  block_info->trailer_padding_size = trailer_padding_size;
  block_info->trailer_padding = body + header->body_size;
  block_info->trailer = trailer;

  IdentifyWholePages(block_info);
  return true;
}

BlockHeader* BlockGetHeaderFromBody(const void* body) {
  DCHECK_NE(static_cast<void*>(NULL), body);

  __try {
    // As little code as possible is inside the body of the __try so that
    // our code coverage can instrument it.
    BlockHeader* header = BlockGetHeaderFromBodyImpl(body);
    return header;
  } __except (AccessViolationFilter(GetExceptionInformation())) {  // NOLINT
    // The block is either corrupt, or the pages are protected.
    return NULL;
  }
}

uint32 BlockCalculateChecksum(const BlockInfo& block_info) {
  // It is much easier to calculate the checksum in place so this actually
  // causes the block to be modified, but restores the original value.
  uint32 old_checksum = block_info.header->checksum;
  block_info.header->checksum = 0;
  BlockSetChecksum(block_info);
  uint32 new_checksum = block_info.header->checksum;
  block_info.header->checksum = old_checksum;
  return new_checksum;
}

bool BlockChecksumIsValid(const BlockInfo& block_info) {
  uint32 checksum = BlockCalculateChecksum(block_info);
  if (checksum == block_info.header->checksum)
    return true;
  return false;
}

void BlockSetChecksum(const BlockInfo& block_info) {
  block_info.header->checksum = 0;

  uint32 checksum = 0;
  switch (block_info.header->state) {
    case ALLOCATED_BLOCK: {
      // Only checksum the header and trailer regions.
      checksum = base::SuperFastHash(
          reinterpret_cast<const char*>(block_info.block),
          block_info.body - block_info.block);
      checksum ^= base::SuperFastHash(
          reinterpret_cast<const char*>(block_info.trailer_padding),
          block_info.block + block_info.block_size -
              block_info.trailer_padding);
      break;
    }

    // The checksum is the calculated in the same way in these two cases.
    // Similary, the catch all default case is calculated in this way so as to
    // allow the hash to successfully be calculated even for a block with a
    // corrupt state.
    case QUARANTINED_BLOCK:
    case FREED_BLOCK:
    default: {
      checksum = base::SuperFastHash(
          reinterpret_cast<const char*>(block_info.block),
          block_info.block_size);
      break;
    }
  }

  checksum = CombineUInt32IntoBlockChecksum(checksum);
  DCHECK_EQ(0u, checksum >> kBlockHeaderChecksumBits);
  block_info.header->checksum = checksum;
}

void BlockProtectNone(const BlockInfo& block_info) {
  if (block_info.block_pages_size == 0)
    return;
  DWORD old_protection = 0;
  DWORD ret = ::VirtualProtect(block_info.block_pages,
                               block_info.block_pages_size,
                               PAGE_READWRITE, &old_protection);
  DCHECK_NE(0u, ret);
}

void BlockProtectRedzones(const BlockInfo& block_info) {
  BlockProtectNone(block_info);

  // Protect the left redzone pages if any.
  DWORD old_protection = 0;
  DWORD ret = 0;
  if (block_info.left_redzone_pages_size > 0) {
    ret = ::VirtualProtect(block_info.left_redzone_pages,
                           block_info.left_redzone_pages_size,
                           PAGE_NOACCESS, &old_protection);
    DCHECK_NE(0u, ret);
  }

  // Protect the right redzone pages if any.
  if (block_info.right_redzone_pages_size > 0) {
    ret = ::VirtualProtect(block_info.right_redzone_pages,
                           block_info.right_redzone_pages_size,
                           PAGE_NOACCESS, &old_protection);
    DCHECK_NE(0u, ret);
  }
}

void BlockProtectAll(const BlockInfo& block_info) {
  if (block_info.block_pages_size == 0)
    return;
  DWORD old_protection = 0;
  DWORD ret = ::VirtualProtect(block_info.block_pages,
                               block_info.block_pages_size,
                               PAGE_NOACCESS, &old_protection);
  DCHECK_NE(0u, ret);
}

}  // namespace asan
}  // namespace agent
