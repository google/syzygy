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

#include <algorithm>

#include "base/hash.h"
#include "base/logging.h"
#include "syzygy/agent/asan/runtime.h"
#include "syzygy/agent/asan/shadow.h"
#include "syzygy/agent/asan/stack_capture_cache.h"
#include "syzygy/common/align.h"

namespace agent {
namespace asan {

namespace {

using ::common::IsAligned;

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

void InitializeBlockHeader(BlockInfo* block_info) {
  DCHECK_NE(static_cast<BlockInfo*>(NULL), block_info);
  DCHECK_NE(static_cast<BlockHeader*>(NULL), block_info->header);
  ::memset(block_info->header, 0, sizeof(BlockHeader));
  block_info->header->magic = kBlockHeaderMagic;
  block_info->header->has_header_padding = block_info->header_padding_size > 0;
  block_info->header->has_excess_trailer_padding =
      block_info->trailer_padding_size > sizeof(uint32_t);
  block_info->header->state = ALLOCATED_BLOCK;
  block_info->header->body_size = block_info->body_size;
}

void InitializeBlockHeaderPadding(BlockInfo* block_info) {
  DCHECK_NE(static_cast<BlockInfo*>(NULL), block_info);
  if (block_info->header_padding_size == 0)
    return;
  DCHECK(IsAligned(block_info->header_padding_size, kShadowRatio));
  DCHECK(IsAligned(block_info->header_padding_size, 2 * sizeof(uint32_t)));

  ::memset(block_info->RawHeaderPadding() + sizeof(uint32_t),
           kBlockHeaderPaddingByte,
           block_info->header_padding_size - 2 * sizeof(uint32_t));
  uint32_t* head = reinterpret_cast<uint32_t*>(block_info->header_padding);
  uint32_t* tail = reinterpret_cast<uint32_t*>(block_info->RawHeaderPadding() +
                                               block_info->header_padding_size -
                                               sizeof(uint32_t));
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
    DCHECK_LE(sizeof(uint32_t), block_info->trailer_padding_size);
    uint32_t* head = reinterpret_cast<uint32_t*>(block_info->trailer_padding);
    *head = block_info->trailer_padding_size;
  }
}

void InitializeBlockTrailer(BlockInfo* block_info) {
  DCHECK_NE(static_cast<BlockInfo*>(NULL), block_info);
  ::memset(block_info->trailer, 0, sizeof(BlockTrailer));
  block_info->trailer->alloc_ticks = ::GetTickCount();
  block_info->trailer->alloc_tid = ::GetCurrentThreadId();
}

// Combines the bits of a uint32_t into the number of bits used to store the
// block checksum.
uint32_t CombineUInt32IntoBlockChecksum(uint32_t val) {
  uint32_t checksum = 0;
  while (val != 0) {
    checksum ^= val;
    val >>= kBlockHeaderChecksumBits;
  }
  checksum &= ((1 << kBlockHeaderChecksumBits) - 1);
  return checksum;
}

// Global callback invoked by exception handlers when exceptions occur. This is
// a testing seam.
OnExceptionCallback g_on_exception_callback;

// An exception filter that catches access violations and out of bound accesses.
// This also invokes the OnExceptionCallback if one has been provided.
DWORD BadMemoryAccessFilter(EXCEPTION_POINTERS* e) {
  if (e->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION ||
      e->ExceptionRecord->ExceptionCode == EXCEPTION_ARRAY_BOUNDS_EXCEEDED) {
    // Invoke the callback if there is one registered. This has to happen here
    // because the exception record lives on the stack in this frame. If we
    // access this in the exception handler itself it will be below the bottom
    // of the stack and potentially overwritten by the handler's calltree.
    if (!g_on_exception_callback.is_null())
      g_on_exception_callback.Run(e);
    return EXCEPTION_EXECUTE_HANDLER;
  }
  return EXCEPTION_CONTINUE_SEARCH;
}

bool BlockInfoFromMemoryImpl(const BlockHeader* const_header,
                             CompactBlockInfo* block_info) {
  DCHECK_NE(static_cast<BlockHeader*>(nullptr), const_header);
  DCHECK_NE(static_cast<CompactBlockInfo*>(nullptr), block_info);

  // We only perform read operations, but the block_info needs to be populated
  // with non-const pointers. Thus, we cast once here to avoid a bunch of casts
  // all through this method.
  BlockHeader* header = const_cast<BlockHeader*>(const_header);

  // The raw_block header must be minimally aligned and begin with the expected
  // magic.
  if (!IsAligned(reinterpret_cast<uintptr_t>(header), kShadowRatio))
    return false;
  if (header->magic != kBlockHeaderMagic)
    return false;

  // Parse the header padding if present.
  uint32_t header_padding_size = 0;
  if (header->has_header_padding) {
    uint8_t* padding = reinterpret_cast<uint8_t*>(header + 1);
    uint32_t* head = reinterpret_cast<uint32_t*>(padding);
    header_padding_size = *head;
    if (header_padding_size < 2 * sizeof(uint32_t))
      return false;
    if (!IsAligned(header_padding_size, kShadowRatio))
      return false;
    uint32_t* tail = reinterpret_cast<uint32_t*>(padding + header_padding_size -
                                                 sizeof(uint32_t));
    if (header_padding_size != *tail)
      return false;
  }

  // Parse the body.
  uint8_t* body = reinterpret_cast<uint8_t*>(header + 1) + header_padding_size;

  // Parse the trailer padding.
  uint32_t trailer_padding_size = 0;
  if (header->has_excess_trailer_padding) {
    uint32_t* head = reinterpret_cast<uint32_t*>(body + header->body_size);
    trailer_padding_size = *head;
  } else if ((header->body_size % kShadowRatio) != (kShadowRatio / 2)) {
    trailer_padding_size = (kShadowRatio / 2) -
        (header->body_size % (kShadowRatio / 2));
  }

  // Parse the trailer. The end of it must be 8 aligned.
  BlockTrailer* trailer = reinterpret_cast<BlockTrailer*>(
      body + header->body_size + trailer_padding_size);
  if (!IsAligned(reinterpret_cast<uintptr_t>(trailer + 1), kShadowRatio))
    return false;

  block_info->header = header;
  block_info->block_size = reinterpret_cast<uint8_t*>(trailer + 1) -
                           reinterpret_cast<uint8_t*>(header);
  block_info->header_size = sizeof(BlockHeader) + header_padding_size;
  block_info->trailer_size = trailer_padding_size + sizeof(BlockTrailer);

  return true;
}

BlockHeader* BlockGetHeaderFromBodyImpl(const BlockBody* const_body) {
  DCHECK_NE(static_cast<BlockBody*>(nullptr), const_body);

  void* body = const_cast<BlockBody*>(const_body);

  // The header must be appropriately aligned.
  if (!IsAligned(reinterpret_cast<uintptr_t>(body), kShadowRatio))
    return NULL;

  // First assume that there is no padding, and check if a valid block header
  // is found there.
  BlockHeader* header = reinterpret_cast<BlockHeader*>(body) - 1;
  if (header->magic == kBlockHeaderMagic && header->has_header_padding == 0)
    return header;

  // Otherwise assume there is padding. The padding must be formatted
  // correctly and have a valid length.
  uint32_t* tail = reinterpret_cast<uint32_t*>(body) - 1;
  if (*tail == 0 || !IsAligned(*tail, kShadowRatio))
    return NULL;
  uint32_t* head = (tail + 1) - ((*tail) / sizeof(uint32_t));
  if (head > tail)
    return NULL;
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

bool BlockPlanLayout(uint32_t chunk_size,
                     uint32_t alignment,
                     uint32_t size,
                     uint32_t min_left_redzone_size,
                     uint32_t min_right_redzone_size,
                     BlockLayout* layout) {
  DCHECK_LE(kShadowRatio, chunk_size);
  DCHECK(::common::IsPowerOfTwo(chunk_size));
  DCHECK_LE(kShadowRatio, alignment);
  DCHECK_GE(chunk_size, alignment);
  DCHECK(::common::IsPowerOfTwo(alignment));

  // Prevent from trying to allocate a memory block bigger than what we can
  // represent in the block header.
  if (size > kMaxBlockHeaderBodySize)
    return false;

  // Calculate minimum redzone sizes that respect the parameters.
  uint32_t left_redzone_size = static_cast<uint32_t>(::common::AlignUp(
      std::max<uint32_t>(min_left_redzone_size, sizeof(BlockHeader)),
      alignment));
  uint32_t right_redzone_size = std::max<uint32_t>(min_right_redzone_size,
                                                   sizeof(BlockTrailer));

  // Calculate the total size of the allocation.
  uint32_t total_size = static_cast<uint32_t>(::common::AlignUp(
      left_redzone_size + size + right_redzone_size, chunk_size));

  if (total_size < size)
    return false;

  // Now figure out the sizes of things such that the body of the allocation is
  // aligned as close as possible to the beginning of the right redzone while
  // respecting the body alignment requirements. This favors catching overflows
  // vs underflows when page protection mechanisms are active.
  uint32_t body_trailer_size = size + right_redzone_size;
  uint32_t body_trailer_size_aligned = static_cast<uint32_t>(
      ::common::AlignUp(body_trailer_size, alignment));
  uint32_t body_padding_size = body_trailer_size_aligned - body_trailer_size;
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
  layout->block_size = static_cast<uint32_t>(total_size);
  layout->header_size = sizeof(BlockHeader);
  layout->header_padding_size = left_redzone_size - sizeof(BlockHeader);
  layout->body_size = size;
  layout->trailer_padding_size = right_redzone_size - sizeof(BlockTrailer);
  layout->trailer_size = sizeof(BlockTrailer);
  return true;
}

void BlockInitialize(const BlockLayout& layout,
                     void* allocation,
                     BlockInfo* block_info) {
  DCHECK_NE(static_cast<void*>(NULL), allocation);
  DCHECK(IsAligned(reinterpret_cast<uintptr_t>(allocation),
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
  uint8_t* cursor = reinterpret_cast<uint8_t*>(allocation);
  block_info->block_size = layout.block_size;
  block_info->header = reinterpret_cast<BlockHeader*>(cursor);
  cursor += sizeof(BlockHeader);
  block_info->header_padding = reinterpret_cast<BlockHeaderPadding*>(cursor);
  cursor += layout.header_padding_size;
  block_info->header_padding_size = layout.header_padding_size;
  block_info->body = reinterpret_cast<BlockBody*>(cursor);
  cursor += layout.body_size;
  block_info->body_size = layout.body_size;
  block_info->trailer_padding = reinterpret_cast<BlockTrailerPadding*>(cursor);
  cursor += layout.trailer_padding_size;
  block_info->trailer_padding_size = layout.trailer_padding_size;
  block_info->trailer = reinterpret_cast<BlockTrailer*>(cursor);

  // If the block information is being returned to the user then determine
  // the extents of whole pages within it.
  if (block_info != &local_block_info)
    BlockIdentifyWholePages(block_info);

  // Initialize the various portions of the memory. The body is not initialized
  // as this is an unnecessary performance hit.
  InitializeBlockHeader(block_info);
  InitializeBlockHeaderPadding(block_info);
  InitializeBlockTrailerPadding(block_info);
  InitializeBlockTrailer(block_info);
}

bool BlockInfoFromMemory(const BlockHeader* header,
                         CompactBlockInfo* block_info) {
  DCHECK_NE(static_cast<BlockHeader*>(nullptr), header);
  DCHECK_NE(static_cast<CompactBlockInfo*>(NULL), block_info);

  __try {
    // As little code as possible is inside the body of the __try so that
    // our code coverage can instrument it.
    bool result = BlockInfoFromMemoryImpl(header, block_info);
    return result;
  } __except (BadMemoryAccessFilter(GetExceptionInformation())) {  // NOLINT
    // The block is either corrupt, or the pages are protected.
    return false;
  }
}

void ConvertBlockInfo(const CompactBlockInfo& compact, BlockInfo* expanded) {
  // Get a byte-aligned pointer to the header for use in calculating pointers to
  // various other points to the block.
  uint8_t* block = reinterpret_cast<uint8_t*>(compact.header);

  expanded->block_size = compact.block_size;
  expanded->header = compact.header;
  expanded->header_padding_size = compact.header_size - sizeof(BlockHeader);
  expanded->header_padding = reinterpret_cast<BlockHeaderPadding*>(
      block + sizeof(BlockHeader));
  expanded->body = reinterpret_cast<BlockBody*>(block + compact.header_size);
  expanded->body_size = compact.block_size - compact.header_size -
      compact.trailer_size;
  expanded->trailer_padding_size = compact.trailer_size - sizeof(BlockTrailer);
  expanded->trailer_padding = reinterpret_cast<BlockTrailerPadding*>(
      block + compact.header_size + expanded->body_size);
  expanded->trailer = reinterpret_cast<BlockTrailer*>(
      expanded->RawTrailerPadding() + expanded->trailer_padding_size);
  BlockIdentifyWholePages(expanded);
}

void ConvertBlockInfo(const BlockInfo& expanded, CompactBlockInfo* compact) {
  DCHECK_NE(static_cast<CompactBlockInfo*>(nullptr), compact);
  compact->header = expanded.header;
  compact->block_size = expanded.block_size;
  compact->header_size = static_cast<uint32_t>(sizeof(BlockHeader) +
                                               expanded.header_padding_size);
  compact->trailer_size = static_cast<uint32_t>(sizeof(BlockTrailer) +
                                                expanded.trailer_padding_size);
}

bool BlockInfoFromMemory(const BlockHeader* header, BlockInfo* block_info) {
  DCHECK_NE(static_cast<BlockHeader*>(nullptr), header);
  DCHECK_NE(static_cast<BlockInfo*>(NULL), block_info);
  CompactBlockInfo compact = {};
  if (!BlockInfoFromMemory(header, &compact))
    return false;
  ConvertBlockInfo(compact, block_info);
  return true;
}

BlockHeader* BlockGetHeaderFromBody(const BlockBody* body) {
  DCHECK_NE(static_cast<BlockBody*>(nullptr), body);

  __try {
    // As little code as possible is inside the body of the __try so that
    // our code coverage can instrument it.
    BlockHeader* header = BlockGetHeaderFromBodyImpl(body);
    return header;
  } __except (BadMemoryAccessFilter(GetExceptionInformation())) {  // NOLINT
    // The block is either corrupt, or the pages are protected.
    return nullptr;
  }
}

uint32_t BlockCalculateChecksum(const BlockInfo& block_info) {
  // It is much easier to calculate the checksum in place so this actually
  // causes the block to be modified, but restores the original value.
  uint32_t old_checksum = block_info.header->checksum;
  block_info.header->checksum = 0;
  BlockSetChecksum(block_info);
  uint32_t new_checksum = block_info.header->checksum;
  block_info.header->checksum = old_checksum;
  return new_checksum;
}

bool BlockChecksumIsValid(const BlockInfo& block_info) {
  uint32_t checksum = BlockCalculateChecksum(block_info);
  if (checksum == block_info.header->checksum)
    return true;
  return false;
}

void BlockSetChecksum(const BlockInfo& block_info) {
  block_info.header->checksum = 0;

  uint32_t checksum = 0;
  switch (static_cast<BlockState>(block_info.header->state)) {
    case ALLOCATED_BLOCK:
    case QUARANTINED_FLOODED_BLOCK: {
      // Only checksum the header and trailer regions.
      checksum = base::SuperFastHash(
          reinterpret_cast<const char*>(block_info.header),
          block_info.TotalHeaderSize());
      checksum ^= base::SuperFastHash(
          reinterpret_cast<const char*>(block_info.trailer_padding),
          block_info.TotalTrailerSize());
      break;
    }

    // The checksum is the calculated in the same way in these two cases.
    case QUARANTINED_BLOCK:
    case FREED_BLOCK: {
      checksum = base::SuperFastHash(
          reinterpret_cast<const char*>(block_info.header),
          block_info.block_size);
      break;
    }
  }

  checksum = CombineUInt32IntoBlockChecksum(checksum);
  DCHECK_EQ(0u, checksum >> kBlockHeaderChecksumBits);
  block_info.header->checksum = checksum;
}

bool BlockBodyIsFloodFilled(const BlockInfo& block_info) {
  // TODO(chrisha): Move the memspn-like function from shadow.cc to a common
  // place and reuse it here.
  for (uint32_t i = 0; i < block_info.body_size; ++i) {
    if (block_info.RawBody(i) != kBlockFloodFillByte)
      return false;
  }
  return true;
}

// Identifies whole pages in the given block_info.
void BlockIdentifyWholePages(BlockInfo* block_info) {
  DCHECK_NE(static_cast<BlockInfo*>(NULL), block_info);
  static const size_t kPageInfoSize =
      FIELD_OFFSET(BlockInfo, right_redzone_pages_size) +
      sizeof(BlockInfo::right_redzone_pages_size) -
      FIELD_OFFSET(BlockInfo, block_pages);

  if (block_info->block_size < GetPageSize()) {
    ::memset(&block_info->block_pages, 0, kPageInfoSize);
    return;
  }

  uintptr_t alloc_start = reinterpret_cast<uintptr_t>(block_info->header);
  uintptr_t alloc_end = alloc_start + block_info->block_size;
  alloc_start = ::common::AlignUp(alloc_start, GetPageSize());
  alloc_end = ::common::AlignDown(alloc_end, GetPageSize());
  if (alloc_start >= alloc_end) {
    ::memset(&block_info->block_pages, 0, kPageInfoSize);
    return;
  }

  block_info->block_pages = reinterpret_cast<uint8_t*>(alloc_start);
  block_info->block_pages_size = alloc_end - alloc_start;

  uintptr_t left_redzone_end = reinterpret_cast<uintptr_t>(block_info->body);
  uintptr_t right_redzone_start = left_redzone_end + block_info->body_size;
  left_redzone_end = ::common::AlignDown(left_redzone_end, GetPageSize());
  right_redzone_start = ::common::AlignUp(right_redzone_start, GetPageSize());

  if (alloc_start < left_redzone_end) {
    block_info->left_redzone_pages = reinterpret_cast<uint8_t*>(alloc_start);
    block_info->left_redzone_pages_size = left_redzone_end - alloc_start;
  } else {
    block_info->left_redzone_pages = nullptr;
    block_info->left_redzone_pages_size = 0;
  }

  if (right_redzone_start < alloc_end) {
    block_info->right_redzone_pages =
        reinterpret_cast<uint8_t*>(right_redzone_start);
    block_info->right_redzone_pages_size = alloc_end - right_redzone_start;
  } else {
    block_info->right_redzone_pages = nullptr;
    block_info->right_redzone_pages_size = 0;
  }
}

namespace {

// Tries to determine if a block is most likely flood-fill quarantined by
// analyzing the block contents.
bool BlockIsMostLikelyFloodFilled(const BlockInfo& block_info) {
  // Count the number of filled bytes, filled spans and unfilled spans.
  size_t filled = 0;
  size_t filled_spans = 0;
  size_t unfilled_spans = 0;
  bool in_filled_span = false;
  for (uint32_t i = 0; i < block_info.body_size; ++i) {
    bool byte_is_filled = (block_info.RawBody(i) == kBlockFloodFillByte);
    if (byte_is_filled) {
      ++filled;
      if (!in_filled_span) {
        ++filled_spans;
        in_filled_span = true;
      }
    } else {
      if (in_filled_span) {
        ++unfilled_spans;
        in_filled_span = false;
      }
    }
  }

  // A perfectly flood-filled block has |filled| = |body_size|, and
  // |filled_spans| = 1. A likely flood-filled block has a low number of
  // |filled_spans| and mostly contains |filled| bytes. A block that is very
  // likely not flood-filled will have very few |filled| bytes, and somewhere
  // near the same number of |filled_spans|. This whole process is imprecise
  // and hard to quantify, so the following thresholds are quite arbitrary.

  // Arbitrarily place the threshold for flood-filled bytes at 50%. Consider it
  // unlikely that 10 disjoint overwrites have occurred. Also require there to
  // be more significantly more filled bytes than spans (twice as many).
  if (filled >= block_info.body_size / 2 && unfilled_spans < 10 &&
      filled > filled_spans / 2) {
    return true;
  }

  return false;
}

}  // namespace

BlockState BlockDetermineMostLikelyState(const Shadow* shadow,
                                         const BlockInfo& block_info) {
  // If the block has no body then the header has to be trusted.
  if (block_info.body_size == 0)
    return static_cast<BlockState>(block_info.header->state);

  // Use the shadow memory to determine if the body is marked as freed.
  ShadowMarker marker = shadow->GetShadowMarkerForAddress(block_info.body);
  if (marker == kHeapFreedMarker) {
    // If the body is freed then the block is more than likely quarantined.
    // Do a quick look to see if the block looks mostly flood-filled.
    if (BlockIsMostLikelyFloodFilled(block_info))
      return QUARANTINED_FLOODED_BLOCK;

    // The block may be freed or quarantined. However, the current runtime
    // doesn't actually persist freed blocks, so it must be quarantined.
    return QUARANTINED_BLOCK;
  }

  // Consider the block to be a live allocation.
  return ALLOCATED_BLOCK;
}

namespace {

// Advances a vector of bitflip locations to the next possible set of bitflip
// locations. Returns true if advancing was possible, false otherwise.
// TODO(chrisha): This can be made drastically more efficient by skipping
//     configurations that flip bits in parts of the block that don't
//     contribute to the checksum (ie, the body for live and flooded
//     allocations).
bool AdvanceBitFlips(size_t positions, std::vector<uint32_t>* flips) {
  DCHECK_NE(static_cast<std::vector<uint32_t>*>(nullptr), flips);

  // An empty set of bitflips is already exhausted.
  if (flips->empty())
    return false;

  // Advancing stops when all bitflip positions are as far right as they can
  // go.
  if (flips->at(0) == positions - flips->size())
    return false;

  // Figure out how many consecutive trailing positions are at their maximums.
  // This will terminate before going out of bounds due to the above condition.
  size_t i = 0;
  while (flips->at(flips->size() - i - 1) == positions - i - 1) {
    ++i;
    DCHECK_LT(i, flips->size());
  }

  // Increment the first position that wasn't as far right as it could go, and
  // then make the rest of them consecutive.
  size_t j = flips->size() - i - 1;
  ++flips->at(j);
  DCHECK_LT(flips->at(j), positions);
  for (size_t k = j + 1; k < flips->size(); ++k) {
    flips->at(k) = flips->at(k - 1) + 1;
    DCHECK_LT(flips->at(k), positions);
  }

  return true;
}

// Flips the bits at the given positions.
void FlipBits(const std::vector<uint32_t>& flips, const BlockInfo& block_info) {
  for (uint32_t i = 0; i < flips.size(); ++i) {
    DCHECK_LT(flips[i], block_info.block_size * 8);
    uint32_t byte = flips[i] / 8;
    uint32_t bit = flips[i] % 8;
    uint8_t mask = static_cast<uint8_t>(1u << bit);
    block_info.RawBlock(byte) ^= mask;
  }
}

bool BlockBitFlipsFixChecksumImpl(const BlockInfo& block_info,
                                  size_t bitflips) {
  bitflips = std::min(bitflips, kBlockHeaderChecksumBits);

  size_t positions = block_info.block_size * 8;

  // Initialize the first possible sequence of bitflips (wrt the generator
  // in AdvanceBitFlips).
  std::vector<uint32_t> flips;
  flips.resize(bitflips);
  for (uint32_t i = 0; i < flips.size(); ++i)
    flips[i] = i;

  while (true) {
    FlipBits(flips, block_info);
    bool valid_checksum = BlockChecksumIsValid(block_info);
    FlipBits(flips, block_info);
    if (valid_checksum)
      return true;

    // When no more sets of bitflips are possible the search has terminated
    // with a negative result.
    if (!AdvanceBitFlips(positions, &flips))
      return false;
  }

  NOTREACHED();
  return false;
}

}  // namespace

bool BlockBitFlipsFixChecksum(BlockState block_state,
                              const BlockInfo& block_info,
                              size_t bitflips) {
  BlockState old_block_state =
      static_cast<BlockState>(block_info.header->state);
  block_info.header->state = block_state;
  bool result = BlockBitFlipsFixChecksumImpl(block_info, bitflips);
  block_info.header->state = old_block_state;
  return result;
}

size_t BlockBitFlipsRequired(BlockState block_state,
                             const BlockInfo& block_info,
                             size_t max_bitflips) {
  max_bitflips = std::min(max_bitflips, kBlockHeaderChecksumBits);
  for (size_t i = 0; i <= max_bitflips; ++i) {
    if (BlockBitFlipsFixChecksum(block_state, block_info, i))
      return i;
  }

  NOTREACHED();
  return 0;
}

// This namespace contains helpers for block analysis.
namespace {

// Determines if a stack-capture pointer is valid by referring to the
// stack-capture cache in the active runtime.
bool IsValidStackCapturePointer(const common::StackCapture* stack) {
  if (stack == nullptr)
    return false;
  AsanRuntime* runtime = AsanRuntime::runtime();
  DCHECK_NE(static_cast<AsanRuntime*>(nullptr), runtime);
  StackCaptureCache* cache = runtime->stack_cache();
  DCHECK_NE(static_cast<StackCaptureCache*>(nullptr), cache);
  if (!cache->StackCapturePointerIsValid(stack))
    return false;
  return true;
}

// Determines if a thread-id is valid by referring to the cache of thread-ids
// in the runtime.
bool IsValidThreadId(uint32_t thread_id) {
  AsanRuntime* runtime = AsanRuntime::runtime();
  DCHECK_NE(static_cast<AsanRuntime*>(nullptr), runtime);
  if (!runtime->ThreadIdIsValid(thread_id))
    return false;
  return true;
}

// Determines if timestamp is plausible by referring to the process start
// time as recorded by the runtime.
bool IsValidTicks(uint32_t ticks) {
  uint32_t end = ::GetTickCount();
  AsanRuntime* runtime = AsanRuntime::runtime();
  DCHECK_NE(static_cast<AsanRuntime*>(nullptr), runtime);
  uint32_t begin = runtime->starting_ticks();
  if (ticks < begin || ticks > end)
    return false;
  return true;
}

// Determines if a heap id is valid by referring to the runtime.
bool IsValidHeapId(size_t heap_id) {
  AsanRuntime* runtime = AsanRuntime::runtime();
  DCHECK_NE(static_cast<AsanRuntime*>(nullptr), runtime);
  if (!runtime->HeapIdIsValid(heap_id))
    return false;
  return true;
}

bool BlockHeaderIsConsistent(BlockState block_state,
                             const BlockInfo& block_info) {
  const BlockHeader* h = block_info.header;
  if (h->magic != kBlockHeaderMagic)
    return false;

  bool expect_header_padding = block_info.header_padding_size > 0;
  if (static_cast<bool>(h->has_header_padding) != expect_header_padding)
    return false;

  bool expect_excess_trailer_padding =
      block_info.trailer_padding_size > (kShadowRatio / 2);
  if (static_cast<bool>(h->has_excess_trailer_padding) !=
          expect_excess_trailer_padding) {
    return false;
  }

  if (h->body_size != block_info.body_size)
    return false;

  // There should always be a valid allocation stack trace.
  if (!IsValidStackCapturePointer(h->alloc_stack))
    return false;

  // The free stack should be empty if we're in the allocated state.
  if (block_state == ALLOCATED_BLOCK) {
    if (h->free_stack != nullptr)
      return false;
  } else {
    // Otherwise there should be a valid free stack.
    if (!IsValidStackCapturePointer(h->free_stack))
      return false;
  }

  // If there's no header padding then the block is valid.
  if (block_info.header_padding_size == 0)
    return true;

  // Analyze the block header padding.
  const uint32_t* head =
      reinterpret_cast<const uint32_t*>(block_info.header_padding);
  const uint32_t* tail =
      reinterpret_cast<const uint32_t*>(block_info.RawHeaderPadding() +
                                        block_info.header_padding_size) -
      1;
  if (*head != block_info.header_padding_size)
    return false;
  if (*tail != block_info.header_padding_size)
    return false;
  static const uint32_t kHeaderPaddingValue =
      (kBlockHeaderPaddingByte << 24) | (kBlockHeaderPaddingByte << 16) |
      (kBlockHeaderPaddingByte << 8) | kBlockHeaderPaddingByte;
  for (++head; head < tail; ++head) {
    if (*head != kHeaderPaddingValue)
      return false;
  }

  return true;
}

// Returns true if the trailer is self-consistent, false otherwise.
// Via |cross_consistent| indicates whether or not the header and trailer
// are consistent with respect to each other.
bool BlockTrailerIsConsistent(BlockState block_state,
                              const BlockInfo& block_info) {
  const BlockTrailer* t = block_info.trailer;

  // The allocation data must always be set.
  if (!IsValidThreadId(t->alloc_tid))
    return false;
  if (!IsValidTicks(t->alloc_ticks))
    return false;

  // The free fields must not be set for allocated blocks, and must be set
  // otherwise.
  if (block_state == ALLOCATED_BLOCK) {
    if (t->free_tid != 0 || t->free_ticks != 0)
      return false;
  } else {
    if (t->free_tid == 0 || t->free_ticks == 0)
      return false;
  }

  // The heap ID must always be set and be valid.
  if (!IsValidHeapId(t->heap_id))
    return false;

  // If there's no padding to check then we're done.
  if (block_info.trailer_padding_size == 0)
    return true;

  const uint8_t* padding = block_info.RawTrailerPadding();
  size_t size = block_info.trailer_padding_size;

  // If we have excess trailer padding then check the encoded length.
  if (size > (kShadowRatio / 2)) {
    const uint32_t* length = reinterpret_cast<const uint32_t*>(padding);
    if (*length != size)
      return false;
    padding += sizeof(uint32_t);
    size -= sizeof(uint32_t);
  }

  // Check the remaining trailer padding to ensure it's appropriately
  // flood-filled.
  while (size > 0) {
    if (*padding != kBlockTrailerPaddingByte)
      return false;
    ++padding;
    --size;
  }

  return true;
}

}  // namespace

void BlockAnalyze(BlockState block_state,
                  const BlockInfo& block_info,
                  BlockAnalysisResult* result) {
  DCHECK_NE(static_cast<BlockAnalysisResult*>(nullptr), result);

  result->block_state = kDataStateUnknown;
  result->header_state = kDataStateUnknown;
  result->body_state = kDataStateUnknown;
  result->trailer_state = kDataStateUnknown;

  bool checksum_is_valid = BlockChecksumIsValid(block_info);
  if (checksum_is_valid) {
    result->block_state = kDataIsClean;
    result->header_state = kDataIsClean;
    result->body_state = kDataIsClean;
    result->trailer_state = kDataIsClean;

    // Unless the block is flood-filled the checksum is the only thing that
    // needs to be checked.
    if (block_state != QUARANTINED_FLOODED_BLOCK)
      return;
  }

  // If the block is flood-filled then check the block contents.
  if (block_state == QUARANTINED_FLOODED_BLOCK) {
    if (!BlockBodyIsFloodFilled(block_info)) {
      result->block_state = kDataIsCorrupt;
      result->body_state = kDataIsCorrupt;
    }

    // The checksum is valid so the header and footer can be inferred to be
    // clean.
    if (checksum_is_valid)
      return;

    // Fall through and let the following logic determine which of the header
    // and footer is corrupt.
  }

  // At this point it's known that the checksum is invalid, so some part
  // of the block is corrupt.
  DCHECK(!checksum_is_valid);
  result->block_state = kDataIsCorrupt;

  // Either the header, the body or the trailer is invalid. We can't
  // ever exonerate the body contents, so at the very least its state
  // is unknown. Leave it set to unknown.

  // Check the header.
  bool consistent_header = BlockHeaderIsConsistent(block_state, block_info);
  if (!consistent_header) {
    result->header_state = kDataIsCorrupt;
  } else {
    result->header_state = kDataIsClean;
  }

  // Check the trailer.
  bool consistent_trailer = BlockTrailerIsConsistent(block_state, block_info);
  if (!consistent_trailer) {
    result->trailer_state = kDataIsCorrupt;
  } else {
    result->trailer_state = kDataIsClean;
  }

  if (consistent_header && consistent_trailer) {
    // If both the header and trailer are fine and the body is not *known* to
    // be clean, then it is most likely that the header and trailer are clean
    // and the body is corrupt. If the body is known to be clean (in the case
    // of a flood-filled body) then this is a hash collision and both the
    // header and trailer will be marked as suspect.
    if (result->body_state != kDataIsClean) {
      result->body_state = kDataIsCorrupt;
    } else {
      DCHECK_EQ(QUARANTINED_FLOODED_BLOCK, block_state);
      result->header_state = kDataStateUnknown;
      result->trailer_state = kDataStateUnknown;
    }
  }
}

void SetOnExceptionCallback(OnExceptionCallback callback) {
  g_on_exception_callback = callback;
}

void ClearOnExceptionCallback() {
  g_on_exception_callback.Reset();
}

}  // namespace asan
}  // namespace agent
