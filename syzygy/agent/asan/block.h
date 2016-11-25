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
//
// Describes and declares an Asan block, which is fundamentally a single
// instrumented allocation of memory.
//
// Under Asan instrumentation allocations are instrumented with leading
// (left) and trailing (right) redzones. The left redzone contains a
// BlockHeader, while the right redzone contains a BlockTrailer. Each of
// these contain metadata about the allocation itself. In both cases the
// redzones may be larger than the headers they contain. Visually, a block is
// laid out as follows:
//
//   +------------------+  <-- N>=8 aligned \
//   |      header      |                   |
//   +------------------+                   |- left redzone
//   |  header padding  |                   |  (mod 8 in size)
//   |    (optional)    |                   /
//   +------------------+  <-- N>=8 aligned
//   |       body       |
//   +------------------+
//   | trailer padding  |                   \
//   |    (optional)    |                   |_ right redzone
//   +------------------+                   |
//   |     trailer      |                   /
//   +------------------+  <-- N>=8 aligned
//
// The information contained in the block headers is insufficient to recover
// the block extents. However, sufficiently detailed bookkeeping information is
// maintained in the shadow memory to allow inferring this data given a block
// pointer.
//
// NAVIGATING A BLOCK
//
// If the block is not corrupt it contains sufficient information to navigate
// the various components simply from inspecting the contents of memory itself.
//
// In the absence of any header padding the body immediately follows the
// header, and the length of the body is encoded directly in the header. The
// header has a bit indicating the presence of header padding. If present it
// has a length of at least kShadowRatio[1], and encodes the total length of
// the padding in the first 4 *and* last 4 bytes of the padding. This makes it
// possible to navigate in O(1) time from the body to the header and vice
// versa.
//
// There is always some implicit minimal amount of trailer padding required to
// flesh out the block body such that the end of the trailer is properly
// aligned. Another header bit indicates if there is more than this implicit
// padding present. If so, the trailer padding length is explicitly encoded in
// the first 4 bytes of the trailer padding. Either way it is possible to
// navigate to the beginning of the trailer.
//
// The rest of the header and trailer padding are filled with constant values
// as a visual debugging aid. An example block (with body of size 16, header
// padding of size 16, and trailer padding of 12) is shown in memory:
//
//   | 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
// --+------------------------------------------------
// 00| 80 CA .. .. .. .. .. .. .. .. .. .. .. .. .. ..
//   | magic \______________header data______________/
// 10| 10 00 00 00 1C 1C 1C 1C 1C 1C 1C 1C 10 00 00 00
//   | \_length__/ \____padding bytes____/ \_length__/
// 20| .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
//   | \____________________body_____________________/
// 30| 0C 00 00 00 C3 C3 C3 C3 C3 C3 C3 C3 .. .. .. ..
//   | \_length__/ \____padding bytes____/ \___trailer
// 40| .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..
//   | _________________trailer data_________________/
//
// [1] kShadowRatio: The ratio of main memory to shadow memory. This many
//     bytes of main memory map to a single byte of shadow memory. Currently
//     8:1, but may be higher.

#ifndef SYZYGY_AGENT_ASAN_BLOCK_H_
#define SYZYGY_AGENT_ASAN_BLOCK_H_

#include "base/callback.h"
#include "base/logging.h"
#include "syzygy/agent/asan/constants.h"

namespace agent {

// Forward declaration.
namespace common {
class StackCapture;
}  // namespace common

namespace asan {

// Forward declarations.
struct BlockLayout;
class Shadow;

// Various constants for identifying the beginnings of regions of memory.
static const uint16_t kBlockHeaderMagic = 0xCA80;

// Various constants used for filling regions of memory.
static const uint8_t kBlockHeaderPaddingByte = 0x1C;
static const uint8_t kBlockTrailerPaddingByte = 0xC3;
static const uint8_t kBlockFloodFillByte = 0xFD;

// The number of bits in the checksum field. This is parameterized so that
// it can be referred to by the checksumming code.
static constexpr size_t kBlockHeaderChecksumBits = 13;

// The number of bits used to store the size of an allocation.
static constexpr size_t kBlockBodySizeBits = 31;

// The state of an Asan block. These are in the order that reflects the typical
// lifespan of an allocation.
enum BlockState {
  // The block is allocated and valid for reading/writing.
  ALLOCATED_BLOCK,
  // The block has been quarantined, and not valid for reading/writing.
  // While in the quarantine it is still allocated as far as the underlying
  // heap is concerned, and won't be reclaimed.
  QUARANTINED_BLOCK,
  // The block is quarantined and its contents flood-filled. When a block is
  // quarantined in this mode it helps to identify the actual ranges of bytes
  // that have been overwritten in an uninstrumented use-after-free.
  QUARANTINED_FLOODED_BLOCK,
  // The block has been returned to the heap and is eligible to be reused
  // in a future allocation. In the meantime it is still not valid for
  // reading and writing.
  FREED_BLOCK,

  BLOCK_STATE_MAX,
};

// Declares the block header that is found in every left redzone. Since
// overwrites are far more common than underwrites critical information should
// be stored here.
#pragma pack(push, 1)
struct BlockHeader {
  struct {
    // A magic constant that identifies the block header in memory.
    unsigned magic : 16;
    // The checksum of the entire block. The semantics of this vary with the
    // block state.
    unsigned checksum : kBlockHeaderChecksumBits;
    // This is implicitly a BlockState value.
    unsigned state : 2;
    // If this bit is positive then header padding is present. The size of the
    // header padding is encoded in the padding itself.
    unsigned has_header_padding : 1;
    // If this bit is positive then trailer padding in excess of
    // kShadowRatio/2 is present, and the size of the trailer padding itself
    // will be encoded in these bytes. Otherwise it is implicit as
    // (kShadowRatio / 2) - (body_size % (kShadowRatio / 2)).
    unsigned has_excess_trailer_padding : 1;
    // The size of the body of the allocation, in bytes.
    unsigned body_size : kBlockBodySizeBits;
  };
  // TODO(loskutov): replace pointers with something more compact.
  // The allocation stack of this block.
  const common::StackCapture* alloc_stack;
  // The free stack of this block (NULL if not yet quarantined/freed).
  const common::StackCapture* free_stack;
};
#pragma pack(pop)
static_assert((sizeof(BlockHeader) % kShadowRatio) == 0,
              "Invalid BlockHeader mod size.");
#ifdef _WIN64
static_assert(sizeof(BlockHeader) == 24, "Invalid BlockHeader size.");
#else
static_assert(sizeof(BlockHeader) == 16, "Invalid BlockHeader size.");
#endif

// Declares dummy types for various parts of a block. These are used for type
// safety of the various utility functions for navigating blocks. These are
// forward declarations only and have no actual definition. This prevents them
// from being used as anything other than pointers, and prohibits pointer
// arithmetic.
struct BlockHeaderPadding;
struct BlockBody;
struct BlockTrailerPadding;

// Declares the block trailer that is found in every right redzone.
// This should ideally be a multiple of size (n + 1/2) * kShadowRatio. This
// is because on average we have half of kShadowRatio as padding trailing
// the body of the allocation. This takes advantage of it, without incurring
// additional penalty on allocation overhead (on average). As of late 2013
// this is supported by the actual distribution of allocations in Chrome.
#pragma pack(push, 1)
struct BlockTrailer {
  // The IDs of the threads that allocated/freed the block. If the block is
  // not yet quarantined/freed then |free_tid| is zero.
  // TODO(chrisha): Make these thread serial numbers, to deal with thread
  //     number reuse. This can be accomplished in the agent via the existing
  //     thread attach/detach callbacks.
  uint32_t alloc_tid;
  uint32_t free_tid;
  // The time at which the block was allocated. Combined with the address of
  // the block itself this acts as a (unique with high probability) serial
  // number for the block (especially if the heap is lazy to reuse
  // allocations).
  uint32_t alloc_ticks;
  // The time at which the block was freed (zero if not yet freed).
  uint32_t free_ticks;
  // The ID of the heap that allocated the block.
  size_t heap_id;
#ifdef _WIN64
  // Add some padding so the trailer size will be a multiple of size
  // (n + 1/2) * kShadowRatio.
  // TODO(sebmarchand): Use this bytes to store more information.
  uint32_t padding_;
#endif
};
#pragma pack(pop)
static_assert((sizeof(BlockTrailer) % kShadowRatio) == (kShadowRatio / 2),
              "Invalid BlockTrailer mod size.");
#ifndef _WIN64
static_assert(sizeof(BlockTrailer) == 20, "Invalid BlockTrailer size.");
#else
static_assert(sizeof(BlockTrailer) == 28, "Invalid BlockTrailer size.");
#endif

// A structure for recording the minimum pertinent information about a block.
// Can easily be expanded into a BlockInfo, but requires less space. This makes
// it suitable for storing blocks in a quarantine, for example.
// NOTE: If you want to navigate a block thoroughly and conveniently it is best
//       to first upgrade a CompactBlockInfo to a full BlockInfo struct.
struct CompactBlockInfo {
  // Pointer to the beginning of the allocation.
  BlockHeader* header;
  // The size of the entire allocation. It's supposed to fit into 30 bits.
  // (See BlockHeader::body_size)
  uint32_t block_size;
  struct {
    // The entire size of the header, including padding.
    unsigned header_size : 15;
    // The entire size of the trailer, including padding.
    unsigned trailer_size : 15;
    // Indicates if the block is nested.
    unsigned is_nested : 1;
  };
};
#ifdef _WIN64
static_assert(sizeof(CompactBlockInfo) == 16, "Invalid CompactBlockInfo size.");
#else
static_assert(sizeof(CompactBlockInfo) == 12, "Invalid CompactBlockInfo size.");
#endif

// A struct for initializing, modifying and navigating the various portions
// of an allocated block. This can be initialized as part of the creation of
// a new block, inferred from an in-memory investigation of an existing block
// (assuming no corruption), or from an investigation of the shadow memory.
struct BlockInfo {
  // The size of the entire allocation. This includes the header, the body,
  // the trailer and any padding. The block starts with the header.
  uint32_t block_size;

  // Left redzone. If there's no padding |header_padding| and |body| will
  // point to the same location, and |header_padding_size| will be zero.
  BlockHeader* header;
  BlockHeaderPadding* header_padding;
  uint32_t header_padding_size;

  // Body of the allocation.
  BlockBody* body;
  uint32_t body_size;

  // Right redzone. If there's no padding |trailer_padding| and |trailer| will
  // point to the same location, and |trailer_padding_size| will be zero.
  BlockTrailerPadding* trailer_padding;
  uint32_t trailer_padding_size;
  BlockTrailer* trailer;

  // Pages of memory that are *exclusive* to this block. These pages may be a
  // strict subset of the entire block, depending on how it was allocated.
  // These pages will have protections toggled as the block changes state.
  // These must stay contiguous.
  uint8_t* block_pages;
  uint32_t block_pages_size;
  uint8_t* left_redzone_pages;
  uint32_t left_redzone_pages_size;
  uint8_t* right_redzone_pages;
  uint32_t right_redzone_pages_size;

  // Convenience accessors to various parts of the block. All access should be
  // gated through these as they provide strong bounds checking in debug
  // builds.
  // @name
  // @{
  uint8_t* RawBlock() const { return reinterpret_cast<uint8_t*>(header); }
  uint8_t& RawBlock(uint32_t index) const {
    DCHECK_GT(block_size, index);
    return RawBlock()[index];
  }
  uint8_t* RawHeader() const { return reinterpret_cast<uint8_t*>(header); }
  uint8_t& RawHeader(uint32_t index) const {
    DCHECK_GT(sizeof(BlockHeader), index);
    return RawHeader()[index];
  }
  uint8_t* RawHeaderPadding() const {
    return reinterpret_cast<uint8_t*>(header_padding);
  }
  uint8_t& RawHeaderPadding(uint32_t index) const {
    DCHECK_GT(header_padding_size, index);
    return RawHeaderPadding()[index];
  }
  uint8_t* RawBody() const { return reinterpret_cast<uint8_t*>(body); }
  uint8_t& RawBody(uint32_t index) const {
    DCHECK_GT(body_size, index);
    return RawBody()[index];
  }
  uint8_t* RawTrailerPadding() const {
    return reinterpret_cast<uint8_t*>(trailer_padding);
  }
  uint8_t& RawTrailerPadding(uint32_t index) const {
    DCHECK_GT(trailer_padding_size, index);
    return RawTrailerPadding()[index];
  }
  uint8_t* RawTrailer() const { return reinterpret_cast<uint8_t*>(trailer); }
  uint8_t& RawTrailer(uint32_t index) const {
    DCHECK_GT(sizeof(BlockTrailer), index);
    return RawTrailer()[index];
  }
  // @}

  // @returns the total header size, including the header and any padding.
  uint32_t TotalHeaderSize() const {
    return sizeof(BlockHeader) + header_padding_size;
  }

  // @returns the total trailer size, including the trailer and any padding.
  uint32_t TotalTrailerSize() const {
    return sizeof(BlockTrailer) + trailer_padding_size;
  }
};

// Plans the layout of a block given allocation requirements. The layout will
// be of minimum size to respect the requested requirements. Padding will be
// introduced to respect alignment constraints, and it will be added strictly
// between the allocation body and the header/trailer (this lowers the
// likelihood of over/underflows corrupting the metadata).
// @param chunk_size The allocation will be assumed to be made with this
//     alignment, and will be a multiple of this in length. Must be a power of
//     2, and >= kShadowRatio.
// @param alignment The minimum alignment that the body of the allocation must
//     respect. This must be a power of two and satisfy
//     kShadowRatio <= |alignment| <= |chunk_size|.
// @param size The size of the body of the allocation. Can be 0.
// @param min_left_redzone_size The minimum size of the left redzone.
// @param min_right_redzone_size The minimum size of the right redzone.
// @param layout The layout structure to be populated.
// @returns true if the layout of the block is valid, false otherwise.
bool BlockPlanLayout(uint32_t chunk_size,
                     uint32_t alignment,
                     uint32_t size,
                     uint32_t min_left_redzone_size,
                     uint32_t min_right_redzone_size,
                     BlockLayout* layout);

// Given a fresh allocation and a block layout, lays out and initializes the
// given block. Initializes everything except for the allocation stack and the
// checksum. Initializes the block to the ALLOCATED_BLOCK state, setting
// |alloc_ticks| and |alloc_tid|. Sets |alloc_stack| to NULL; the caller should
// set this stack upon return so as to minimize the number of useless frames on
// the stack. Does not set the checksum.
// @param layout The layout to be respected.
// @param allocation The allocation to be filled in. This must be of
//     |layout.block_size| in size, and be aligned with
//     |layout.block_alignment|.
// @param block_info Will be filled in with pointers to the various portions
//     of the block. May be NULL.
// @note The pages containing the block must be writable and readable.
void BlockInitialize(const BlockLayout& layout,
                     void* allocation,
                     BlockInfo* block_info);

// Converts between the two BlockInfo formats. This will work as long as the
// input is valid; garbage in implies garbage out.
// @param compact The populated compact block info.
// @param expanded The full expanded block info.
void ConvertBlockInfo(const CompactBlockInfo& compact, BlockInfo* expanded);
void ConvertBlockInfo(const BlockInfo& expanded, CompactBlockInfo* compact);

// Given a pointer to a block examines memory and extracts the block layout.
// This protects against invalid memory accesses that may occur as a result of
// block corruption, or the block pages being protected; in case of error,
// this will return false.
// @note For unittesting the OnExceptionCallback may be used to determine if
//     an exception was handled.
// @param header A pointer to the block header.
// @param block_info The description of the block to be populated.
// @returns true if a valid block was encountered at the provided location,
//     false otherwise.
bool BlockInfoFromMemory(const BlockHeader* header,
                         CompactBlockInfo* block_info);
bool BlockInfoFromMemory(const BlockHeader* header, BlockInfo* block_info);

// Given a block body, finds the header. To find any other part of the
// block first parse it using BlockInfoFromMemory. This protects against
// invalid memory accesses that may occur as a result of block corruption,
// or the block pages being protected; in case of error, this will return
// NULL.
// @note For unittesting the OnExceptionCallback may be used to determine if
//     an exception was handled.
// @param body The body of the block.
// @returns a pointer to the block header, NULL if it was not found or in
//     case of error.
BlockHeader* BlockGetHeaderFromBody(const BlockBody* body);

// @name Checksum related functions.
// @{
// Calculates the checksum for the given block. This causes the contents
// of the block header to be modified temporarily while calculating the
// checksum, and as such is not thread safe.
// @param block_info The block to be checksummed.
// @returns the calculated checksum.
// @note The pages containing the block must be writable and readable.
uint32_t BlockCalculateChecksum(const BlockInfo& block_info);

// Determines if the block checksum is valid.
// @param block_info The block to be validated.
// @returns true on success, false otherwise.
// @note The pages containing the block must be writable and readable.
bool BlockChecksumIsValid(const BlockInfo& block_info);

// Calculates and sets the block checksum in place.
// @param block_info The block to be checksummed.
// @note The pages containing the block must be writable and readable.
void BlockSetChecksum(const BlockInfo& block_info);
// @}

// Determines if the body of a block is a valid flood-filled body.
// @param block_info The block to be checked.
// @returns true if the body is appropriately flood-filled.
bool BlockBodyIsFloodFilled(const BlockInfo& block_info);

// Infers the most likely block state from an analysis of the block header,
// contents, and the shadow memory.
// @param shadow The shadow memory to be queried.
// @param block_info The block to be analyzed.
// @returns the likely state of the block.
// @note The pages of the block must be readable.
BlockState BlockDetermineMostLikelyState(const Shadow* shadow,
                                         const BlockInfo& block_info);

// Determines if a block can be made checksum consistent with exactly
// the given number of bitflips.
// @param block_state The state of the block to be assumed during the
//     analysis. (The state encoded in the header may itself be corrupt.)
// @param block_info The block to be analyzed.
// @param bitflips The maximum number of bitflips to try. Values larger
//     than kBlockHeaderChecksumBits are meaningless.
bool BlockBitFlipsFixChecksum(BlockState block_state,
                              const BlockInfo& block_info,
                              size_t bitflips);

// Explores a block to see how many bitflips are required to make the checksum
// valid. This is always at most kBlockHeaderChecksumBits.
// @param block_state The state of the block to be assumed during the
//     analysis. (The state encoded in the header may itself be corrupt.)
// @param block_info The block to be analyzed.
// @param max_bitflips The maximum number of bitflips to try. Values larger
//     than kBlockHeaderChecksumBits are meaningless.
// @returns the number of bitflips that are required to make the checksum
//     match.
// @note The pages of the block must be readable and writable.
// @nore Any checksum can be made good using exactly kBlockHeaderChecksumBits
//     bitflips.
size_t BlockBitFlipsRequired(BlockState block_state,
                               const BlockInfo& block_info,
                               size_t max_bitflips);

// @name Block analysis related functions and declarations.
// @{
// An enumeration of possible states of snippets of data.
enum DataState {
  // Unable to determine if the data is corrupt or clean.
  kDataStateUnknown,
  // The data is in a known good state.
  kDataIsClean,
  // The data is corrupt.
  kDataIsCorrupt,
};

// Results of an analysis of block contents.
struct BlockAnalysisResult {
  // The overall result of the block state.
  DataState block_state;
  // The state of the sub-components of the block.
  DataState header_state;
  DataState body_state;
  DataState trailer_state;
};

// Analyzes a block for types of corruption. For each of the header,
// the body and the trailer, determines their state.
// @param block_state The state of the block to be assumed during the
//     analysis. (The state encoded in the header may itself be corrupt.)
// @param block_info The block to be analyzed.
// @param result The determined state of the block will be written
//     here.
// @note The pages of the block must be readable.
void BlockAnalyze(BlockState block_state,
                  const BlockInfo& block_info,
                  BlockAnalysisResult* result);

// @}

// This is a testing seam. If a callback is provided it will be invoked by
// the exception handling code in block.cc. Exceptions can occur due to the
// RTL playing with page protections, but during unittests it is known whether
// or not an exception should occur. This allows testing those expectations
// explicitly.
typedef base::Callback<void(EXCEPTION_POINTERS*)> OnExceptionCallback;
void SetOnExceptionCallback(OnExceptionCallback callback);
void ClearOnExceptionCallback();

}  // namespace asan
}  // namespace agent

#include "syzygy/agent/asan/block_impl.h"

#endif  // SYZYGY_AGENT_ASAN_BLOCK_H_
