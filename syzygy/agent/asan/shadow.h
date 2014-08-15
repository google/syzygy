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
//
// Implements an all-static class that manages shadow memory for ASAN.
//
// The layout of a block is fully encoded in shadow memory, allowing for
// recovery of the block simply by inspecting the shadow memory. This is
// accomplished as follows:
//
// - Blocks are always a multiple of kShadowRatio in size and alignment.
// - Each group of kShadowRatio contiguous bytes is represented by a single
//   marker in the shadow.
// - The first marker of a block is a single block start marker, and the last
//   is a single block end marker. This uniquely identifies the beginning
//   and end of a block simply by scanning and looking for balanced markers.
// - The left and right redzones are uniquely identified by distinct markers.
// - The location of the header and trailer of a block are always at the
//   extremes, thus knowing the locations of the start and end markers
//   uniquely identifies their positions.
// - The left redzone markers uniquely encodes the length of the header padding
//   as it must also be a multiple of kShadowRatio in length.
// - The right redzone implies the length of the body of the allocation and
//   the trailer padding modulo kShadowRatio. The remaining bits are encoded
//   directly in the block start marker.
// - Nested blocks and regular blocks use differing block start/end markers.
//   This allows navigation through allocation hierarchies to terminate
//   without necessitating a scan through the entire shadow memory.
//
// A typical block will look something like the following in shadow memory:
//
//   00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
//   E7 FA FA FA 00 00 00 00 00 00 FB FB FB FB FB F4
//   |  \______/ \_______________/ \____________/ |
//   |     :             |                :       +-- Block end.
//   |     :             |                + - - - - - Right redzone.
//   |     :             +--------------------------- Body of allocation.
//   |     +- - - - - - - - - - - - - - - - - - - - - Left redzone.
//   +----------------------------------------------- Block start.
//
// - Both the end marker and the start marker indicate the block
//   is not nested. Together they indicate the total length of the
//   block is 128 bytes.
// - The start marker indicates that the body length is 7 % 8.
// - The header padding indicates that the 16 byte header is followed
//   by a further 16 bytes of padding.
// - The 6 body markers indicate an allocation size of 41..48 bytes.
//   Combined with the start marker bits the allocation size can be
//   inferred as being 47 bytes, with the last byte contributing to
//   the trailer padding.
// - The 5 right redzone markers indicate that the 20 byte trailer is
//   preceded by at least 28 trailer padding bytes. The additional
//   padding from the body means that there are in total 29 trailer
//   padding bytes.
// - 16(header) + 16(pad) + 47(body) + 29(pad) + 20(trailer) = 128

#ifndef SYZYGY_AGENT_ASAN_SHADOW_H_
#define SYZYGY_AGENT_ASAN_SHADOW_H_

#include <string>

#include "base/basictypes.h"
#include "base/logging.h"
#include "syzygy/agent/asan/block.h"
#include "syzygy/agent/asan/constants.h"
#include "syzygy/agent/asan/shadow_marker.h"

namespace agent {
namespace asan {

// An all-static class that manages the ASAN shadow memory.
class Shadow {
 public:
  // The first 64k of the memory are not addressable.
  static const size_t kAddressLowerBound = 0x10000;

  // One shadow byte for per group of kShadowRatio bytes in a 2G address space.
  // NOTE: This is dependent on the process NOT being large address aware.
  static const size_t kShadowSize = 1 << (31 - kShadowRatioLog);

  // The upper bound of the addressable memory.
  static const size_t kAddressUpperBound = kShadowSize << kShadowRatioLog;

  // Set up the shadow memory.
  static void SetUp();

  // Tear down the shadow memory.
  static void TearDown();

  // Poisons @p size bytes starting at @p addr with @p shadow_val value.
  // @pre addr + size mod 8 == 0.
  // @param address The starting address.
  // @param size The size of the memory to poison.
  // @param shadow_val The poison marker value.
  static void Poison(const void* addr, size_t size, ShadowMarker shadow_val);

  // Un-poisons @p size bytes starting at @p addr.
  // @pre addr mod 8 == 0 && size mod 8 == 0.
  // @param addr The starting address.
  // @param size The size of the memory to unpoison.
  static void Unpoison(const void* addr, size_t size);

  // Mark @p size bytes starting at @p addr as freed. This will preserve
  // nested block headers/trailers/redzones, but mark all contents as freed.
  // It is expected that the states of all nested blocks have already been
  // marked as freed prior to possibly freeing the parent block.
  // @param addr The starting address.
  // @param size The size of the memory to mark as freed.
  static void MarkAsFreed(const void* addr, size_t size);

  // Returns true iff the byte at @p addr is not poisoned.
  // @param addr The address that we want to check.
  // @returns true if this address is accessible, false otherwise.
  static bool IsAccessible(const void* addr);

  // @param address The address that we want to check.
  // @returns true if the byte at @p address is an active left redzone.
  static bool IsLeftRedzone(const void* address);

  // @param address The address that we want to check.
  // @returns true if the byte at @p address is an active right redzone.
  static bool IsRightRedzone(const void* address);

  // @param address The address that we want to check.
  // @returns true if the byte at @p address is the start of a block.
  static bool IsBlockStartByte(const void* address);

  // Returns the ShadowMarker value for the byte at @p addr.
  // @param addr The address for which we want the ShadowMarker value.
  // @returns the ShadowMarker value for this address.
  static ShadowMarker GetShadowMarkerForAddress(const void* addr);

  // Appends a textual description of the shadow memory for @p addr to
  // @p output, including the values of the shadow bytes and a legend.
  // @param addr The address for which we want to get the textual description.
  // @param output The string in which we want to store this information.
  static void AppendShadowMemoryText(const void* addr, std::string* output);

  // Appends a textual description of the shadow memory for @p addr to
  // @p output. This only appends the values of the shadow bytes.
  // @param addr The address whose shadow memory is to be described.
  // @param output The string to be populated with the shadow memory
  //     information.
  static void AppendShadowArrayText(const void* addr, std::string* output);

  // Returns true iff the array starting at @p addr is terminated with
  // sizeof(@p type) null bytes within a contiguous accessible region of memory.
  // When returning true the length of the null-terminated array (including the
  // trailings zero) will be returned via @p size. When returning false the
  // offset of the invalid access will be returned via @p size.
  // @tparam type The type of the null terminated value, this determines the
  //     numbers of null bytes that we want to have at the end of the array.
  // @param addr The starting address of the array that we want to check.
  // @param max_size The maximum length to check (in bytes). Ignored if set to
  //     zero.
  // @param size Will receive the size (in bytes) of the array terminated with
  //     sizeof(type) bytes or the offset of the invalid access.
  // @returns true iff the array starting at @p addr is null terminated within a
  //     contiguous accessible region of memory, false otherwise.
  template<typename type>
  static bool GetNullTerminatedArraySize(const void* addr,
                                         size_t max_size,
                                         size_t* size);

  // Clones a shadow memory range from one location to another.
  // @pre src_pointer mod 8 == 0.
  // @pre dst_pointer mod 8 == 0.
  // @pre size mod 8 == 0.
  // @param src_pointer The starting address of the range to copy.
  // @param dst_pointer The destination where the copy should be made.
  // @param size The size of the range to copy.
  static void CloneShadowRange(const void* src_pointer,
                               void* dst_pointer,
                               size_t size);

  // Calculate the allocation size of a block by using the shadow memory.
  // @param mem A pointer inside the memory block for which we want to calculate
  //     the underlying allocation size.
  // @returns The underlying allocation size or 0 if it can't find a valid block
  //     at this address.
  // @note This function doesn't work for nested blocks.
  // TODO(sebmarchand): Add support for nested blocks.
  static size_t GetAllocSize(const uint8* mem);

  // Poisons memory for an freshly allocated block.
  // @param info Info about the block layout.
  // @note The block must be readable.
  static void PoisonAllocatedBlock(const BlockInfo& info);

  // Determines if the block is nested simply by inspecting shadow memory.
  static bool BlockIsNested(const BlockInfo& info);

  // Inspects shadow memory to determine the layout of a block in memory.
  // Does not rely on any block content itself, strictly reading from the
  // shadow memory. In the case of nested blocks this will always return
  // the innermost containing block.
  // @param addr An address in the block to be inspected.
  // @param info The block information to be populated.
  // @returns true on success, false otherwise.
  static bool BlockInfoFromShadow(const void* addr, BlockInfo* info);

  // Inspects shadow memory to find the block containing a nested block.
  // @param nested Information about the nested block.
  // @param info The block information to be populated.
  // @returns true on success, false otherwise.
  static bool ParentBlockInfoFromShadow(
      const BlockInfo& nested, BlockInfo* info);

 protected:
  // Reset the shadow memory.
  static void Reset();

  // Appends a line of shadow byte text for the bytes ranging from
  // shadow_[index] to shadow_[index + 7], prefixed by @p prefix. If the index
  // @p bug_index is present in this range then its value will be surrounded by
  // brackets.
  static void AppendShadowByteText(const char *prefix,
                                   uintptr_t index,
                                   std::string* output,
                                   size_t bug_index);

  // Scans to the left of the provided cursor, looking for the presence of a
  // block start marker that brackets the cursor.
  // @param initial_nesting_depth If zero then this will return the inner
  //     most block containing the cursor. If 1 then this will find the start of
  //     the block containing that block, and so on.
  // @param cursor The position in shadow memory from which to start the scan.
  // @param location Will be set to the location of the start marker, if found.
  // @returns true on success, false otherwise.
  static bool ScanLeftForBracketingBlockStart(
      size_t initial_nesting_depth, size_t cursor, size_t* location);

  // Scans to the right of the provided cursor, looking for the presence of a
  // block end marker that brackets the cursor.
  // @param initial_nesting_depth If zero then this will return the inner
  //     most block containing the cursor. If 1 then this will find the end of
  //     the block containing that block, and so on.
  // @param cursor The position in shadow memory from which to start the scan.
  // @param location Will be set to the location of the end marker, if found.
  // @returns true on success, false otherwise.
  static bool ScanRightForBracketingBlockEnd(
      size_t initial_nesting_depth, size_t cursor, size_t* location);

  // Inspects shadow memory to determine the layout of a block in memory.
  // @param initial_nesting_depth If zero then this will return the inner
  //     most block containing the cursor. If 1 then this will find the end of
  //     the block containing that block, and so on.
  // @param addr An address in the block to be inspected.
  // @param info The block information to be populated.
  // @returns true on success, false otherwise.
  static bool BlockInfoFromShadowImpl(
      size_t initial_nesting_depth, const void* addr, BlockInfo* info);

  // The shadow memory.
  static uint8 shadow_[kShadowSize];
};

// A helper class to walk over the blocks contained in a given memory region.
// This uses only the metadata present in the shadow to identify the blocks.
class ShadowWalker {
 public:
  // Constructor.
  // @param recursive If true then this will recursively descend into nested
  //     blocks. Otherwise it will only return the outermost blocks in the
  //     provided region.
  // @param lower_bound The lower bound of the region that this walker should
  //     cover in the actual memory.
  // @param upper_bound The upper bound of the region that this walker should
  //     cover in the actual memory.
  ShadowWalker(bool recursive,
                  const void* lower_bound,
                  const void* upper_bound);

  // Return the next block in this memory region.
  // @param info The block information to be populated.
  // @return true if a block was found, false otherwise.
  bool Next(BlockInfo* info);

  // Reset the walker to its initial state.
  void Reset();

  // @returns the nesting depth of the last returned block. If no blocks have
  //     been walked then this returns -1.
  int nesting_depth() const { return nesting_depth_; }

 private:
  // Indicates whether or not the walker will descend recursively into nested
  // blocks.
  bool recursive_;

  // The bounds of the memory region for this walker.
  const uint8* lower_bound_;
  const uint8* upper_bound_;

  // The cursor of the shadow walker. This points to upper_bound_ when
  // the walk is terminated.
  const uint8* cursor_;

  // The current nesting depth. Starts at -1.
  int nesting_depth_;

  DISALLOW_COPY_AND_ASSIGN(ShadowWalker);
};

// Bring in the implementation of the templated functions.
#include "syzygy/agent/asan/shadow_impl.h"

}  // namespace asan
}  // namespace agent

#endif  // SYZYGY_AGENT_ASAN_SHADOW_H_
