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
// Implements a class that manages shadow memory for Asan.
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

#include "base/logging.h"
#include "base/synchronization/lock.h"
#include "syzygy/agent/asan/block.h"
#include "syzygy/agent/asan/constants.h"
#include "syzygy/agent/asan/shadow_marker.h"

namespace agent {
namespace asan {

// A class for managing shadow memory state.
class Shadow {
 public:
  // The first 64k of the memory are not addressable.
  static const size_t kAddressLowerBound = 0x10000;

  // The number of shadow bytes to emit per line of a report.
  static const size_t kShadowBytesPerLine = 8;

  // The number of lines of shadow memory to emit before and after the
  // faulting address. Thus, information about
  //
  // (2 * kShadowContextLines + 1) * kShadowBytesPerLine
  //
  // shadow bytes will be reported in all.
  static const size_t kShadowContextLines = 4;

  // Default constructor. Creates a shadow memory of the appropriate size
  // depending on the addressable memory for this process.
  // @note The allocation may fail, in which case 'shadow()' will return
  //     nullptr. If this is true the object should not be used.
  Shadow();

  // Shadow constructor. Allocates shadow memory internally.
  // @param length The length of the shadow memory in bytes. This implicitly
  //     encodes the maximum addressable address of the shadow.
  // @note The allocation may fail, in which case 'shadow()' will return
  //     nullptr. If this is true the object should not be used.
  explicit Shadow(size_t length);

  // Shadow constructor.
  // @param shadow The array to use for storing the shadow memory. The shadow
  //     memory allocation *must* be kShadowRatio byte aligned.
  // @param length The length of the shadow memory in bytes. This implicitly
  //     encodes the maximum addressable address of the shadow.
  Shadow(void* shadow, size_t length);

  // Destructor.
  virtual ~Shadow();

  // @returns the length of the shadow memory required for the current process.
  static size_t RequiredLength();

  // Set up the shadow memory.
  void SetUp();

  // Tear down the shadow memory.
  void TearDown();

  // Poisons @p size bytes starting at @p addr with @p shadow_val value.
  // @pre addr + size mod 8 == 0.
  // @param address The starting address.
  // @param size The size of the memory to poison.
  // @param shadow_val The poison marker value.
  void Poison(const void* addr, size_t size, ShadowMarker shadow_val);

  // Un-poisons @p size bytes starting at @p addr.
  // @pre addr mod 8 == 0 && size mod 8 == 0.
  // @param addr The starting address.
  // @param size The size of the memory to unpoison.
  void Unpoison(const void* addr, size_t size);

  // Mark @p size bytes starting at @p addr as freed.
  // @param addr The starting address.
  // @param size The size of the memory to mark as freed.
  void MarkAsFreed(const void* addr, size_t size);

  // Returns true iff the byte at @p addr is not poisoned.
  // @param addr The address that we want to check.
  // @returns true if this address is accessible, false otherwise.
  bool IsAccessible(const void* addr) const;

  // Returns true iff all the bytes from @p addr to @p addrs + size - 1 are
  // not poisoned
  // @param addr The address that we want to check.
  // @param size the number of bytes we want to check.
  // @returns true if this address is accessible, false otherwise.
  bool IsRangeAccessible(const void* addr, size_t size) const;

  // Returns the address of the first poisoned byte in the range
  // [@p addrs, @p addr + size), or nullptr if none are poisoned.
  // @param addr The address that we want to check.
  // @param size the number of bytes we want to check.
  // @returns the address of the first byte that's not accessible, or nullptr
  //     if all bytes in the range are accessible.
  const void* FindFirstPoisonedByte(const void* addr, size_t size) const;

  // @param address The address that we want to check.
  // @returns true if the byte at @p address is an active left redzone.
  bool IsLeftRedzone(const void* address) const;

  // @param address The address that we want to check.
  // @returns true if the byte at @p address is an active right redzone.
  bool IsRightRedzone(const void* address) const;

  // @param address The address that we want to check.
  // @returns true if the byte at @p address is the start of a block.
  bool IsBlockStartByte(const void* address) const;

  // Gets the shadow memory associated with an address.
  // @param addr The address for which we want the ShadowMarker value.
  // @returns a pointer to the shadow memory corresponding to the given
  //     address.
  const uint8_t* GetShadowMemoryForAddress(const void* addr) const;

  // Returns the ShadowMarker value for the byte at @p addr.
  // @param addr The address for which we want the ShadowMarker value.
  // @returns the ShadowMarker value for this address.
  ShadowMarker GetShadowMarkerForAddress(const void* addr) const;

  // Appends a textual description of the shadow memory for @p addr to
  // @p output, including the values of the shadow bytes and a legend.
  // @param addr The address for which we want to get the textual description.
  // @param output The string in which we want to store this information.
  void AppendShadowMemoryText(const void* addr, std::string* output) const;

  // Appends a textual description of the shadow memory for @p addr to
  // @p output. This only appends the values of the shadow bytes.
  // @param addr The address whose shadow memory is to be described.
  // @param output The string to be populated with the shadow memory
  //     information.
  void AppendShadowArrayText(const void* addr, std::string* output) const;

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
  bool GetNullTerminatedArraySize(const void* addr,
                                  size_t max_size,
                                  size_t* size) const;

  // Calculate the allocation size of a block by using the shadow memory.
  // @param mem A pointer inside the memory block for which we want to calculate
  //     the underlying allocation size.
  // @returns The underlying allocation size or 0 if it can't find a valid block
  //     at this address.
  size_t GetAllocSize(const uint8_t* mem) const;

  // Poisons memory for an freshly allocated block.
  // @param info Info about the block layout.
  // @note The block must be readable.
  void PoisonAllocatedBlock(const BlockInfo& info);

  // Inspects shadow memory to determine the layout of a block in memory.
  // Does not rely on any block content itself, strictly reading from the
  // shadow memory.
  // @param addr An address in the block to be inspected.
  // @param info The block information to be populated.
  // @returns true on success, false otherwise.
  bool BlockInfoFromShadow(const void* addr, CompactBlockInfo* info) const;
  bool BlockInfoFromShadow(const void* addr, BlockInfo* info) const;

  // Checks if the address @p addr corresponds to the beginning of a block's
  // body, i.e. if it's preceded by a left redzone.
  // @param addr The address that we want to check.
  // @returns true if the address corresponds to the beginning of a block's
  //     body, false otherwise.
  bool IsBeginningOfBlockBody(const void* addr) const;

  // Queries a given page's protection status.
  // @param addr An address in the page to be queried.
  // @returns true if the address containing the given page is protected,
  //     false otherwise.
  // @note The read does not occur under a lock, so it is possible to get
  //     stale data. Users must be robust for this.
  bool PageIsProtected(const void* addr) const;

  // Marks a given page as being protected.
  // @param addr An address in the page to be protected.
  // @note Grabs a global shadow lock.
  void MarkPageProtected(const void* addr);

  // Marks a given page as being unprotected.
  // @param addr An address in the page to be protected.
  // @note Grabs a global shadow lock.
  void MarkPageUnprotected(const void* addr);

  // Marks a given range of pages as being protected.
  // @param addr The first page to be marked.
  // @param size The extent of the memory to be marked.
  // @note Grabs a global shadow lock.
  void MarkPagesProtected(const void* addr, size_t size);

  // Marks a given range of pages as being unprotected.
  // @param addr The first page to be marked.
  // @param size The extent of the memory to be marked.
  // @note Grabs a global shadow lock.
  void MarkPagesUnprotected(const void* addr, size_t size);

  // Returns the size of memory represented by the shadow. This is a 64-bit
  // result to prevent overflow for 4GB 32-bit processes.
  const uint64_t memory_size() const {
    return static_cast<uint64_t>(length_) << kShadowRatioLog;
  }

  // Read only accessor of shadow memory.
  // @returns a pointer to the actual shadow memory.
  const uint8_t* shadow() const { return shadow_; }

  // Returns the length of the shadow array.
  size_t length() const { return length_; }

  // Read only accessor of page protection bits.
  const uint8_t* page_bits() const { return page_bits_; }

  // Returns the length of the page bits array.
  size_t const page_bits_size() const { return page_bits_length_; }

  // Determines if the shadow memory is clean. That is, it reflects the
  // state of shadow memory immediately after construction and a call to
  // SetUp.
  // @returns true if the shadow memory is clean (as it would appear directly
  //     after an initialization), false otherwise.
  bool IsClean() const;

 protected:
  // Seam for debug and testing shadow implementations. This is called for
  // every change made to a region of shadow memory.
  virtual void SetShadowMemory(
      const void* address, size_t length, ShadowMarker marker);

  // Returns the appropriately aligned (rounded as necessary) pointer and
  // size of the most derived class implementing Shadow.
  void GetPointerAndSize(void const** self, size_t* size) const;

  // Must be implemented by any derived classes. This returns the this pointer
  // and the size of the *most derived* class.
  virtual void GetPointerAndSizeImpl(void const** self, size_t* size) const;

  // Initializes this shadow object.
  void Init(size_t length);
  void Init(bool own_memory, void* shadow, size_t length);

  // Reset the shadow memory.
  void Reset();

  // Appends a line of shadow byte text for the bytes ranging from
  // shadow_[index] to shadow_[index + 7], prefixed by @p prefix. If the index
  // @p bug_index is present in this range then its value will be surrounded by
  // brackets.
  void AppendShadowByteText(const char *prefix,
                            uintptr_t index,
                            std::string* output,
                            size_t bug_index) const;

  // Scans to the left of the provided cursor, looking for the presence of a
  // block start marker that brackets the cursor.
  // @param cursor The position in shadow memory from which to start the scan.
  // @param location Will be set to the location of the start marker, if found.
  // @returns true on success, false otherwise.
  bool ScanLeftForBracketingBlockStart(size_t cursor, size_t* location) const;

  // Scans to the right of the provided cursor, looking for the presence of a
  // block end marker that brackets the cursor.
  // @param cursor The position in shadow memory from which to start the scan.
  // @param location Will be set to the location of the end marker, if found.
  // @returns true on success, false otherwise.
  bool ScanRightForBracketingBlockEnd(size_t cursor, size_t* location) const;

  // Inspects shadow memory to determine the layout of a block in memory.
  // @param addr An address in the block to be inspected.
  // @param info The block information to be populated.
  // @returns true on success, false otherwise.
  bool BlockInfoFromShadowImpl(
      const void* addr,
      CompactBlockInfo* info) const;

  // If this is true then this shadow object owns the memory.
  bool own_memory_;

  // The actual shadow that is being referred to. In case of large
  // address spaces it's stored as a sparse array
  // (see ShadowExceptionHandler in the .cc file).
  uint8_t* shadow_;

  // The length of the underlying shadow.
  size_t length_;

  // A lock under which page protection bits are modified.
  base::Lock page_bits_lock_;

  // Data about which pages are protected. As with large address spaces
  // there are a lot of pages, in that case it's stored as a sparse array,
  // in the same manner as the shadow. This changes relatively rarely, so
  // is reasonable to synchronize. Under page_bits_lock_.
  uint8_t* page_bits_;

  // The length of page_bits_. Under page_bits_lock_.
  size_t page_bits_length_;

#ifdef _WIN64
  // The exception handler handle to be able to remove it on object destruction.
  HANDLE exception_handler_;
#endif
};

// A helper class to walk over the blocks contained in a given memory region.
// This uses only the metadata present in the shadow to identify the blocks.
class ShadowWalker {
 public:
  // Constructor.
  // @param shadow The shadow memory object to walk.
  // @param lower_bound The lower bound of the region that this walker should
  //     cover in the actual memory.
  // @param upper_bound The upper bound of the region that this walker should
  //     cover in the actual memory. This can overflow to 0 to indicate walking
  //     all of memory.
  ShadowWalker(const Shadow* shadow,
               const void* lower_bound,
               const void* upper_bound);

  // Return the next block in this memory region.
  // @param info The block information to be populated.
  // @return true if a block was found, false otherwise.
  bool Next(BlockInfo* info);

  // Reset the walker to its initial state.
  void Reset();

 private:
  // The shadow memory being walked.
  const Shadow* shadow_;

  // The bounds of the memory region for this walker, expressed as pointers in
  // the shadow memory. This allows walking to occur without worrying about
  // overflow.
  size_t lower_index_;
  size_t upper_index_;

  // The shadow cursor.
  const uint8_t* shadow_cursor_;

  // The information about the memory range that we're currently scanning.
  MEMORY_BASIC_INFORMATION memory_info_;

  DISALLOW_COPY_AND_ASSIGN(ShadowWalker);
};

// The static shadow memory that is referred to by the memory interceptors.
extern "C" {
extern uint8_t asan_memory_interceptors_shadow_memory[];
}

// Bring in the implementation of the templated functions.
#include "syzygy/agent/asan/shadow_impl.h"

}  // namespace asan
}  // namespace agent

#endif  // SYZYGY_AGENT_ASAN_SHADOW_H_
