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
// Implements HeapProxy, a class that wraps Win32 heap allocations but adds
// heap/tail redzones.

#ifndef SYZYGY_AGENT_ASAN_ASAN_HEAP_H_
#define SYZYGY_AGENT_ASAN_ASAN_HEAP_H_

#include <windows.h>  // NOLINT

#include "base/logging.h"
#include "base/string_piece.h"
#include "base/debug/stack_trace.h"
#include "base/synchronization/lock.h"
#include "syzygy/agent/asan/stack_capture_cache.h"
#include "syzygy/agent/common/dlist.h"

namespace agent {
namespace asan {

// Forward declaration.
class StackCapture;
class StackCaptureCache;
struct AsanErrorInfo;

// Makes like a Win32 heap manager heap, but adds a redzone before and after
// each allocation and maintains a quarantine list of freed blocks.
class HeapProxy {
 public:
  // The different memory access modes that we can encounter.
  enum AccessMode {
    ASAN_READ_ACCESS,
    ASAN_WRITE_ACCESS,
    ASAN_UNKNOWN_ACCESS
  };

  // Enumeration of the different kinds of bad heap accesses that we can
  // encounter.
  enum BadAccessKind {
    // This enum should start with bad access type that are not relative to a
    // heap block.
    // @note The ordering is important because those labels are used in
    //     numeric inequalities.
    UNKNOWN_BAD_ACCESS,
    WILD_ACCESS,
    INVALID_ADDRESS,

    // This enum should end with bad access types that are relative to heap
    // blocks.
    USE_AFTER_FREE,
    HEAP_BUFFER_OVERFLOW,
    HEAP_BUFFER_UNDERFLOW,
    DOUBLE_FREE
  };

  // The different types of error we can encounter.
  static const char* kHeapUseAfterFree;
  static const char* kHeapBufferUnderFlow;
  static const char* kHeapBufferOverFlow;
  static const char* kAttemptingDoubleFree;
  static const char* kInvalidAddress;
  static const char* kWildAccess;
  static const char* kHeapUnknownError;

  // The sleep time (in milliseconds) used to approximate the CPU frequency.
  // Exposed for testing.
  static const size_t kSleepTimeForApproximatingCPUFrequency = 100;

  // The number of bits used to store the block checksum.
  static const size_t kChecksumBits = 12;

  HeapProxy();
  ~HeapProxy();

  // @name Cast to/from HANDLE.
  // @{
  static HANDLE ToHandle(HeapProxy* proxy);
  static HeapProxy* FromHandle(HANDLE heap);
  // @}

  // @name Heap interface.
  // @{
  bool Create(DWORD options,
              size_t initial_size,
              size_t maximum_size);
  bool Destroy();
  void* Alloc(DWORD flags, size_t bytes);
  void* ReAlloc(DWORD flags, void* mem, size_t bytes);
  bool Free(DWORD flags, void* mem);
  size_t Size(DWORD flags, const void* mem);
  bool Validate(DWORD flags, const void* mem);
  size_t Compact(DWORD flags);
  bool Lock();
  bool Unlock();
  bool Walk(PROCESS_HEAP_ENTRY* entry);
  bool SetInformation(HEAP_INFORMATION_CLASS info_class,
                      void* info,
                      size_t info_length);
  bool QueryInformation(HEAP_INFORMATION_CLASS info_class,
                        void* info,
                        size_t info_length,
                        unsigned long* return_length);
  // @}

  // Return the handle to the underlying heap.
  HANDLE heap() { return heap_; }

  // indicates if we own the underlying heap.
  bool owns_heap() { return owns_heap_; }

  // Initialize this instance with a given heap handle.
  // @param underlying_heap The underlying heap we should delegate to.
  // @returns true on success, false otherwise.
  // @note The caller keeps the ownership of the heap and is responsible for
  //     releasing it. (@p underlying_heap should have a lifetime exceeding
  //     this).
  void UseHeap(HANDLE underlying_heap);

  // Get information about a bad access.
  // @param bad_access_info Will receive the information about this access.
  // @returns true if the address belongs to a memory block, false otherwise.
  static bool GetBadAccessInformation(AsanErrorInfo* bad_access_info);

  // @name Cast to/from HANDLE.
  // @{
  static LIST_ENTRY* ToListEntry(HeapProxy* proxy);
  static HeapProxy* FromListEntry(LIST_ENTRY* list_entry);
  // @}

  // Set the default max size of the quarantine of a heap proxy.
  // @param quarantine_size The maximum size of the quarantine list, in
  //     bytes.
  static void set_default_quarantine_max_size(
      size_t default_quarantine_max_size) {
    default_quarantine_max_size_ = default_quarantine_max_size;
  }

  // Get the default max size of the quarantine of a heap proxy.
  static size_t default_quarantine_max_size() {
    return default_quarantine_max_size_;
  }

  // Set the max size of the quarantine of a heap proxy. If the current size of
  // the quarantine is greater than this new max size then the extra blocks are
  // removed from the quarantine.
  // @param quarantine_size The maximum size of the quarantine list, in
  //     bytes.
  void SetQuarantineMaxSize(size_t quarantine_max_size);

  // Get the max size of the quarantine of a heap proxy.
  size_t quarantine_max_size() {
    return quarantine_max_size_;
  }

  // Set the trailer padding size.
  // @param trailer_padding_size The trailer padding size, in bytes.
  static void set_trailer_padding_size(size_t trailer_padding_size) {
    trailer_padding_size_ = trailer_padding_size;
  }

  // Get the trailer padding size.
  static size_t trailer_padding_size() {
    return trailer_padding_size_;
  }

  // Static initialization of HeapProxy context.
  // @param cache The stack capture cache shared by the HeapProxy.
  static void Init(StackCaptureCache* cache);

  // Returns a string describing a bad access kind.
  static const char* AccessTypeToStr(BadAccessKind bad_access_kind);

  // Calculates the underlying allocation size for a requested allocation of
  // @p bytes, with an alignment of @p alignment bytes.
  static size_t GetAllocSize(size_t bytes, size_t alignment);

  // Returns the location and size of the ASan block wrapping a given user
  // pointer.
  // @param user_pointer The user pointer for this ASan block.
  // @param asan_pointer Receives the ASan pointer.
  // @param size Receives the size of this ASan block.
  static void GetAsanExtent(const void* user_pointer,
                            void** asan_pointer,
                            size_t* size);

  // Given a pointer to an ASan wrapped allocation, returns the location and
  // size of the user data contained within.
  // @param asan_pointer The pointer to the ASan block.
  // @param user_pointer Receives the user pointer.
  // @param size Receives the size of the user part of this block.
  static void GetUserExtent(const void* asan_pointer,
                            void** user_pointer,
                            size_t* size);

  // Initialize an ASan block. This will red-zone the header and trailer, green
  // zone the user data, and save the allocation stack trace and other metadata.
  // @param asan_pointer The ASan block to initialize.
  // @param user_size The user size for this block.
  // @param asan_size The total size of this block.
  // @param alloc_granularity_log The allocation granularity for this block.
  // @param stack The allocation stack capture for this block.
  // @returns The user pointer for this block on success, NULL otherwise.
  static void* InitializeAsanBlock(uint8* asan_pointer,
                                   size_t user_size,
                                   size_t asan_size,
                                   size_t alloc_granularity_log,
                                   const StackCapture& stack);

  // Mark the given block as freed, but still residing in memory. This will
  // red-zone the user data and grab a free stack trace and other metadata.
  // After this call the object is effectively quarantined and access to it will
  // be caught as errors.
  // @param asan_pointer The pointer to the ASan block.
  // @param stack The free stack capture for this block.
  static void MarkBlockAsQuarantined(void* asan_pointer,
                                     const StackCapture& stack);

  // Clean up the object's metadata. The object is dead entirely, clean up the
  // metadata. This makes sure that we can decrement stack trace ref-counts and
  // reap them. This leaves the memory red-zoned (inaccessible).
  // @param asan_pointer The pointer to the ASan block.
  static void DestroyAsanBlock(void* asan_pointer);

  // Clones an object from one location to another. This mediates access to the
  // protected header and footer wrapping the user object, as the client code
  // may itself be instrumented. This will also copy the shadow memory and the
  // contents of the block: the new object will preserve the alive or free
  // status of the old object.
  // NOTES:
  // - The client must ensure there is sufficient room at the destination for
  //   the object to be cloned.
  // - If the source object is no longer needed it is up to the client to call
  //   QuarantineObject or DestroyObject.
  // - It is up to the client to ensure that the destination address meets any
  //   alignment requirements of the source object.
  // @param src_asan_pointer The pointer to the ASan source block.
  // @param dst_asan_pointer The pointer to the ASan destination block.
  static void CloneObject(const void* src_asan_pointer,
                          void* dst_asan_pointer);

 protected:
  enum BlockState {
    ALLOCATED,
    FREED,
    QUARANTINED,
  };

  // Every allocated block starts with a BlockHeader...
  struct BlockHeader {
    size_t magic_number : 16;
    size_t alignment_log : 4;
    size_t checksum : kChecksumBits;
    size_t block_size : 30;
    // This is implicitly a BlockState value.
    size_t state : 2;
    const StackCapture* alloc_stack;
    const StackCapture* free_stack;
  };
  COMPILE_ASSERT((sizeof(BlockHeader) & 7) == 0,
                 asan_block_header_not_multiple_of_8_bytes);
  COMPILE_ASSERT(sizeof(BlockHeader) == 16, asan_block_header_too_big);

  // ... and ends with a BlockTrailer.
  #pragma pack(push, 4)
  struct BlockTrailer {
    DWORD alloc_tid;
    uint64 free_timestamp;
    DWORD free_tid;
    // Free blocks are linked together.
    BlockHeader* next_free_block;
  };
  #pragma pack(pop)
  COMPILE_ASSERT(sizeof(BlockTrailer) == 20, asan_block_trailer_too_big);

  // Magic number to identify the beginning of a block header.
  static const size_t kBlockHeaderSignature = 0xCA80;

  // Sets the checksum of a block. If the block is allocated then only the
  // header and trailer are used to calculate the checksum, otherwise the data
  // is also used.
  // @param block_header The header of the block.
  // @param block_trailer The trailer of the block.
  static void SetBlockChecksum(BlockHeader* block_header,
                               const BlockTrailer* block_trailer);

  // Mark a block as quarantined. This will red-zone the user data, and save the
  // deallocation stack trace and other metadata.
  // @param block_header The header for this block.
  // @param stack The deallocation stack for this block.
  // @returns true on success, false otherwise.
  static bool MarkBlockAsQuarantined(BlockHeader* block_header,
                                     const StackCapture& stack);

  // Clean up the metadata of an ASan block.
  // @param block_header The header of the block.
  // @param block_header The trailer of the block.
  // @note This leaves the memory red-zoned.
  static void ReleaseASanBlock(BlockHeader* block_header,
                               BlockTrailer* block_trailer);

  // Returns the block header for a user pointer.
  // @param user_pointer The user pointer for which we want the block header
  //     pointer.
  // @returns A pointer to the block header of @p user_pointer on success, NULL
  //    otherwise.
  static BlockHeader* UserPointerToBlockHeader(const void* user_pointer);

  // Returns the ASan pointer for a user pointer. This should be equal to the
  // block pointer for the blocks allocated by this proxy.
  // @param user_pointer The user pointer for which we want the ASan pointer.
  // @returns A pointer to the ASan pointer of @p user_pointer on success, NULL
  //    otherwise.
  static uint8* UserPointerToAsanPointer(const void* user_pointer);

  // Returns the block header for an ASan pointer.
  // @param asan_pointer The ASan pointer for which we want the block header
  //     pointer.
  // @returns A pointer to the block header of @p asan_pointer on success, NULL
  //     otherwise.
  static BlockHeader* AsanPointerToBlockHeader(void* asan_pointer);

  // Returns the user pointer for an ASan pointer.
  // @param asan_pointer The ASan pointer for which we want the user pointer.
  // @returns A pointer to the user pointer of @p asan_pointer on success, NULL
  //    otherwise.
  static uint8* AsanPointerToUserPointer(void* asan_pointer);

  // Returns the ASan pointer for a block header.
  // @param header The block header pointer for which we want the ASan pointer.
  // @returns A pointer to the ASan pointer of @p header.
  static uint8* BlockHeaderToAsanPointer(const BlockHeader* header);

  // Returns the user pointer for a block header.
  // @param header The block header pointer for which we want the user pointer.
  // @returns A pointer to the user pointer of @p header.
  static uint8* BlockHeaderToUserPointer(BlockHeader* header);

  // Returns the block trailer for a block header.
  // @param block The block header pointer for which we want the block trailer
  //     pointer.
  // @returns A pointer to the block trailer of @p header.
  // @note This function doesn't validate its return value, it just checks that
  //     the given block header is valid and returns a pointer to the location
  //     where the trailer should be.
  static BlockTrailer* BlockHeaderToBlockTrailer(const BlockHeader* header);

  // Returns the time since the block @p header was freed (in microseconds).
  // @param header The block for which we want the time since free.
  static uint64 GetTimeSinceFree(const BlockHeader* header);

  // Give the type of a bad heap access corresponding to an address.
  // @param addr The address causing a bad heap access.
  // @param header The header of the block containing this address.
  // @returns The type of the bad heap access corresponding to this address.
  static BadAccessKind GetBadAccessKind(const void* addr, BlockHeader* header);

  // Get the information about an address relative to a block.
  // @param header The header of the block containing this address.
  // @param bad_access_info Will receive the information about this address.
  static void GetAddressInformation(BlockHeader* header,
                                    AsanErrorInfo* bad_access_info);

  // Find the memory block containing @p addr.
  // @param addr The address for which we want to find the containing block.
  // @note |addr| may be in the header or trailer of the block, not strictly
  //     within its data.
  // @returns a pointer to this memory block in case of success, NULL otherwise.
  static BlockHeader* FindBlockContainingAddress(uint8* addr);

  // Find the memory block containing the block @p inner_block.
  // @param inner_block The block for which we want to find the containing
  //     block.
  // @returns a pointer to this memory block in case of success, NULL otherwise.
  static BlockHeader* FindContainingBlock(BlockHeader* inner_block);

  // Find the freed memory block containing the block @p inner_block.
  // @param inner_block The block for which we want to find the containing
  //     freed block.
  // @returns a pointer to this memory block in case of success, NULL otherwise.
  static BlockHeader* FindContainingFreedBlock(BlockHeader* inner_block);

  // Quarantines @p block and trims the quarantine if it has grown too big.
  // @param block The block to quarantine.
  void QuarantineBlock(BlockHeader* block);

  // If the quarantine size is over quarantine_max_size_, trim it down until
  // it's below the limit.
  void TrimQuarantine();

  // Arbitrarily keep 16 megabytes of quarantine per heap by default.
  static const size_t kDefaultQuarantineMaxSize = 16 * 1024 * 1024;

  // By default we use no additional padding between heap blocks, beyond the
  // header and footer.
  static const size_t kDefaultTrailerPaddingSize = 0;

  // The default alloc granularity. The Windows heap is 8-byte granular, so
  // there's no gain in a lower allocation granularity.
  static const size_t kDefaultAllocGranularity = 8;
  static const uint16 kDefaultAllocGranularityLog = 3;

  // Default max size of blocks in quarantine (in bytes).
  static size_t default_quarantine_max_size_;

  // The size of the padding that we append to every block (in bytes). Defaults
  // to zero.
  static size_t trailer_padding_size_;

  // The number of CPU cycles per microsecond on the current machine.
  static double cpu_cycles_per_us_;

  // The underlying heap we delegate to.
  HANDLE heap_;

  // Indicates if we own the underlying heap.
  bool owns_heap_;

  // A repository of unique stack captures recorded on alloc and free.
  // @note This variable is declared as static to improve the stack cache
  //     compression for the process with several heap.
  static StackCaptureCache* stack_cache_;

  // Protects concurrent access to HeapProxy internals.
  base::Lock lock_;

  // Points to the head of the quarantine queue.
  BlockHeader* head_;  // Under lock_.

  // Points to the tail of the quarantine queue.
  BlockHeader* tail_;  // Under lock_.

  // Total size of blocks in quarantine.
  size_t quarantine_size_;  // Under lock_.

  // Max size of blocks in quarantine.
  size_t quarantine_max_size_;  // Under lock_.

  // The entry linking to us.
  LIST_ENTRY list_entry_;
};

}  // namespace asan
}  // namespace agent

#endif  // SYZYGY_AGENT_ASAN_ASAN_HEAP_H_
