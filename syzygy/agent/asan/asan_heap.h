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

#include "base/callback.h"
#include "base/logging.h"
#include "base/string_piece.h"
#include "base/debug/stack_trace.h"
#include "base/synchronization/lock.h"
#include "syzygy/agent/asan/block_utils.h"
#include "syzygy/agent/asan/error_info.h"
#include "syzygy/agent/asan/shadow.h"
#include "syzygy/agent/asan/stack_capture_cache.h"
#include "syzygy/agent/asan/quarantines/sharded_quarantine.h"
#include "syzygy/agent/common/dlist.h"

namespace agent {
namespace asan {

// Forward declaration.
class StackCapture;
class StackCaptureCache;
struct AsanErrorInfo;
struct AsanBlockInfo;

// Defines a heap slab, which represents a contiguous range of memory containing
// one or more allocations made by a single allocator.
struct HeapSlab {
  const uint8* address;
  size_t length;
};

// Makes like a Win32 heap manager heap, but adds a redzone before and after
// each allocation and maintains a quarantine list of freed blocks.
class HeapProxy {
 public:
  // This callback allows the heap to report heap consistency problems that it
  // encounters during its operation. This is usually plumbed into the ASAN
  // runtime so that the errors may be appropriately reported.
  // TODO(chrisha|sebmarchand): Add a mechanism to walk the entire heap and get
  //     additional information on other potentially corrupt blocks.
  // |asan_error_info| contains information about the primary heap error that
  //     was encountered. It is guaranteed to be on the stack.
  typedef base::Callback<void(AsanErrorInfo* asan_error_info)>
      HeapErrorCallback;

  // A vector of heap slabs.
  typedef std::vector<HeapSlab> HeapSlabVector;

  // The sleep time (in milliseconds) used to approximate the CPU frequency.
  // Exposed for testing.
  static const size_t kSleepTimeForApproximatingCPUFrequency = 100;

  HeapProxy();
  ~HeapProxy();

  // @name Cast to/from HANDLE.
  // @{
  static HANDLE ToHandle(HeapProxy* proxy);
  static HeapProxy* FromHandle(HANDLE heap);
  // @}

  // @name Cast to/from HANDLE.
  // @{
  static LIST_ENTRY* ToListEntry(HeapProxy* proxy);
  static HeapProxy* FromListEntry(LIST_ENTRY* list_entry);
  // @}

  // Set the default max size of the quarantine of a heap proxy. This value is
  // used when constructing a new heap proxy. This will cap the current
  // default_quarantine_max_block_size, so be sure to set the value after.
  // @param default_quarantine_max_size The maximum size of the quarantine list,
  //     in bytes.
  static void set_default_quarantine_max_size(
      size_t default_quarantine_max_size);

  // @returns the default max size of the quarantine of a heap proxy.
  static size_t default_quarantine_max_size() {
    return default_quarantine_max_size_;
  }

  // Set the default max size of a block to be accepted in the quarantine of a
  // heap proxy. This value is used when constructing a new heap proxy. The
  // value that is set will be capped by the currently active
  // default_quarantine_max_size, so set that value first!
  // @param default_quarantine_max_block_size The maximum size of a block that
  //     will be accepted into the quarantine of a heap proxy, in bytes.
  static void set_default_quarantine_max_block_size(
      size_t default_quarantine_max_block_size);

  // @returns the default max size of a block to be accepted in the quarantine
  //     of a heap proxy.
  static size_t default_quarantine_max_block_size() {
    return default_quarantine_max_block_size_;
  }

  // Set the max size of the quarantine of a heap proxy. If the current size of
  // the quarantine is greater than this new max size then the extra blocks are
  // removed from the quarantine.
  // @param quarantine_size The maximum size of the quarantine list, in
  //     bytes.
  // @note This function acquires lock_.
  void SetQuarantineMaxSize(size_t quarantine_max_size);

  // Get the max size of the quarantine of a heap proxy.
  size_t quarantine_max_size() {
    return quarantine_.max_quarantine_size();
  }

  // Sets the maximum size of blocks to be accepted in the quarantine. Does not
  // removed blocks exceeding this size, but will prevent future ones from being
  // accepted.
  // @param quarantine_max_block_size The maximum size of a block that will be
  //     accepted into the quarantine. This will be capped at
  //     quarantine_max_size.
  // @note This function acquires lock_.
  void SetQuarantineMaxBlockSize(size_t quarantine_max_block_size);

  // Returns the current max size of a block that will be accepted into the
  // quarantine.
  size_t quarantine_max_block_size() {
    return quarantine_.max_object_size();
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

  // Sets the allocation guard rate.
  // @param allocation_guard_rate The allocation guard rate, as a value between
  //     0 and 1, inclusive.
  static void set_allocation_guard_rate(float allocation_guard_rate) {
    DCHECK_LE(0.0f, allocation_guard_rate);
    DCHECK_GE(1.0f, allocation_guard_rate);
    allocation_guard_rate_ = allocation_guard_rate;
  }

  // @returns the allocation guard rate.
  static float allocation_guard_rate() { return allocation_guard_rate_; }

  // Static initialization of HeapProxy context.
  // @param cache The stack capture cache shared by the HeapProxy.
  static void Init(StackCaptureCache* cache);

  // Calculates the underlying allocation size for a requested allocation of
  // @p bytes, with an alignment of @p alignment bytes.
  static size_t GetAllocSize(size_t bytes, size_t alignment);

  // Initialize an ASan block. This will red-zone the header and trailer, green
  // zone the user data, and save the allocation stack trace and other metadata.
  // @param asan_pointer The ASan block to initialize.
  // @param user_size The user size for this block.
  // @param alloc_granularity_log The allocation granularity for this block.
  // @param is_nested Indicates if the block is nested.
  // @param stack The allocation stack capture for this block.
  // @returns The user pointer for this block on success, NULL otherwise.
  static void* InitializeAsanBlock(uint8* asan_pointer,
                                   size_t user_size,
                                   size_t alloc_granularity_log,
                                   bool is_nested,
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

  // Sets the callback that this heap will invoke when heap corruption is
  // encountered.
  // @param heap_error_callback The callback to be invoked when heap
  //     corruption is encountered.
  void SetHeapErrorCallback(
      HeapErrorCallback heap_error_callback) {
    heap_error_callback_ = heap_error_callback;
  }
  void ClearHeapErrorCallback() {
    heap_error_callback_.Reset();
  }

 protected:
  // Defines the type of quarantine that we'll use.
  typedef quarantines::ShardedQuarantine<BlockHeader*,
                                         GetTotalBlockSizeFunctor,
                                         GetBlockHashFunctor,
                                         kQuarantineDefaultShardingFactor>
      AsanShardedQuarantine;

  // Mark a block as quarantined. This will red-zone the user data, and save the
  // deallocation stack trace and other metadata.
  // @param block_header The header for this block.
  // @param stack The deallocation stack for this block.
  // @returns true on success, false otherwise.
  static bool MarkBlockAsQuarantined(BlockHeader* block_header,
                                     const StackCapture& stack);

  // Clean up the metadata of an ASan block.
  // @param block_header The header of the block.
  // @note This leaves the memory red-zoned.
  static void ReleaseAsanBlock(BlockHeader* block_header);

  // Quarantines @p block and trims the quarantine if it has grown too big.
  // @param block The block to quarantine.
  void QuarantineBlock(const BlockInfo& block);

  // If the quarantine size is over quarantine_max_size_, trim it down until
  // it's below the limit. Can potentially cause heap errors to be reported if
  // the underlying book-keeping detects problems.
  // @returns true on success, false otherwise.
  bool TrimQuarantine();

  // Free a block that has been popped from the quarantine. This reports a heap
  // error if the block has been corrupt while in the quarantine.
  // @param block The block to be freed.
  // @returns true if the block has been successfully freed, false otherwise.
  bool FreeQuarantinedBlock(BlockHeader* block);

  // Free a corrupt memory block. This clears its metadata (including the shadow
  // memory) and calls ::HeapFree on it.
  // @param header The ASan block header for the block to be freed.
  // @param user_pointer The user pointer for the block to be freed.
  // @param alloc_size If non-NULL will be populated with the allocation size as
  //     calculated by looking at the shadow memory.
  // @returns true on success, false otherwise.
  bool FreeCorruptBlock(BlockHeader* header, size_t* alloc_size);
  bool FreeCorruptBlock(void* user_pointer, size_t* alloc_size);

  // Cleanup a block's metadata and free it.
  // @param block_header The block header.
  // @param alloc_size The underlying allocation size for this block.
  // @returns true on success, false otherwise.
  bool CleanUpAndFreeAsanBlock(BlockHeader* block_header, size_t alloc_size);

  // Reports a heap error via the heap error callback. This is for originating
  // errors that are detected while performing operations on the heap metadata.
  // Read/write errors are detected outside of the HeapProxy, and query the heap
  // for information about the error itself.
  // @param address The address that was being accessed/manipulating when the
  //     error was detected.
  // @param kind The type of error encountered.
  void ReportHeapError(void* address, BadAccessKind kind);

  // The default alloc granularity.
  static const size_t kDefaultAllocGranularity = kShadowRatio;
  static const uint16 kDefaultAllocGranularityLog = kShadowRatioLog;

  // Default max size of a quarantine, and any block within it (in bytes).
  static size_t default_quarantine_max_size_;
  static size_t default_quarantine_max_block_size_;

  // The size of the padding that we append to every block (in bytes). Defaults
  // to zero.
  static size_t trailer_padding_size_;

  // The rate at which allocations are intercepted and augmented with
  // headers/footers.
  static float allocation_guard_rate_;

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

  // The entry linking to us.
  LIST_ENTRY list_entry_;

  // The callback this heap uses to expose internal state errors. These are
  // caused by uninstrumented code (system libraries, etc), thus aren't caught
  // at their source. Catching their side effect as early as possible allows the
  // recovery of some useful debugging information.
  HeapErrorCallback heap_error_callback_;

  // The quarantine that will be used by this heap.
  AsanShardedQuarantine quarantine_;
};

// Utility class which implements an auto lock for a HeapProxy.
// TODO(sebmarchand): Move this to an asan_heap_util.[h|cc] set of files.
class HeapLocker {
 public:
  explicit HeapLocker(HeapProxy* const heap);

  ~HeapLocker();

 private:
  HeapProxy* const heap_;

  DISALLOW_COPY_AND_ASSIGN(HeapLocker);
};

}  // namespace asan
}  // namespace agent

#endif  // SYZYGY_AGENT_ASAN_ASAN_HEAP_H_
