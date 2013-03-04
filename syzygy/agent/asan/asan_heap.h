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
class AsanLogger;
class StackCapture;
class StackCaptureCache;

// An helper function to send a command to Windbg. Windbg should first receive
// the ".ocommand ASAN" command to treat those messages as commands.
// TODO(sebmarchand): Move this function and the following one to the
//     AsanRuntime class once it's ready.
void ASANDbgCmd(const wchar_t* fmt, ...);

// An helper function to print a message to Windbg's console.
void ASANDbgMessage(const wchar_t* fmt, ...);

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

  HeapProxy(StackCaptureCache* cache, AsanLogger* logger);
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

  // Report a bad access to the heap.
  // @param addr The red-zoned address causing a bad access.
  // @param context The context at which the access occurred.
  // @param stack The stack capture at the point of error.
  // @param access_mode The kind of the access (read or write).
  // @param access_size The size of the access (in bytes).
  // @returns true if the address belongs to a memory block, false otherwise.
  bool OnBadAccess(const void* addr,
                   const CONTEXT& context,
                   const StackCapture& stack,
                   AccessMode access_mode,
                   size_t access_size);

  // Report an unknown error while attempting to access a red-zoned heap
  // address.
  // @param addr The address causing an error.
  // @param context The context at which the access occurred.
  // @param stack The stack capture at the point of error.
  // @param access_mode The kind of the access (read or write).
  // @param access_size The size of the access (in bytes).
  void ReportUnknownError(const void* addr,
                          const CONTEXT& context,
                          const StackCapture& stack,
                          AccessMode access_mode,
                          size_t access_size);

  // @name Cast to/from HANDLE.
  // @{
  static LIST_ENTRY* ToListEntry(HeapProxy* proxy);
  static HeapProxy* FromListEntry(LIST_ENTRY* list_entry);
  // @}

  // Set the default max size of the quarantine of a heap proxy.
  // @param quarantine_max_size The maximum size of the quarantine list, in
  //     bytes.
  static void set_default_quarantine_max_size(size_t quarantine_max_size) {
    default_quarantine_max_size_ = quarantine_max_size;
  }

  // Get the default max size of the quarantine of a heap proxy.
  static size_t default_quarantine_max_size() {
    return default_quarantine_max_size_;
  }

  // Set the max size of the quarantine of a heap proxy. If the current size of
  // the quarantine is greater than this new max size then the extra blocks are
  // removed from the quarantine.
  // @param quarantine_max_size The maximum size of the quarantine list, in
  //     bytes.
  void set_quarantine_max_size(size_t quarantine_max_size);

  // Get the max size of the quarantine of a heap proxy.
  size_t quarantine_max_size() {
    return quarantine_max_size_;
  }

 protected:
  // Enumeration of the different kind of bad heap access that we can encounter.
  enum BadAccessKind {
    UNKNOWN_BAD_ACCESS,
    USE_AFTER_FREE,
    HEAP_BUFFER_OVERFLOW,
    HEAP_BUFFER_UNDERFLOW,
  };

  enum BlockState {
    ALLOCATED,
    FREED,
    QUARANTINED,
  };

  // Every allocated block starts with a BlockHeader.
  struct BlockHeader {
    size_t magic_number;
    size_t size;
    BlockState state;
    const StackCapture* alloc_stack;
    const StackCapture* free_stack;
  };

  // Free blocks are linked together.
  struct FreeBlockHeader : public BlockHeader {
    FreeBlockHeader* next;
  };

  // Magic number to identify the beginning of a block header.
  static const size_t kBlockHeaderSignature = 0x03CA80E7;

  // Returns a string describing a bad access kind.
  static const char* AccessTypeToStr(BadAccessKind bad_access_kind);

  // Returns the block header for an alloc.
  BlockHeader* ToBlock(const void* alloc);

  // Returns alloc for a block.
  uint8* ToAlloc(BlockHeader* block);

  // Find the memory block containing @p addr.
  // @returns a pointer to this memory block in case of success, NULL otherwise.
  BlockHeader* FindAddressBlock(const void* addr);

  // Give the type of a bad heap access corresponding to an address.
  // @param addr The address causing a bad heap access.
  // @param header The header of the block containing this address.
  BadAccessKind GetBadAccessKind(const void* addr, BlockHeader* header);

  // Calculates the underlying allocation size for a requested
  // allocation of @p bytes.
  static size_t GetAllocSize(size_t bytes);

  // Quarantines @p block and flushes quarantine overage.
  void QuarantineBlock(BlockHeader* block);

  // Free and remove the first block of the quarantine. lock_ must be held.
  void PopQuarantineUnlocked();

  // Get the information about an address belonging to a memory block. This
  // function will output the relative position of this address inside a block
  // and the bounds of this block.
  // @param addr The address for which we want information.
  // @param header The block containing the address.
  // @param bad_access_kind The kind of bad access corresponding to this
  //     address.
  void ReportAddressInformation(const void* addr,
                                BlockHeader* header,
                                BadAccessKind bad_access_kind);

  // Low-level ASAN reporting function. This function dumps the stack,
  // optionally including an extra (free-form) description of the address
  // being accessed when the error occurred.
  // @param bug_descr The description of the error.
  // @param addr The address causing an error.
  // @param context The context at which the access occurred.
  // @param stack The stack capture at the point of error.
  // @param bad_access_kind The kind of error.
  // @param access_mode The mode of the access (read or write).
  // @param access_size The size of the access (in bytes).
  void ReportAsanErrorBase(const char* bug_descr,
                           const void* addr,
                           const CONTEXT& context,
                           const StackCapture& stack,
                           BadAccessKind bad_access_kind,
                           AccessMode access_mode,
                           size_t access_size);

  // Report an ASAN error, automatically including information about the
  // address being accessed when the error occurred.
  // @param bug_descr The description of the error.
  // @param addr The address causing an error.
  // @param context The context at which the access occurred.
  // @param stack The stack capture at the point of error.
  // @param bad_access_kind The kind of error.
  // @param header The header of the block containing this address.
  // @param access_mode The kind of the access (read or write).
  // @param access_size The size of the access (in bytes).
  void ReportAsanError(const char* bug_descr,
                       const void* addr,
                       const CONTEXT& context,
                       const StackCapture& stack,
                       BadAccessKind bad_access_kind,
                       BlockHeader* header,
                       AccessMode access_mode,
                       size_t access_size);

  // Default max size of blocks in quarantine (in bytes).
  static size_t default_quarantine_max_size_;

  // The underlying heap we delegate to.
  HANDLE heap_;

  // A repository of unique stack captures recorded on alloc and free.
  StackCaptureCache* const stack_cache_;

  // The logger to use when an error occurs.
  AsanLogger* const logger_;

  // Protects concurrent access to HeapProxy internals.
  base::Lock lock_;

  // Points to the head of the quarantine queue.
  FreeBlockHeader* head_;  // Under lock_.

  // Points to the tail of the quarantine queue.
  FreeBlockHeader* tail_;  // Under lock_.

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
