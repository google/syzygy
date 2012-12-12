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

#include "base/string_piece.h"
#include "base/debug/stack_trace.h"
#include "base/synchronization/lock.h"
#include "syzygy/agent/common/dlist.h"

namespace agent {
namespace asan {

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

  // Report a bad access to the heap.
  // @param addr The red-zoned address causing a bad access.
  // @param access_mode The kind of the access (read or write).
  // @param access_size The size of the access (in bytes).
  // @returns true if the address belongs to a memory block, false otherwise.
  bool OnBadAccess(const void* addr,
                   AccessMode access_mode,
                   size_t access_size);

  // Report an unknown error while attempting to access a red-zoned heap
  // address.
  // @param addr The address causing an error.
  // @param access_mode The kind of the access (read or write).
  // @param access_size The size of the access (in bytes).
  static void ReportUnknownError(const void* addr,
                                 AccessMode access_mode,
                                 size_t access_size);

  // @name Cast to/from HANDLE.
  // @{
  static LIST_ENTRY* ToListEntry(HeapProxy* proxy);
  static HeapProxy* FromListEntry(LIST_ENTRY* list_entry);
  // @}

  // Set the max size of the quarantine of a heap proxy.
  // @param quarantine_max_size The maximum size of the quarantine list, in
  //     bytes.
  static void SetQuarantineMaxSize(size_t quarantine_max_size) {
    quarantine_max_size_ = quarantine_max_size;
  }

  // Get the max size of the quarantine of a heap proxy.
  static size_t GetQuarantineMaxSize() { return quarantine_max_size_; }

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

    // This enum value should always be last.
    MAX_STATE,
  };

  // Every allocated block starts with a BlockHeader.
  struct BlockHeader {
    size_t magic_number;
    size_t size;
    BlockState state;
    void* alloc_stack_trace;
    void* free_stack_trace;
    uint8 alloc_stack_trace_size;
    uint8 free_stack_trace_size;
  };

  // Default value for the quarantine size.
  static const size_t kDefaultQuarantineSize;

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

  // Max size of blocks in quarantine (in bytes).
  static size_t quarantine_max_size_;
 private:
  // Magic number to identify the beginning of a block header.
  static const size_t kBlockHeaderSignature = 0x03CA80E7;

  // Free blocks are linked together.
  struct FreeBlockHeader : public BlockHeader {
    FreeBlockHeader* next;
  };

  // Returns a string describing a bad access kind.
  static const char* AccessTypeToStr(BadAccessKind bad_access_kind);

  // Quarantines @p block and flushes quarantine overage.
  void QuarantineBlock(BlockHeader* block);

  // Free and remove the first block of the quarantine.
  void PopQuarantine();

  // Calculates the underlying allocation size for a requested
  // allocation of @p bytes.
  static size_t GetAllocSize(size_t bytes);

  // Get the information about an address belonging to a memory block. This
  // function will output the relative position of this address inside a block
  // and the bounds of this block.
  // @param addr The address for which we want information.
  // @param header The block containing the address.
  // @param bad_access_kind The kind of bad access corresponding to this
  //     address.
  // @param output The textual output will be returned here.
  void GetAddressInformation(const void* addr,
                             BlockHeader* header,
                             BadAccessKind bad_access_kind,
                             std::string* output);

  // Low-level ASAN reporting function. This function dumps the stack,
  // optionally including an extra (free-form) description of the address
  // being accessed when the error occurred.
  // @param bug_descr The description of the error.
  // @param addr The address causing an error.
  // @param addr_info A (possibly empty) string describing @p addr.
  // @param bad_access_kind The kind of error.
  // @param access_mode The mode of the access (read or write).
  // @param access_size The size of the access (in bytes).
  static void ReportAsanErrorBase(const char* bug_descr,
                                  const void* addr,
                                  const base::StringPiece& addr_info,
                                  BadAccessKind bad_access_kind,
                                  AccessMode access_mode,
                                  size_t access_size);

  // Report an ASAN error, automatically including information about the
  // address being accessed when the error occurred.
  // @param bug_descr The description of the error.
  // @param addr The address causing an error.
  // @param bad_access_kind The kind of error.
  // @param header The header of the block containing this address.
  // @param access_mode The kind of the access (read or write).
  // @param access_size The size of the access (in bytes).
  void ReportAsanError(const char* bug_descr,
                       const void* addr,
                       BadAccessKind bad_access_kind,
                       BlockHeader* header,
                       AccessMode access_mode,
                       size_t access_size);

  // Contains the underlying heap we delegate to.
  HANDLE heap_;

  base::Lock lock_;
  // Points to the head of the quarantine queue.
  FreeBlockHeader* head_;  // Under lock_.
  // Points to the tail of the quarantine queue.
  FreeBlockHeader* tail_;  // Under lock_.
  // Total size of blocks in quarantine.
  size_t quarantine_size_;  // Under lock_.

  // The entry linking to us.
  LIST_ENTRY list_entry_;
};

}  // namespace asan
}  // namespace agent

#endif  // SYZYGY_AGENT_ASAN_ASAN_HEAP_H_
