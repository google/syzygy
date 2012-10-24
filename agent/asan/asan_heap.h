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

#include <windows.h>

#include "base/synchronization/lock.h"

namespace agent {
namespace asan {

// Makes like a Win32 heap manager heap, but adds a redzone before and after
// each allocation and maintains a quarantine list of freed blocks.
class HeapProxy {
 public:
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
  // @returns true if the address belongs to a memory block, false otherwise.
  bool OnBadAccess(const uint8* addr);

  // Report an unknown error while attempting the red-zoned heap address @addr.
  static void ReportUnknownError(const uint8* addr);

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
  // TODO(sebmarchand): Add field for stack trace etc.
  struct BlockHeader {
    size_t magic_number;
    size_t size;
    BlockState state;
  };

  // Returns the block header for an alloc.
  BlockHeader* ToBlock(const void* alloc);

  // Returns alloc for a block.
  uint8* ToAlloc(BlockHeader* block);

  // Find the memory block containing @p addr.
  // @returns a pointer to this memory block in case of success, NULL otherwise.
  BlockHeader* FindAddressBlock(const uint8* addr);

  // Give the type of a bad heap access corresponding to an address.
  // @param addr The address causing a bad heap access.
  // @param header The header of the block containing this address.
  BadAccessKind GetBadAccessKind(const uint8* addr, BlockHeader* header);

 private:
  // Magic number to identify the beginning of a block header.
  static const size_t kBlockHeaderSignature = 0x03CA80E7;

  // Free blocks are linked together.
  struct FreeBlockHeader : public BlockHeader {
    FreeBlockHeader* next;
  };

  // Returns a string describing a bad access kind.
  static char* AccessTypeToStr(BadAccessKind bad_access_kind);

  // Quarantines @p block and flushes quarantine overage.
  void QuarantineBlock(BlockHeader* block);

  // Calculates the underlying allocation size for a requested
  // allocation of @p bytes.
  static size_t GetAllocSize(size_t bytes);

  // Print the information about an address belonging to a memory block. This
  // function will print the relative position of this address inside a block
  // and the bounds of this block.
  // @param addr The address for which we want information.
  // @param header The block containing the address.
  // @param bad_access_kind The kind of bad access corresponding to this
  //     address.
  void PrintAddressInformation(const uint8* addr,
                               BlockHeader* header,
                               BadAccessKind bad_access_kind);

  // Report a basic Asan error to stderr. This function just dump the stack
  // without providing information relative to the shadow memory.
  // @param bug_descr The description of the error.
  // @param addr The address causing an error.
  // @param bad_access_kind The kind of error.
  static void ReportAsanErrorBase(const char* bug_descr,
                                  const uint8* addr,
                                  BadAccessKind bad_access_kind);

  // Report an Asan error to stderr with information about the address causing
  // this error.
  // @param bug_descr The description of the error.
  // @param addr The address causing an error.
  // @param bad_access_kind The kind of error.
  // @param header The header of the block containing this address.
  void ReportAsanError(const char* bug_descr,
                       const uint8* addr,
                       BadAccessKind bad_access_kind,
                       BlockHeader* header);

  // Contains the underlying heap we delegate to.
  HANDLE heap_;

  base::Lock lock_;
  // Points to the head of the quarantine queue.
  FreeBlockHeader* head_;  // Under lock_.
  // Points to the tail of the quarantine queue.
  FreeBlockHeader* tail_;  // Under lock_.
  // Total size of blocks in quarantine.
  size_t quarantine_size_;  // Under lock_.
};

}  // namespace asan
}  // namespace agent

#endif  // SYZYGY_AGENT_ASAN_ASAN_HEAP_H_
