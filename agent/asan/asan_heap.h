// Copyright 2012 Google Inc.
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

 private:
  // Every allocated block starts with a BlockHeader.
  struct BlockHeader {
    size_t size;
  };

  // Free blocks are linked together.
  struct FreeBlockHeader : public BlockHeader {
    FreeBlockHeader* next;
  };

  // Quarantines @p block and flushes quarantine overage.
  void QuarantineBlock(BlockHeader* block);

  // Calculates the underlying allocation size for a requested
  // allocation of @p bytes.
  static size_t GetAllocSize(size_t bytes);

  // Returns the block header for an alloc.
  static BlockHeader* ToBlock(const void* alloc);

  // Returns alloc for a block.
  static uint8* ToAlloc(BlockHeader* block);

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
