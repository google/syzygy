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
// Declares LargeBlockHeap, a heap that directly grabs pages of memory from the
// OS and redzones blocks with entire pages. This is only intended for use with
// sufficiently large allocations (hence the name) where the redzone overhead
// can be amortized.
//
// SyzyASan overhead is roughly 45% overall, with 25% coming from memory
// allocation overhead (20 + 16 = 36 bytes of overhead for average allocation
// sizes of 144 bytes in Chrome). If we wish to maintain a similar overhead
// then allocations being fed into the large block heap should be at least
// 32KB in size. Ideally the large allocation heap should not be leaned on too
// heavily as it can cause significant memory fragmentation.

#ifndef SYZYGY_AGENT_ASAN_HEAPS_LARGE_BLOCK_HEAP_H_
#define SYZYGY_AGENT_ASAN_HEAPS_LARGE_BLOCK_HEAP_H_

#include <unordered_set>

#include "syzygy/agent/asan/heap.h"
#include "syzygy/agent/asan/memory_notifier.h"
#include "syzygy/common/recursive_lock.h"

namespace agent {
namespace asan {
namespace heaps {

class LargeBlockHeap : public BlockHeapInterface {
 public:
  // Constructor.
  explicit LargeBlockHeap(MemoryNotifierInterface* memory_notifier);

  // Virtual destructor.
  virtual ~LargeBlockHeap() { }

  // @name HeapInterface implementation.
  // @{
  virtual uint32 GetHeapFeatures() const;
  virtual void* Allocate(size_t bytes);
  virtual bool Free(void* alloc);
  virtual bool IsAllocated(void* alloc);
  virtual void Lock();
  virtual void Unlock();
  // @}

  // @name BlockHeapInterface implementation.
  // @{
  virtual void* AllocateBlock(size_t size,
                              size_t min_left_redzone_size,
                              size_t min_right_redzone_size,
                              BlockLayout* layout);
  virtual bool FreeBlock(const BlockInfo& block_info);
  // @}

  // @returns the number of active allocations in this heap.
  size_t size() const { return allocs_.size(); }

 protected:
  // The collection of allocations that has been made through this allocator.
  // It is expected that a small number of allocations will be made, so keeping
  // track of these explicitly is fine for now.
  typedef std::unordered_set<
      void*,
      std::hash<void*>,
      std::equal_to<void*>,
      MemoryNotifierAllocator<void*>> AllocationSet;
  AllocationSet allocs_;  // Under lock_.

  // The global lock for this allocator.
  common::RecursiveLock lock_;

 private:
  DISALLOW_COPY_AND_ASSIGN(LargeBlockHeap);
};

}  // namespace heaps
}  // namespace asan
}  // namespace agent

#endif  // SYZYGY_AGENT_ASAN_HEAPS_LARGE_BLOCK_HEAP_H_
