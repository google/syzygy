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
// SyzyAsan overhead is roughly 45% overall, with 25% coming from memory
// allocation overhead (20 + 16 = 36 bytes of overhead for average allocation
// sizes of 144 bytes in Chrome). If we wish to maintain a similar overhead
// then allocations being fed into the large block heap should be at least
// 32KB in size. Ideally the large allocation heap should not be leaned on too
// heavily as it can cause significant memory fragmentation.

#ifndef SYZYGY_AGENT_ASAN_HEAPS_LARGE_BLOCK_HEAP_H_
#define SYZYGY_AGENT_ASAN_HEAPS_LARGE_BLOCK_HEAP_H_

#include <unordered_set>

#include "syzygy/agent/asan/allocators.h"
#include "syzygy/agent/asan/heap.h"
#include "syzygy/common/recursive_lock.h"

namespace agent {
namespace asan {

class MemoryNotifierInterface;

namespace heaps {

class LargeBlockHeap : public BlockHeapInterface {
 public:
  // Constructor.
  // @param memory_notifier The memory notifier to use.
  // @param internal_heap The heap to use for making internal allocations.
  LargeBlockHeap(MemoryNotifierInterface* memory_notifier,
                 HeapInterface* internal_heap);

  // Virtual destructor.
  virtual ~LargeBlockHeap();

  // @name HeapInterface implementation.
  // @{
  virtual HeapType GetHeapType() const;
  virtual uint32_t GetHeapFeatures() const;
  virtual void* Allocate(uint32_t bytes);
  virtual bool Free(void* alloc);
  virtual bool IsAllocated(const void* alloc);
  virtual uint32_t GetAllocationSize(const void* alloc);
  virtual void Lock();
  virtual void Unlock();
  virtual bool TryLock();
  // @}

  // @name BlockHeapInterface implementation.
  // @{
  virtual void* AllocateBlock(uint32_t size,
                              uint32_t min_left_redzone_size,
                              uint32_t min_right_redzone_size,
                              BlockLayout* layout);
  virtual bool FreeBlock(const BlockInfo& block_info);
  // @}

  // @returns the number of active allocations in this heap.
  size_t size() const { return allocs_.size(); }

 protected:
  // Information about an allocation made by this allocator.
  struct Allocation {
    const void* address;
    uint32_t size;
  };

  // Calculates a hash of an Allocation object by forwarding to the STL
  // hash for the allocation address.
  struct AllocationHash {
    size_t operator()(const Allocation& allocation) const {
      std::hash<const void*> hash;
      return hash(allocation.address);
    }
  };

  // Functor for determining if 2 allocation objects are identical. This only
  // uses the allocation address as a key.
  struct AllocationEqualTo {
    bool operator()(const Allocation& a1, const Allocation& a2) const {
      return a1.address == a2.address;
    }
  };

  // The collection of allocations that has been made through this allocator.
  // It is expected that a small number of allocations will be made, so keeping
  // track of these explicitly is fine for now.
  typedef std::unordered_set<
      Allocation,
      AllocationHash,
      AllocationEqualTo,
      HeapAllocator<Allocation>> AllocationSet;
  AllocationSet allocs_;  // Under lock_.

  // Free all the allocations owned by this heap.
  void FreeAllAllocations();

  // The global lock for this allocator.
  ::common::RecursiveLock lock_;

  // The memory notifier in use.
  MemoryNotifierInterface* memory_notifier_;

 private:
  DISALLOW_COPY_AND_ASSIGN(LargeBlockHeap);
};

}  // namespace heaps
}  // namespace asan
}  // namespace agent

#endif  // SYZYGY_AGENT_ASAN_HEAPS_LARGE_BLOCK_HEAP_H_
