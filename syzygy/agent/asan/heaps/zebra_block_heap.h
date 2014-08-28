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
// An implementation of HeapInterface which ensures that the end of memory
// allocations is aligned to the system page size and followed by an empty
// page.

#ifndef SYZYGY_AGENT_ASAN_HEAPS_ZEBRA_BLOCK_HEAP_H_
#define SYZYGY_AGENT_ASAN_HEAPS_ZEBRA_BLOCK_HEAP_H_

#include <windows.h>

#include <list>
#include <queue>
#include <vector>

#include "base/logging.h"
#include "syzygy/agent/asan/allocators.h"
#include "syzygy/agent/asan/circular_queue.h"
#include "syzygy/agent/asan/constants.h"
#include "syzygy/agent/asan/heap.h"
#include "syzygy/agent/asan/memory_notifier.h"
#include "syzygy/agent/asan/quarantine.h"
#include "syzygy/common/recursive_lock.h"

namespace agent {
namespace asan {
namespace heaps {

// A zebra-stripe heap allocates a (maximum) predefined amount of memory
// and serves allocation requests with size less than or equal to the system
// page size.
// It divides the memory into 'slabs'; each slab consist of an 'even' page
// followed by an 'odd' page (like zebra-stripes).
//
//                             |-----------slab 1----------|
// +-------------+-------------+-------------+-------------+------------- - -+
// |even 4k page | odd 4k page |even 4k page | odd 4k page |             ... |
// +-------------+-------------+-------------+-------------+------------- - -+
// |-----------slab 0----------|                           |---slab 2---- - -|
//
// All the allocations are done in the even pages, just before the odd pages.
// The odd pages can be protected againt read/write which gives a basic
// mechanism for detecting buffer overflows.
//
// A block allocation starts with the block header and ends with the block
// trailer. The body is completely contained in the even page and pushed to the
// right, but since the body must be kShadowRatio-aligned there could be a
// small gap between the body and the odd page which is covered by the trailer
// padding. Both paddings fill the rest of the pages.
//
//          |-header-padding-|      |-------trailer-padding------|
// +--------+----------------+------+--+-------------------------+---------+
// |         even 4k page              |          odd 4k page              |
// +--------+----------------+------+--+-------------------------+---------+
// |-header-|                |-body-|                            |-trailer-|
//
// Calling Free on a quarantined address is an invalid operation.
class ZebraBlockHeap : public BlockHeapInterface,
                       public BlockQuarantineInterface {
 public:
  // The size of a 2-page slab (2 * kPageSize).
  static const size_t kSlabSize;

  // Constructor.
  // @param heap_size The amount of memory reserved by the heap in bytes.
  // @param memory_notifier The MemoryNotifierInterface used to report
  //     allocation information.
  ZebraBlockHeap(size_t heap_size,
                 MemoryNotifierInterface* memory_notifier);

  // Virtual destructor. Frees all the allocated memory.
  virtual ~ZebraBlockHeap();

  // @name HeapInterface functions.
  // @{
  virtual uint32 GetHeapFeatures() const;
  virtual void* Allocate(size_t bytes);
  virtual bool Free(void* alloc);
  virtual bool IsAllocated(void* alloc);
  virtual void Lock();
  virtual void Unlock();
  // @}

  // @name BlockHeapInterface functions.
  // @{
  virtual void* AllocateBlock(size_t size,
                              size_t min_left_redzone_size,
                              size_t min_right_redzone_size,
                              BlockLayout* layout);
  virtual bool FreeBlock(const BlockInfo& block_info);
  // @}

  // @name BlockQuarantineInterface functions.
  // @{
  virtual bool Push(BlockHeader* const &object);
  virtual bool Pop(BlockHeader** object);
  virtual void Empty(std::vector<BlockHeader*>* objects);
  virtual size_t GetCount();
  // @}

  // Get the ratio of the memory used by the quarantine.
  float quarantine_ratio() const { return quarantine_ratio_; }

  // Set the ratio of the memory used by the quarantine.
  void set_quarantine_ratio(float quarantine_ratio);

 protected:
  // Checks if the quarantine invariant is satisfied.
  // @returns true if the quarantine invariant is satisfied, false otherwise.
  bool QuarantineInvariantIsSatisfied();

  // Gives the 0-based index of the slab containing 'address'.
  // @param address address.
  // @returns The 0-based index of the slab containing 'address', or
  //     kInvalidSlab index if the address is not valid.
  size_t GetSlabIndex(void* address);

  // Gives the addres of the given slab.
  // @param index 0-based index of the slab.
  // @returns The address of the slab, or NULL if the index is invalid.
  uint8* GetSlabAddress(size_t index);

  // Defines an invalid slab index.
  static const size_t kInvalidSlabIndex = -1;

  // The set of possible states of the slabs.
  enum SlabState {
    kFreeSlab,
    kAllocatedSlab,
    kQuarantinedSlab
  };

  // Describes the slab state.
  struct SlabInfo {
    SlabState state;
    uint8* allocated_address;
  };

  // Heap memory address.
  uint8* heap_address_;

  // The heap size in bytes.
  size_t heap_size_;

  // The total number of slabs.
  size_t slab_count_;

  // The ratio [0 .. 1] of the memory used by the quarantine. Under lock_.
  float quarantine_ratio_;

  typedef CircularQueue<size_t, MemoryNotifierAllocator<size_t>> SlabIndexQueue;

  // Holds the indices of free slabs. Under lock_.
  SlabIndexQueue free_slabs_;

  // Holds the indices of the quarantined slabs. Under lock_.
  SlabIndexQueue quarantine_;

  typedef std::vector<SlabInfo,
                      MemoryNotifierAllocator<SlabInfo>> SlabInfoVector;

  // Holds the information related to slabs. Under lock_.
  SlabInfoVector slab_info_;

  // The interface that will be notified of internal memory use. Has its own
  // locking.
  MemoryNotifierInterface* memory_notifier_;

  // The global lock for this allocator.
  common::RecursiveLock lock_;

 private:
  DISALLOW_COPY_AND_ASSIGN(ZebraBlockHeap);
};

}  // namespace heaps
}  // namespace asan
}  // namespace agent

#endif  // SYZYGY_AGENT_ASAN_HEAPS_ZEBRA_BLOCK_HEAP_H_
