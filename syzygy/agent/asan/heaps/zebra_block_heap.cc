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

#include "syzygy/agent/asan/heaps/zebra_block_heap.h"

#include <algorithm>

#include "syzygy/common/align.h"
#include "syzygy/common/asan_parameters.h"

namespace agent {
namespace asan {
namespace heaps {

const size_t ZebraBlockHeap::kSlabSize = 2 * kPageSize;

ZebraBlockHeap::ZebraBlockHeap(size_t heap_size,
                               MemoryNotifierInterface* memory_notifier)
    : heap_address_(NULL),
      // Makes the heap_size a multiple of kSlabSize to avoid incomplete slabs
      // at the end of the reserved memory.
      heap_size_(common::AlignUp(heap_size, kSlabSize)),
      slab_count_(heap_size_ / kSlabSize),
      slab_info_(MemoryNotifierAllocator<SlabInfo>(memory_notifier)),
      quarantine_ratio_(common::kDefaultZebraBlockHeapQuarantineRatio),
      free_slabs_(slab_count_,
                  MemoryNotifierAllocator<size_t>(memory_notifier)),
      quarantine_(slab_count_,
                  MemoryNotifierAllocator<size_t>(memory_notifier)),
      memory_notifier_(memory_notifier) {
  DCHECK_NE(reinterpret_cast<MemoryNotifierInterface*>(NULL), memory_notifier);

  // Allocate the chunk of memory directly from the OS.
  heap_address_ = reinterpret_cast<uint8*>(
      ::VirtualAlloc(NULL,
                     heap_size_,
                     MEM_RESERVE | MEM_COMMIT,
                     PAGE_READWRITE));
  CHECK_NE(reinterpret_cast<uint8*>(NULL), heap_address_);
  DCHECK(common::IsAligned(heap_address_, kPageSize));
  memory_notifier_->NotifyFutureHeapUse(heap_address_, heap_size_);

  // Initialize the metadata describing the state of our heap.
  slab_info_.resize(slab_count_);
  for (size_t i = 0; i < slab_count_; ++i) {
    slab_info_[i].allocated_address = NULL;
    slab_info_[i].state = kFreeSlab;
    free_slabs_.push(i);
  }
}

ZebraBlockHeap::~ZebraBlockHeap() {
  DCHECK_NE(reinterpret_cast<uint8*>(NULL), heap_address_);
  CHECK_NE(FALSE, ::VirtualFree(heap_address_, 0, MEM_RELEASE));
  memory_notifier_->NotifyReturnedToOS(heap_address_, heap_size_);
  heap_address_ = NULL;
}

uint32 ZebraBlockHeap::GetHeapFeatures() const {
  return kHeapSupportsIsAllocated | kHeapReportsReservations;
}

void* ZebraBlockHeap::Allocate(size_t bytes) {
  if (bytes == 0 || bytes > kPageSize)
    return NULL;
  common::AutoRecursiveLock lock(lock_);

  if (free_slabs_.empty())
    return NULL;

  size_t slab_index = free_slabs_.front();
  DCHECK_NE(kInvalidSlabIndex, slab_index);
  free_slabs_.pop();
  uint8* slab_address = GetSlabAddress(slab_index);
  DCHECK_NE(reinterpret_cast<uint8*>(NULL), slab_address);

  // Push the allocation to the end of the even page.
  uint8* alloc = slab_address + kPageSize - bytes;
  alloc = common::AlignDown(alloc, kShadowRatio);

  slab_info_[slab_index].state = kAllocatedSlab;
  slab_info_[slab_index].allocated_address = alloc;
  return alloc;
}

bool ZebraBlockHeap::Free(void* alloc) {
  if (alloc == NULL)
    return true;
  common::AutoRecursiveLock lock(lock_);
  size_t slab_index = GetSlabIndex(alloc);
  if (slab_index == kInvalidSlabIndex)
    return false;
  if (slab_info_[slab_index].allocated_address != alloc)
    return false;

  // Memory must be released from the quarantine before calling Free.
  DCHECK_NE(kQuarantinedSlab, slab_info_[slab_index].state);

  if (slab_info_[slab_index].state == kFreeSlab)
    return false;

  // Make the slab available for allocations.
  slab_info_[slab_index].state = kFreeSlab;
  slab_info_[slab_index].allocated_address = NULL;
  free_slabs_.push(slab_index);
  return true;
}

bool ZebraBlockHeap::IsAllocated(void* alloc) {
  if (alloc == NULL)
    return false;
  common::AutoRecursiveLock lock(lock_);
  size_t slab_index = GetSlabIndex(alloc);
  if (slab_index == kInvalidSlabIndex)
    return false;
  if (slab_info_[slab_index].allocated_address != alloc)
    return false;
  return (slab_info_[slab_index].state != kFreeSlab);
}

void ZebraBlockHeap::Lock() {
  lock_.Acquire();
}

void ZebraBlockHeap::Unlock() {
  lock_.Release();
}

void* ZebraBlockHeap::AllocateBlock(size_t size,
                                    size_t min_left_redzone_size,
                                    size_t min_right_redzone_size,
                                    BlockLayout* layout) {
  DCHECK_NE(static_cast<BlockLayout*>(NULL), layout);
  // Abort if the redzones do not fit in a page. Even if the allocation
  // is possible it will lead to a non-standard block layout.
  if (min_left_redzone_size + size > kPageSize)
    return NULL;
  if (min_right_redzone_size > kPageSize)
    return NULL;

  // Plan the block layout.
  BlockPlanLayout(kPageSize,
                  kShadowRatio,
                  size,
                  min_left_redzone_size,
                  std::max(kPageSize, min_right_redzone_size),
                  layout);

  if (layout->block_size != kSlabSize)
    return NULL;
  size_t right_redzone_size = layout->trailer_size +
      layout->trailer_padding_size;
  // Part of the body lies inside an "odd" page.
  if (right_redzone_size < kPageSize)
    return NULL;
  // There should be less than kShadowRatio bytes between the body end
  // and the "odd" page.
  if (right_redzone_size - kPageSize >= kShadowRatio)
    return NULL;

  // Allocate space for the block. If the allocation fails, it will
  // return NULL and we'll simply pass it on.
  void* alloc = Allocate(kPageSize);

  DCHECK_EQ(0u, reinterpret_cast<uintptr_t>(alloc) % kShadowRatio);
  return alloc;
}

bool ZebraBlockHeap::FreeBlock(const BlockInfo& block_info) {
  DCHECK_NE(static_cast<uint8*>(NULL), block_info.block);
  if (!Free(block_info.block))
    return false;
  return true;
}

bool ZebraBlockHeap::Push(BlockHeader* const &object) {
  common::AutoRecursiveLock lock(lock_);
  size_t slab_index = GetSlabIndex(reinterpret_cast<void*>(object));
  if (slab_index == kInvalidSlabIndex)
    return false;
  if (slab_info_[slab_index].state != kAllocatedSlab)
    return false;
  if (slab_info_[slab_index].allocated_address !=
      reinterpret_cast<void*>(object)) {
    return false;
  }

  quarantine_.push(slab_index);
  slab_info_[slab_index].state = kQuarantinedSlab;
  return true;
}

bool ZebraBlockHeap::Pop(BlockHeader** block) {
  common::AutoRecursiveLock lock(lock_);

  if (QuarantineInvariantIsSatisfied())
    return false;

  size_t slab_index = quarantine_.front();
  DCHECK_NE(kInvalidSlabIndex, slab_index);
  quarantine_.pop();

  void* alloc = slab_info_[slab_index].allocated_address;
  DCHECK_NE(static_cast<void*>(NULL), alloc);
  *block = reinterpret_cast<BlockHeader*>(alloc);

  DCHECK_EQ(kQuarantinedSlab, slab_info_[slab_index].state);
  slab_info_[slab_index].state = kAllocatedSlab;
  return true;
}

void ZebraBlockHeap::Empty(ObjectVector* objects) {
  common::AutoRecursiveLock lock(lock_);
  BlockHeader* object = NULL;
  while (!quarantine_.empty()) {
    size_t slab_index = quarantine_.front();
    DCHECK_NE(kInvalidSlabIndex, slab_index);
    quarantine_.pop();

    object = reinterpret_cast<BlockHeader*>(
        slab_info_[slab_index].allocated_address);

    DCHECK_NE(reinterpret_cast<BlockHeader*>(NULL), object);

    // Do not free the slab, only release it from the quarantine.
    slab_info_[slab_index].state = kAllocatedSlab;
    objects->push_back(object);
  }
}

size_t ZebraBlockHeap::GetCount() {
  common::AutoRecursiveLock lock(lock_);
  return quarantine_.size();
}

void ZebraBlockHeap::set_quarantine_ratio(float quarantine_ratio) {
  DCHECK_LE(0, quarantine_ratio);
  DCHECK_GE(1, quarantine_ratio);
  common::AutoRecursiveLock lock(lock_);
  quarantine_ratio_ = quarantine_ratio;
}

bool ZebraBlockHeap::QuarantineInvariantIsSatisfied() {
  return quarantine_.empty() ||
         (quarantine_.size() / static_cast<float>(slab_count_) <=
             quarantine_ratio_);
}

uint8* ZebraBlockHeap::GetSlabAddress(size_t index) {
  if (index >= slab_count_)
    return NULL;
  return heap_address_ + index * kSlabSize;
}

size_t ZebraBlockHeap::GetSlabIndex(void* address) {
  if (address < heap_address_ || address >= heap_address_ + heap_size_)
    return kInvalidSlabIndex;
  return (reinterpret_cast<uint8*>(address) - heap_address_) / kSlabSize;
}

}  // namespace heaps
}  // namespace asan
}  // namespace agent
