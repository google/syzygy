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

namespace agent {
namespace asan {
namespace heaps {

ZebraBlockHeap::ZebraBlockHeap(size_t heap_size) : heap_size_(heap_size) {
  heap_address_ = reinterpret_cast<uint8*>(
      ::VirtualAlloc(NULL, heap_size_,
                     MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));

  CHECK_NE(reinterpret_cast<uint8*>(NULL), heap_address_);

  // Assumes base_address is page_size aligned.
  DCHECK(common::IsAligned(heap_address_, kPageSize));

  stripe_count_ = heap_size_ / kPageSize;
  allocated_address_.resize(stripe_count_, NULL);

  // Ensures that every "even" page has a reserved "odd" page after.
  // If the last page is "even" it is discarded.
  for (size_t i = 0; i + 1 < stripe_count_; i += 2)
    free_stripes_.push(i);

  max_number_of_allocations_ = free_stripes_.size();
}

ZebraBlockHeap::~ZebraBlockHeap() {
  DCHECK_NE(reinterpret_cast<uint8*>(NULL), heap_address_);
  CHECK_NE(FALSE, ::VirtualFree(heap_address_, 0, MEM_RELEASE));
}

ZebraBlockHeap::HeapType ZebraBlockHeap::GetHeapType() const {
  return kTransparentHeap;
}

void* ZebraBlockHeap::Allocate(size_t bytes) {
  if (bytes == 0 || bytes > kPageSize)
    return NULL;

  common::AutoRecursiveLock lock(lock_);

  if (free_stripes_.empty())
    return NULL;
  size_t stripe_index = free_stripes_.front();
  free_stripes_.pop();

  uint8* page_address = reinterpret_cast<uint8*>(
      GetStripeAddress(stripe_index));

  // Use the memory at the end of the page.
  uint8* alloc = page_address + kPageSize - bytes;
  alloc = common::AlignDown(alloc, kShadowRatio);

  allocated_address_[stripe_index] = alloc;
  return alloc;
}

bool ZebraBlockHeap::Free(void* alloc) {
  if (alloc == NULL)
    return true;

  size_t stripe_index = GetStripeIndex(alloc);

  // Address inside an "odd" (protected) page.
  if (stripe_index & 1)
    return false;
  if (stripe_index >= stripe_count_)
    return false;

  common::AutoRecursiveLock lock(lock_);

  // The address must match the one returned to the caller by Allocate.
  if (alloc != allocated_address_[stripe_index])
    return false;

  allocated_address_[stripe_index] = NULL;
  free_stripes_.push(stripe_index);

  return true;
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

  if (layout->block_size != 2 * kPageSize)
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

void* ZebraBlockHeap::GetStripeAddress(const size_t index) {
  return heap_address_ + (kPageSize * index);
}

size_t ZebraBlockHeap::GetStripeIndex(const void* address) {
  DCHECK_NE(reinterpret_cast<const uint8*>(NULL), address);
  DCHECK_GE(reinterpret_cast<const uint8*>(address), heap_address_);
  return (reinterpret_cast<const uint8*>(address)-heap_address_) / kPageSize;
}

}  // namespace heaps
}  // namespace asan
}  // namespace agent
