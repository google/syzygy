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

#include "syzygy/agent/asan/heaps/large_block_heap.h"

#include <windows.h>

#include <algorithm>

#include "base/logging.h"
#include "syzygy/common/align.h"

namespace agent {
namespace asan {
namespace heaps {

LargeBlockHeap::LargeBlockHeap(HeapInterface* internal_heap)
    : allocs_(HeapAllocator<void*>(internal_heap)) {
}

uint32 LargeBlockHeap::GetHeapFeatures() const {
  return kHeapSupportsIsAllocated;
}

void* LargeBlockHeap::Allocate(size_t bytes) {
  // Always allocate some memory so as to guarantee that zero-sized
  // allocations get an actual distinct address each time.
  size_t size = std::max(bytes, 1u);
  size = common::AlignUp(size, kPageSize);
  void* alloc = ::VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_READWRITE);

  if (alloc != NULL) {
    common::AutoRecursiveLock lock(lock_);
    allocs_.insert(alloc);
  }

  return alloc;
}

bool LargeBlockHeap::Free(void* alloc) {
  {
    // First lookup the allocation to ensure it was made by us.
    common::AutoRecursiveLock lock(lock_);
    AllocationSet::iterator it = allocs_.find(alloc);
    if (it == allocs_.end())
      return false;
    allocs_.erase(it);
  }

  ::VirtualFree(alloc, 0, MEM_RELEASE);
  return true;
}

bool LargeBlockHeap::IsAllocated(void* alloc) {
  common::AutoRecursiveLock lock(lock_);
  AllocationSet::iterator it = allocs_.find(alloc);
  if (it == allocs_.end())
    return false;

  return true;
}

size_t LargeBlockHeap::GetAllocationSize(void* alloc) {
  return kUnknownSize;
}

void LargeBlockHeap::Lock() {
  lock_.Acquire();
}

void LargeBlockHeap::Unlock() {
  lock_.Release();
}

void* LargeBlockHeap::AllocateBlock(size_t size,
                                    size_t min_left_redzone_size,
                                    size_t min_right_redzone_size,
                                    BlockLayout* layout) {
  DCHECK_NE(static_cast<BlockLayout*>(NULL), layout);

  // Plan the layout with full guard pages.
  BlockPlanLayout(kPageSize, kPageSize, size, kPageSize, kPageSize, layout);
  DCHECK_EQ(0u, layout->block_size % kPageSize);

  return Allocate(layout->block_size);
}

bool LargeBlockHeap::FreeBlock(const BlockInfo& block_info) {
  DCHECK_NE(static_cast<uint8*>(NULL), block_info.block);

  return Free(block_info.block);
}

}  // namespace heaps
}  // namespace asan
}  // namespace agent
