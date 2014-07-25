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

#include "base/logging.h"

namespace agent {
namespace asan {

LargeBlockHeap::LargeBlockHeap() {
}

LargeBlockHeap::~LargeBlockHeap() {
}

HeapInterface::HeapType LargeBlockHeap::GetHeapType() const {
  return kTransparentHeap;
}

void* LargeBlockHeap::Allocate(size_t bytes) {
  if (bytes == 0)
    return NULL;

  void* alloc = ::VirtualAlloc(NULL, bytes, MEM_COMMIT, PAGE_READWRITE);

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

}  // namespace asan
}  // namespace agent
