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

#include "syzygy/agent/asan/heaps/simple_block_heap.h"

#include "base/logging.h"

namespace agent {
namespace asan {
namespace heaps {

SimpleBlockHeap::SimpleBlockHeap(HeapInterface* heap) : heap_(heap) {
  DCHECK_NE(static_cast<HeapInterface*>(NULL), heap);
}

SimpleBlockHeap::~SimpleBlockHeap() {
}

HeapType SimpleBlockHeap::GetHeapType() const {
  return heap_->GetHeapType();
}

uint32_t SimpleBlockHeap::GetHeapFeatures() const {
  return heap_->GetHeapFeatures();
}

void* SimpleBlockHeap::Allocate(uint32_t bytes) {
  return heap_->Allocate(bytes);
}

bool SimpleBlockHeap::Free(void* alloc) {
  return heap_->Free(alloc);
}

bool SimpleBlockHeap::IsAllocated(const void* alloc) {
  return heap_->IsAllocated(alloc);
}

uint32_t SimpleBlockHeap::GetAllocationSize(const void* alloc) {
  return heap_->GetAllocationSize(alloc);;
}

void SimpleBlockHeap::Lock() {
  heap_->Lock();
}

void SimpleBlockHeap::Unlock() {
  heap_->Unlock();
}

bool SimpleBlockHeap::TryLock() {
  return heap_->TryLock();
}

void* SimpleBlockHeap::AllocateBlock(uint32_t size,
                                     uint32_t min_left_redzone_size,
                                     uint32_t min_right_redzone_size,
                                     BlockLayout* layout) {
  DCHECK_NE(static_cast<BlockLayout*>(nullptr), layout);

  // Plan the block layout.
  if (!BlockPlanLayout(kShadowRatio, kShadowRatio, size, min_left_redzone_size,
                       min_right_redzone_size, layout)) {
    return nullptr;
  }

  // Allocate space for the block. If the allocation fails heap_ will
  // return NULL and we'll simply pass it on.
  void* alloc = heap_->Allocate(layout->block_size);
  DCHECK_EQ(0u, reinterpret_cast<uintptr_t>(alloc) % kShadowRatio);
  return alloc;
}

bool SimpleBlockHeap::FreeBlock(const BlockInfo& block_info) {
  DCHECK_NE(static_cast<BlockHeader*>(nullptr), block_info.header);

  if (!heap_->Free(block_info.header))
    return false;

  return true;
}

}  // namespace heaps
}  // namespace asan
}  // namespace agent
