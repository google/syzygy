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

#include "syzygy/agent/asan/heaps/internal_heap.h"

#include "syzygy/common/align.h"

namespace agent {
namespace asan {
namespace heaps {

namespace {

struct InternalHeapEntry {
  uint32 size;
  // Actually of a size such that the whole InternalHeapAlloc is of size
  // |size|.
  uint8 body[1];
};

const size_t kBodyOffset = offsetof(InternalHeapEntry, body);

}  // namespace

InternalHeap::InternalHeap(MemoryNotifierInterface* memory_notifier,
                           HeapInterface* heap)
    : memory_notifier_(memory_notifier), heap_(heap) {
  DCHECK_NE(static_cast<MemoryNotifierInterface*>(NULL), memory_notifier);
  DCHECK_NE(static_cast<HeapInterface*>(NULL), heap);
  notifying_heap_ =
      heap_->GetHeapFeatures() & HeapInterface::kHeapReportsReservations;
}

uint32 InternalHeap::GetHeapFeatures() const {
  // Endow a wrapped heap with GetAllocationSize support.
  return heap_->GetHeapFeatures() | kHeapSupportsGetAllocationSize |
      kHeapGetAllocationSizeIsUpperBound;
}

void* InternalHeap::Allocate(size_t bytes) {
  size_t size = common::AlignUp(bytes + kBodyOffset, kShadowRatio);
  void* alloc = heap_->Allocate(size);
  if (alloc == NULL)
    return NULL;

  InternalHeapEntry* entry = reinterpret_cast<InternalHeapEntry*>(alloc);
  entry->size = size;
  memory_notifier_->NotifyInternalUse(entry, size);

  return entry->body;
}

bool InternalHeap::Free(void* alloc) {
  if (alloc != NULL) {
    uint8* bytes = reinterpret_cast<uint8*>(alloc);
    InternalHeapEntry* entry = reinterpret_cast<InternalHeapEntry*>(
        bytes - kBodyOffset);
    if (notifying_heap_) {
      // A notifying heap redzones the memory from which allocations are made.
      // We return the redzone to its initial state.
      memory_notifier_->NotifyFutureHeapUse(entry, entry->size);
    } else {
      // A non-notifying heap serves memory from greenzoned pages, so indicate
      // the memory has returned to the OS.
      memory_notifier_->NotifyReturnedToOS(entry, entry->size);
    }

    // Adjust the allocation pointer to that of the wrapped heap.
    alloc = entry;
  }

  return heap_->Free(alloc);
}

bool InternalHeap::IsAllocated(void* alloc) {
  if (alloc != NULL) {
    uint32* header = reinterpret_cast<uint32*>(alloc) - 1;
    alloc = header;
  }
  return heap_->IsAllocated(alloc);
}

size_t InternalHeap::GetAllocationSize(void* alloc) {
  if (alloc == NULL)
    return kUnknownSize;

  uint8* bytes = reinterpret_cast<uint8*>(alloc);
  InternalHeapEntry* entry = reinterpret_cast<InternalHeapEntry*>(
      bytes - kBodyOffset);
  return entry->size;
}

void InternalHeap::Lock() {
  heap_->Lock();
}

void InternalHeap::Unlock() {
  heap_->Unlock();
}

}  // namespace heaps
}  // namespace asan
}  // namespace agent
