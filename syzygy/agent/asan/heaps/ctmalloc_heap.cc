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

#include "syzygy/agent/asan/heaps/ctmalloc_heap.h"

namespace agent {
namespace asan {
namespace heaps {

namespace {

// Callback that CtMalloc will invoke when memory is reserved.
void CtMallocMemoryReservedCallback(
    void* user_data, void* addr, size_t length) {
  DCHECK_NE(static_cast<void*>(NULL), user_data);
  DCHECK_NE(static_cast<void*>(NULL), addr);
  DCHECK_LT(0u, length);

  MemoryNotifierInterface* memory_notifier =
      reinterpret_cast<MemoryNotifierInterface*>(user_data);
  memory_notifier->NotifyFutureHeapUse(addr, length);
}

// Callback that CtMalloc will invoke when memory is released.
void CtMallocMemoryReleasedCallback(
    void* user_data, void* addr, size_t length) {
  DCHECK_NE(static_cast<void*>(NULL), user_data);
  DCHECK_NE(static_cast<void*>(NULL), addr);
  DCHECK_LT(0u, length);

  MemoryNotifierInterface* memory_notifier =
      reinterpret_cast<MemoryNotifierInterface*>(user_data);
  memory_notifier->NotifyReturnedToOS(addr, length);
}

}  // namespace

CtMallocHeap::CtMallocHeap(MemoryNotifierInterface* memory_notifier)
    : memory_notifier_(memory_notifier) {
  DCHECK_NE(static_cast<MemoryNotifierInterface*>(NULL), memory_notifier);

  ::memset(&allocator_, 0, sizeof(allocator_));

  // Wire the memory notifier up to the underlying CtMalloc implementation via
  // the callbacks we added.
  allocator_.root()->callbacks.user_data = memory_notifier;
  allocator_.root()->callbacks.reserved_callback =
      &CtMallocMemoryReservedCallback;
  allocator_.root()->callbacks.released_callback =
      &CtMallocMemoryReleasedCallback;

  // Initialize the CtMalloc heap.
  allocator_.init();
}

CtMallocHeap::~CtMallocHeap() {
  // Shutdown the CtMalloc heap.
  allocator_.shutdown();
}

uint32 CtMallocHeap::GetHeapFeatures() const {
  return kHeapReportsReservations | kHeapSupportsIsAllocated;
}

void* CtMallocHeap::Allocate(size_t bytes) {
  common::AutoRecursiveLock lock(lock_);
  void* alloc = WTF::partitionAllocGeneric(allocator_.root(), bytes);
  return alloc;
}

bool CtMallocHeap::Free(void* alloc) {
  common::AutoRecursiveLock lock(lock_);
  WTF::partitionFreeGeneric(allocator_.root(), alloc);
  return true;
}

bool CtMallocHeap::IsAllocated(void* alloc) {
  if (!WTF::partitionIsAllocatedGeneric(allocator_.root(), alloc, -1))
    return false;
  return true;
}

size_t CtMallocHeap::GetAllocationSize(void* alloc) {
  return 0;
}

void CtMallocHeap::Lock() {
  lock_.Acquire();
}

void CtMallocHeap::Unlock() {
  lock_.Release();
}

}  // namespace heaps
}  // namespace asan
}  // namespace agent
