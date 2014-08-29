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
// Defines InternalHeap, a simple wrapper of any other HeapInterface that
// adds internal-use notifications via a MemoryNotifierInterface.

#ifndef SYZYGY_AGENT_ASAN_HEAPS_INTERNAL_HEAP_H_
#define SYZYGY_AGENT_ASAN_HEAPS_INTERNAL_HEAP_H_

#include "base/logging.h"
#include "syzygy/agent/asan/heap.h"
#include "syzygy/agent/asan/memory_notifier.h"

namespace agent {
namespace asan {
namespace heaps {

// An implementation of HeapInterface that wraps another HeapInterface and
// a MemoryNotificationInterface. It subsequently will notify all allocations
// as being for internal use. This incurs a small amount of memory overhead
// per allocation to store the original size of the allocation. This heap
// does *not* return allocations that are kShadowRatio aligned. Rather, it
// returns allocations that sizeof(uint32) % kShadowRatio aligned, due to the
// extra incurred header. This is not an issue as the allocations are only
// for internal use and no shadow memory notations will be applied to them.
class InternalHeap : public HeapInterface {
 public:
  // Constructor.
  // @param memory_notifier The notifier that will be used to inform the
  //     runtime of all allocations.
  // @param heap The underlying heap that is being wrapped.
  InternalHeap(MemoryNotifierInterface* memory_notifier,
               HeapInterface* heap);

  // Destructor.
  virtual ~InternalHeap() { }

  // @name HeapInterface functions.
  // @{
  virtual uint32 GetHeapFeatures() const;
  virtual void* Allocate(size_t bytes);
  virtual bool Free(void* alloc);
  virtual bool IsAllocated(void* alloc);
  virtual size_t GetAllocationSize(void* alloc);
  virtual void Lock();
  virtual void Unlock();
  // @}

 protected:
  // The interface that will be notified of all memory use. Has its own
  // locking.
  MemoryNotifierInterface* memory_notifier_;

  // The underlying heap interface. Provides locking for us.
  HeapInterface* heap_;

  // This is true if the wrapped heap is a notifying heap.
  bool notifying_heap_;

 private:
  DISALLOW_COPY_AND_ASSIGN(InternalHeap);
};

}  // namespace heaps
}  // namespace asan
}  // namespace agent

#endif  // SYZYGY_AGENT_ASAN_HEAPS_INTERNAL_HEAP_H_
