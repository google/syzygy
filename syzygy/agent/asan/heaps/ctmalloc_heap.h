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
// An implementation of HeapInterface that wraps the CtMalloc heap.

#ifndef SYZYGY_AGENT_ASAN_HEAPS_CTMALLOC_HEAP_H_
#define SYZYGY_AGENT_ASAN_HEAPS_CTMALLOC_HEAP_H_

#include "base/logging.h"
#include "base/memory/scoped_ptr.h"
#include "syzygy/agent/asan/heap.h"
#include "syzygy/agent/asan/memory_notifier.h"
#include "syzygy/common/recursive_lock.h"
#include "wtf/config.h"
#include "wtf/PartitionAlloc.h"

namespace agent {
namespace asan {
namespace heaps {

class CtMallocHeap : public HeapInterface {
 public:
  // Constructor. Creates a heap that is owned uniquely by this object.
  // @param memory_notifier The notifier that will be used to inform the
  //     runtime of this heaps internal memory use.
  explicit CtMallocHeap(MemoryNotifierInterface* memory_notifier);

  // Destructor.
  virtual ~CtMallocHeap();

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
  // The underlying heap. Under lock_.
  PartitionAllocatorGeneric allocator_;

  // The interface that will be notified of internal memory use. Has its own
  // locking.
  MemoryNotifierInterface* memory_notifier_;

  // The lock that gates access to this heap.
  common::RecursiveLock lock_;

 private:
  DISALLOW_COPY_AND_ASSIGN(CtMallocHeap);
};

}  // namespace heaps
}  // namespace asan
}  // namespace agent

#endif  // SYZYGY_AGENT_ASAN_HEAPS_CTMALLOC_HEAP_H_
