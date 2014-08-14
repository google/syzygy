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
// Declares a minimal heap manager interface.

#ifndef SYZYGY_AGENT_ASAN_HEAP_MANAGER_H_
#define SYZYGY_AGENT_ASAN_HEAP_MANAGER_H_

#include "base/basictypes.h"

namespace agent {
namespace asan {

// A heap manager is responsible for creating and managing heaps. It also acts
// as a proxy between the heap function interceptors and the underlying heaps.
class HeapManagerInterface {
 public:
  typedef uintptr_t HeapId;

  // Virtual destructor.
  virtual ~HeapManagerInterface() { }

  // Creates a new heap.
  // @returns the ID of the heap that has been created.
  virtual HeapId CreateHeap() = 0;

  // Destroy a heap.
  // @param heap The ID of the heap to destroy.
  // @returns true on success, false otherwise.
  virtual bool DestroyHeap(HeapId heap) = 0;

  // Do an allocation in a given heap.
  // @param heap The ID of the heap that should preferably be used for the
  //     allocation. The implementation is free to use this heap or not.
  // @param bytes The requested size of the allocation, in bytes.
  // @returns A pointer to the new allocation on success, NULL otherwise.
  virtual void* Allocate(HeapId heap, size_t bytes) = 0;

  // Free a given heap allocation.
  // @param heap A hint on the heap that might contain this allocation.
  // @param alloc The pointer to the allocation to be freed. This must be a
  //     value that was previously returned by a call to 'Allocate'.
  // @returns true on failure, false otherwise.
  virtual bool Free(HeapId heap, void* alloc) = 0;

  // Returns the size of a heap allocation.
  // @param heap A hint on the heap that might contain this allocation.
  // @param alloc The pointer to the allocation whose size is to be calculated.
  //     This must be a value that was previously returned by a call to
  //     'Allocate'.
  // @returns the size of the block on success, 0 otherwise.
  virtual size_t Size(HeapId heap, const void* alloc) = 0;

  // Locks a heap.
  // @param heap The ID of the heap that should be locked.
  virtual void Lock(HeapId heap) = 0;

  // Unlocks a heap.
  // @param heap The ID of the heap that should be unlocked.
  virtual void Unlock(HeapId heap) = 0;
};

}  // namespace asan
}  // namespace agent

#endif  // SYZYGY_AGENT_ASAN_HEAP_MANAGER_H_
