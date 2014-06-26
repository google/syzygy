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
// Declares the interface that all heap implementations must implement.
// This is a vastly simplified interface as the instrumentation layer
// provides more advanced features (validation, iteration, etc).

#ifndef SYZYGY_AGENT_ASAN_HEAP_H_
#define SYZYGY_AGENT_ASAN_HEAP_H_

namespace agent {
namespace asan {

// An extremely simple heap interface. More advanced heap features are
// provided by the instrumentation layer which is overlaid on top of a
// raw heap.
class HeapInterface {
 public:
  // The fundamental type of the heap.
  enum HeapType {
    // An opaque heap has a hidden implementation and does not notify
    // the shadow memory of reserved or internally used memory.
    kOpaqueHeap,
    // A transparent heap notifies the shadow directly, allowing for better
    // redzoning coverage and implicit quarantining.
    kTransparentHeap,
  };

  // Virtual destructor.
  virtual ~HeapInterface() { }

  // @returns the heap type. This guides behaviour of the shadow memory when
  //     allocating and freeing memory through this heap.
  virtual HeapType GetHeapType() const = 0;

  // Allocates memory from the heap. It is valid to request an allocation
  // of size zero, in which case any return address is valid. If @p bytes
  // is non-zero and the request fails this should return NULL.
  // @param bytes The size of the requested allocation, in bytes.
  // @returns a valid pointer on success, or NULL on failure.
  virtual void* Allocate(size_t bytes) = 0;

  // Frees an allocation, returning the memory to the underlying heap. It is
  // invalid to attempt to free memory not previously allocated by this heap,
  // or double free previously freed memory.
  // @param alloc The address of the allocation.
  // @returns true on success, false otherwise.
  virtual bool Free(void* alloc) = 0;

  // Locks the heap. All other calls to the heap will be blocked until
  // a corresponding call to Unlock.
  virtual void Lock() = 0;

  // Unlocks the heap.
  virtual void Unlock() = 0;
};

}  // namespace asan
}  // namespace agent

#endif  // SYZYGY_AGENT_ASAN_HEAP_H_
