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
//
// This also declares the interface for an instrumented heap. An instrumented
// heap has explicit knowledge of the fact that it is laying out blocks
// with redzones, as due to heap implementation details it may need to grow
// the redzones of the block being allocated.

#ifndef SYZYGY_AGENT_ASAN_HEAP_H_
#define SYZYGY_AGENT_ASAN_HEAP_H_

#include "syzygy/agent/asan/block.h"

namespace agent {
namespace asan {

// An enumeration of known heap types. New heaps should be added strictly
// to the end of this list.
enum HeapType {
  // A catch-all heap type for test fixtures, etc.
  kUnknownHeapType,
  kWinHeap,
  kReserved, // Was kCtMalloc.
  kLargeBlockHeap,
  kZebraBlockHeap,

  // This must be last.
  kHeapTypeMax,
};

extern const char* kHeapTypes[kHeapTypeMax];

// An extremely simple heap interface. More advanced heap features are
// provided by the instrumentation layer which is overlaid on top of a
// raw heap. This is the API for a heap that performs actual memory
// management of simple contiguous chunks of memory. Instrumented heaps
// (for allocating Blocks, with redzones, etc) are allocated and laid out
// by BlockHeap implementations.
class HeapInterface {
 public:
  // A bitset of features supported by this heap.
  enum HeapFeatures {
    // If this is set then the heap reports reserved memory via the
    // MemoryNotifierInterface. This implies that allocations will come
    // from regions of memory that have been previously redzoned, and
    // guides the heap manager in maintaining consistent shadow memory.
    //
    // If this flag is set then the heap should also support the
    // kHeapSupportsGetAllocationSize feature in order to be able to redzone the
    // unguarded allocations when they get freed.
    kHeapReportsReservations = 1 << 0,

    // If this bit is set then the heap is able to determine if a given
    // address is part of an active allocation owned by the heap, via the
    // 'IsAllocated' function.
    kHeapSupportsIsAllocated = 1 << 1,

    // If this bit is set then the heap supports returning allocation sizes.
    kHeapSupportsGetAllocationSize = 1 << 2,

    // If this bit is set then the results returned by GetAllocationSize are
    // approximate, and reflect the size of the block of memory returned for
    // the allocation, not the actual initially requested amount. Can only be
    // set in conjunction with kHeapSupportsGetAllocationSize.
    kHeapGetAllocationSizeIsUpperBound = 1 << 3,
  };

  // The return value of GetAllocationSize if the heap does not support it.
  static const size_t kUnknownSize = ~0U;

  // Virtual destructor.
  virtual ~HeapInterface() { }

  // Reports the of this heap.
  // @returns the type of this heap.
  virtual HeapType GetHeapType() const = 0;

  // @returns the heap features.
  virtual uint32_t GetHeapFeatures() const = 0;

  // Allocates memory from the heap. It is valid to request an allocation
  // of size zero, in which case any return address is valid. If @p bytes
  // is non-zero and the request fails this should return NULL. The allocation
  // must have an alignment of at least kShadowRatio.
  // @param bytes The size of the requested allocation, in bytes.
  // @returns a valid pointer on success, or NULL on failure.
  virtual void* Allocate(uint32_t bytes) = 0;

  // Frees an allocation, returning the memory to the underlying heap. It is
  // invalid to attempt to free memory not previously allocated by this heap,
  // or double free previously freed memory.
  // @param alloc The address of the allocation.
  // @returns true on success, false otherwise.
  virtual bool Free(void* alloc) = 0;

  // Determines if the heap owns the given allocation.
  // @param alloc An address.
  // @returns true if @p alloc is an address previously returned by a call
  //     to 'Allocate', and not yet returned via 'Free'.
  // @note This will always return false unless the heap has the
  //     kHeapSupportsIsAllocated feature.
  virtual bool IsAllocated(const void* alloc) = 0;

  // Returns the size of the given allocation.
  // @param alloc An address previously returned by Allocate.
  // @returns the size of the allocation.
  // @note This will always return kUnknownSize unless the heap has the
  //     kHeapSupportsGetAllocationSize feature.
  virtual uint32_t GetAllocationSize(const void* alloc) = 0;

  // Locks the heap. All other calls to the heap will be blocked until
  // a corresponding call to Unlock.
  virtual void Lock() = 0;

  // Unlocks the heap.
  virtual void Unlock() = 0;

  // Tries to lock this heap.
  // @returns true if the lock was acquired, false otherwise.
  virtual bool TryLock() = 0;
};

// Declares the interface that a block-allocating heap must implement. The API
// reflects the fact that the heap implementation is aware that it is
// allocating Block objects with redzones, and allows for the implementation to
// potentially grow the redzones of the requested block. This is an extension
// of HeapInterface.
class BlockHeapInterface : public HeapInterface {
 public:
  // Virtual destructor.
  virtual ~BlockHeapInterface() { }

  // Allocates a block from the heap. If this heap is unable to satisfy the
  // allocation then it can simply return NULL and not initialize the block
  // layout.
  // @param size The size of the body of the allocation. Can be 0.
  // @param min_left_redzone_size The minimum size of the left redzone.
  // @param min_right_redzone_size The minimum size of the right redzone.
  // @param layout The layout structure to be populated.
  // @returns a pointer to the allocation upon success, otherwise NULL.
  virtual void* AllocateBlock(uint32_t size,
                              uint32_t min_left_redzone_size,
                              uint32_t min_right_redzone_size,
                              BlockLayout* layout) = 0;

  // Frees the block at the given address.
  // @returns true on success, false otherwise.
  virtual bool FreeBlock(const BlockInfo& block_info) = 0;
};

}  // namespace asan
}  // namespace agent

#endif  // SYZYGY_AGENT_ASAN_HEAP_H_
