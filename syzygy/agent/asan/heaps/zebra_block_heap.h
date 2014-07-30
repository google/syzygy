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
// An implementation of HeapInterface which ensures that the end of memory
// allocations is aligned to the system page size and followed by an empty
// page.

#ifndef SYZYGY_AGENT_ASAN_HEAPS_ZEBRA_BLOCK_HEAP_H_
#define SYZYGY_AGENT_ASAN_HEAPS_ZEBRA_BLOCK_HEAP_H_

#include <windows.h>

#include <queue>
#include <vector>

#include "base/logging.h"
#include "syzygy/agent/asan/constants.h"
#include "syzygy/agent/asan/heap.h"
#include "syzygy/common/recursive_lock.h"

namespace agent {
namespace asan {
namespace heaps {

// A zebra-stripe heap allocates a (maximum) predefined amount of memory
// and serves allocation requests with size less than or equal to the system
// page size.
// It divides the memory pages into "even" and "odd" types (like zebra-stripes).
//
// All the allocations are done in the even pages, just before the "odd" pages.
// The "odd" pages can be protected againt read/write which gives a basic
// mechanism for detecting buffer overflows.
class ZebraBlockHeap : public BlockHeapInterface {
 public:
  // Constructor.
  // @param heap_size The amount of memory reserved by the heap in bytes.
  explicit ZebraBlockHeap(size_t heap_size);

  // Virtual destructor. Frees all the allocated memory.
  virtual ~ZebraBlockHeap();

  // @name HeapInterface functions.
  // @{
  virtual HeapType GetHeapType() const;
  virtual void* Allocate(size_t bytes);
  virtual bool Free(void* alloc);
  virtual void Lock();
  virtual void Unlock();
  // @}

  // @name BlockHeapInterface functions.
  // @{
  virtual void* AllocateBlock(size_t size,
                              size_t min_left_redzone_size,
                              size_t min_right_redzone_size,
                              BlockLayout* layout);
  virtual bool FreeBlock(const BlockInfo& block_info);
  // @}

 protected:
  // Gives the starting address of a stripe.
  // @param index The 0-based index of the stripe.
  // @returns the starting address of the stripe.
  void* GetStripeAddress(const size_t index);

  // Gives the index of the stripe containing "address".
  // @param address An address which belongs to some stripe.
  // @returns The 0-based index of the stripe that contains the address.
  // @note address can be any address inside the stripe.
  size_t GetStripeIndex(const void* address);

  // Total number of stripes (odd and even).
  size_t stripe_count_;

  // Heap memory address.
  uint8* heap_address_;

  // The heap size in bytes.
  size_t heap_size_;

  // The maximum number of allocations this heap can handle.
  size_t max_number_of_allocations_;

  // Holds the indices of free (even) stripes.
  // Freed allocations are pushed to the queue, while new allocations are
  // taken from the *front* of the queue, so as to maximize the time a free
  // page is freed.
  std::queue<size_t> free_stripes_;

  // Maps the stripe index to the single allocated address inside the stripe.
  std::vector<void*> allocated_address_;

  // The global lock for this allocator.
  common::RecursiveLock lock_;

 private:
  DISALLOW_COPY_AND_ASSIGN(ZebraBlockHeap);
};

}  // namespace heaps
}  // namespace asan
}  // namespace agent

#endif  // SYZYGY_AGENT_ASAN_HEAPS_ZEBRA_BLOCK_HEAP_H_
