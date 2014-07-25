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
// Declares SimpleBlockHeap, which is a simple block-aware wrapper of an
// instance of a HeapInterface. This is the primary type of block heap used
// by the ASAN instrumentation.

#ifndef SYZYGY_AGENT_ASAN_HEAPS_SIMPLE_BLOCK_HEAP_H_
#define SYZYGY_AGENT_ASAN_HEAPS_SIMPLE_BLOCK_HEAP_H_

#include "syzygy/agent/asan/heap.h"

namespace agent {
namespace asan {

// A block heap that wraps a raw heap.
class SimpleBlockHeap : public BlockHeapInterface {
 public:
  // Constructor.
  // @param heap Is the underlying raw heap that will be used by this heap.
  explicit SimpleBlockHeap(HeapInterface* heap);

  // Virtual destructor.
  virtual ~SimpleBlockHeap();

  // @name HeapInterface implementation.
  // @{
  virtual HeapType GetHeapType() const;
  virtual void* Allocate(size_t bytes);
  virtual bool Free(void* alloc);
  virtual void Lock();
  virtual void Unlock();
  // @}

  // @name BlockHeapInterface implementation.
  // @{
  virtual void* AllocateBlock(size_t size,
                              size_t min_left_redzone_size,
                              size_t min_right_redzone_size,
                              BlockLayout* layout);
  virtual bool FreeBlock(const BlockInfo& block_info);
  // @}

 protected:
  // The underlying raw heap.
  HeapInterface* heap_;

 private:
  DISALLOW_COPY_AND_ASSIGN(SimpleBlockHeap);
};

}  // namespace asan
}  // namespace agent

#endif  // SYZYGY_AGENT_ASAN_HEAPS_SIMPLE_BLOCK_HEAP_H_
