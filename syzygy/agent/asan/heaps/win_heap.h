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
// An implementation of HeapInterface that wraps the Windows heap API.

#ifndef SYZYGY_AGENT_ASAN_HEAPS_WIN_HEAP_H_
#define SYZYGY_AGENT_ASAN_HEAPS_WIN_HEAP_H_

#include <windows.h>

#include "base/logging.h"
#include "syzygy/agent/asan/heap.h"

namespace agent {
namespace asan {
namespace heaps {

class WinHeap : public HeapInterface {
 public:
  // Constructor. Creates a heap that is owned uniquely by this object.
  WinHeap();

  // Constructor that wraps an existing heap. Ownership of the heap remains
  // external to this object.
  explicit WinHeap(HANDLE heap);

  // Destructor.
  virtual ~WinHeap();

  // @name HeapInterface functions.
  // @{
  virtual uint32 GetHeapFeatures() const;
  virtual void* Allocate(size_t bytes);
  virtual bool Free(void* alloc);
  virtual bool IsAllocated(void* alloc);
  virtual void Lock();
  virtual void Unlock();
  // @}

 protected:
  // The heap that is wrapped by this object.
  HANDLE heap_;

  // If true then this object owns the wrapped heap.
  bool own_heap_;

 private:
  DISALLOW_COPY_AND_ASSIGN(WinHeap);
};

}  // namespace heaps
}  // namespace asan
}  // namespace agent

#endif  // SYZYGY_AGENT_ASAN_HEAPS_WIN_HEAP_H_
