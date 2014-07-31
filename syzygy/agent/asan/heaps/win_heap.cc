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

#include "syzygy/agent/asan/heaps/win_heap.h"

namespace agent {
namespace asan {
namespace heaps {

WinHeap::WinHeap() : heap_(NULL), own_heap_(true) {
  heap_ = ::HeapCreate(0, 0, 0);
  DCHECK_NE(static_cast<HANDLE>(NULL), heap_);
}

WinHeap::WinHeap(HANDLE heap) : heap_(heap), own_heap_(false) {
}

WinHeap::~WinHeap() {
  if (!own_heap_)
    return;
  DCHECK_NE(static_cast<HANDLE>(NULL), heap_);
  ::HeapDestroy(heap_);
}

uint32 WinHeap::GetHeapFeatures() const {
  // This heap doesn't support any advanced features.
  return 0;
}

void* WinHeap::Allocate(size_t bytes) {
  DCHECK_NE(static_cast<HANDLE>(NULL), heap_);
  void* alloc = ::HeapAlloc(heap_, 0, bytes);
  return alloc;
}

bool WinHeap::Free(void* alloc) {
  DCHECK_NE(static_cast<HANDLE>(NULL), heap_);
  if (::HeapFree(heap_, 0, alloc) != TRUE)
    return false;
  return true;
}

bool WinHeap::IsAllocated(void* alloc) {
  return false;
}

void WinHeap::Lock() {
  DCHECK_NE(static_cast<HANDLE>(NULL), heap_);
  // This can only fail if the heap was opened with HEAP_NO_SERIALIZATION.
  // This is strictly unsupported.
  // TODO(chrisha): If we want to support this we can always provide our own
  //     serialization, and query for this condition at runtime.
  CHECK_EQ(TRUE, ::HeapLock(heap_));
}

void WinHeap::Unlock() {
  DCHECK_NE(static_cast<HANDLE>(NULL), heap_);
  CHECK_EQ(TRUE, ::HeapUnlock(heap_));
}

}  // namespace heaps
}  // namespace asan
}  // namespace agent
