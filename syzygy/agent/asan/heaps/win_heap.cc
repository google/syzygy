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

WinHeap::WinHeap() : heap_(NULL), own_heap_(true), heap_lock_held_(false) {
  heap_ = ::HeapCreate(0, 0, 0);
  DCHECK_NE(static_cast<HANDLE>(NULL), heap_);
}

WinHeap::WinHeap(HANDLE heap)
    : heap_(heap), own_heap_(false), heap_lock_held_(false) {
}

WinHeap::~WinHeap() {
  if (!own_heap_)
    return;
  DCHECK_NE(static_cast<HANDLE>(NULL), heap_);
  ::HeapDestroy(heap_);
}

HeapType WinHeap::GetHeapType() const {
  return kWinHeap;
}

uint32_t WinHeap::GetHeapFeatures() const {
  return kHeapSupportsGetAllocationSize;
}

void* WinHeap::Allocate(uint32_t bytes) {
  DCHECK_NE(static_cast<HANDLE>(NULL), heap_);
  void* alloc = ::HeapAlloc(heap_, 0, bytes);
  return alloc;
}

bool WinHeap::Free(void* alloc) {
  DCHECK_NE(static_cast<HANDLE>(NULL), heap_);

  // According to the MSDN documentation about HeapFree the return value needs
  // to be cast to BOOLEAN in order to support Windows XP:
  //     Prior to Windows Vista, HeapFree has a bug: only the low byte of the
  //     return value is correctly indicative of the result.  This is because
  //     the implementation returns type BOOLEAN (BYTE) despite the prototype
  //     declaring it as returning BOOL (int).
  //
  //     If you care about the return value of HeapFree, and you need to support
  //     XP and 2003, cast the return value to BOOLEAN before checking it.
  if (static_cast<BOOLEAN>(::HeapFree(heap_, 0, alloc)) != TRUE)
    return false;
  return true;
}

bool WinHeap::IsAllocated(const void* alloc) {
  return false;
}

uint32_t WinHeap::GetAllocationSize(const void* alloc) {
  return ::HeapSize(heap_, 0, alloc);
}

void WinHeap::Lock() {
  DCHECK_NE(static_cast<HANDLE>(NULL), heap_);
  lock_.Acquire();
  if (lock_.recursion() == 1) {
    DCHECK(!heap_lock_held_);
    if (::HeapLock(heap_) == TRUE)
      heap_lock_held_ = true;
  }
}

void WinHeap::Unlock() {
  DCHECK_NE(static_cast<HANDLE>(NULL), heap_);
  lock_.AssertAcquired();
  if (lock_.recursion() == 1 && heap_lock_held_) {
    ::HeapUnlock(heap_);
    heap_lock_held_ = false;
  }
  lock_.Release();
}

bool WinHeap::TryLock() {
  return lock_.Try();
}

}  // namespace heaps
}  // namespace asan
}  // namespace agent
