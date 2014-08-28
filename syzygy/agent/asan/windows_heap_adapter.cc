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

#include "syzygy/agent/asan/windows_heap_adapter.h"

#include <algorithm>

#include "base/logging.h"
#include "syzygy/agent/asan/heap_manager.h"

namespace agent {
namespace asan {

namespace {

// Cast a heap ID into a HANDLE.
// @param heap_id The heap ID to cast.
// @returns the heap ID casted as an HANDLE.
HANDLE HeapIdToHandle(HeapManagerInterface::HeapId heap_id) {
  DCHECK_NE(static_cast<HeapManagerInterface::HeapId>(NULL), heap_id);
  COMPILE_ASSERT(sizeof(HANDLE) == sizeof(HeapManagerInterface::HeapId),
                 size_of_handle_and_heap_id_are_different);
  return reinterpret_cast<HANDLE>(heap_id);
}

// Cast a HANDLE into a heap ID.
// @param heap The HANDLE to cast.
// @returns the HANDLE casted as a heap ID.
HeapManagerInterface::HeapId HandleToHeapId(HANDLE heap) {
  DCHECK_NE(static_cast<HANDLE>(NULL), heap);
  return reinterpret_cast<HeapManagerInterface::HeapId>(heap);
}

}  // namespace

HeapManagerInterface* WindowsHeapAdapter::heap_manager_ = NULL;

void WindowsHeapAdapter::SetUp(HeapManagerInterface* heap_manager) {
  DCHECK_NE(reinterpret_cast<HeapManagerInterface*>(NULL), heap_manager);
  DCHECK_EQ(reinterpret_cast<HeapManagerInterface*>(NULL), heap_manager_);
  heap_manager_ = heap_manager;
}

void WindowsHeapAdapter::TearDown() {
  DCHECK_NE(reinterpret_cast<HeapManagerInterface*>(NULL), heap_manager_);
  heap_manager_ = NULL;
}

HANDLE WindowsHeapAdapter::HeapCreate(DWORD options,
                                      SIZE_T initial_size,
                                      SIZE_T maximum_size) {
  DCHECK_NE(reinterpret_cast<HeapManagerInterface*>(NULL), heap_manager_);
  return HeapIdToHandle(heap_manager_->CreateHeap());
}

BOOL WindowsHeapAdapter::HeapDestroy(HANDLE heap) {
  DCHECK_NE(reinterpret_cast<HeapManagerInterface*>(NULL), heap_manager_);
  return heap_manager_->DestroyHeap(HandleToHeapId(heap));
}

LPVOID WindowsHeapAdapter::HeapAlloc(HANDLE heap, DWORD flags, SIZE_T bytes) {
  DCHECK_NE(reinterpret_cast<HeapManagerInterface*>(NULL), heap_manager_);
  LPVOID alloc = heap_manager_->Allocate(HandleToHeapId(heap), bytes);
  if (alloc != NULL && (flags & HEAP_ZERO_MEMORY) != 0 && bytes > 0)
    ::memset(alloc, 0, bytes);
  return alloc;
}

LPVOID WINAPI WindowsHeapAdapter::HeapReAlloc(HANDLE heap,
                                              DWORD flags,
                                              LPVOID mem,
                                              SIZE_T bytes) {
  DCHECK_NE(reinterpret_cast<HeapManagerInterface*>(NULL), heap_manager_);
  // Always fail in-place reallocation requests.
  if ((flags & HEAP_REALLOC_IN_PLACE_ONLY) != 0)
    return NULL;

  void* new_mem = WindowsHeapAdapter::HeapAlloc(heap, flags, bytes);
  // Bail early if the new allocation didn't succeed and avoid freeing the
  // existing allocation.
  if (new_mem == NULL)
    return NULL;

  if (mem != NULL) {
    ::memcpy(new_mem, mem, std::min(bytes, HeapSize(heap, 0, mem)));
    WindowsHeapAdapter::HeapFree(heap, flags, mem);
  }

  return new_mem;
}

BOOL WindowsHeapAdapter::HeapFree(HANDLE heap, DWORD flags, LPVOID mem) {
  DCHECK_NE(reinterpret_cast<HeapManagerInterface*>(NULL), heap_manager_);
  return heap_manager_->Free(HandleToHeapId(heap), mem);
}

SIZE_T WindowsHeapAdapter::HeapSize(HANDLE heap, DWORD flags, LPCVOID mem) {
  DCHECK_NE(reinterpret_cast<HeapManagerInterface*>(NULL), heap_manager_);
  return heap_manager_->Size(HandleToHeapId(heap), mem);
}

BOOL WindowsHeapAdapter::HeapValidate(HANDLE heap, DWORD flags, LPCVOID mem) {
  DCHECK_NE(reinterpret_cast<HeapManagerInterface*>(NULL), heap_manager_);
  // This function isn't supported by the by the heap managers and doesn't
  // really makes sense in an ASan build.
  return TRUE;
}

SIZE_T WindowsHeapAdapter::HeapCompact(HANDLE heap, DWORD flags) {
  DCHECK_NE(reinterpret_cast<HeapManagerInterface*>(NULL), heap_manager_);
  // This function isn't supported by the by the heap managers and doesn't
  // really makes sense in an ASan build.
  return 0;
}

BOOL WindowsHeapAdapter::HeapLock(HANDLE heap) {
  DCHECK_NE(reinterpret_cast<HeapManagerInterface*>(NULL), heap_manager_);
  heap_manager_->Lock(HandleToHeapId(heap));
  return TRUE;
}

BOOL WindowsHeapAdapter::HeapUnlock(HANDLE heap) {
  DCHECK_NE(reinterpret_cast<HeapManagerInterface*>(NULL), heap_manager_);
  heap_manager_->Unlock(HandleToHeapId(heap));
  return TRUE;
}

BOOL WindowsHeapAdapter::HeapWalk(HANDLE heap, LPPROCESS_HEAP_ENTRY entry) {
  DCHECK_NE(reinterpret_cast<HeapManagerInterface*>(NULL), heap_manager_);
  // TODO(sebmarchand): Add walking support to the heaps if needed.
  return FALSE;
}

BOOL WindowsHeapAdapter::HeapSetInformation(HANDLE heap,
                                            HEAP_INFORMATION_CLASS info_class,
                                            PVOID info,
                                            SIZE_T info_length) {
  DCHECK_NE(reinterpret_cast<HeapManagerInterface*>(NULL), heap_manager_);
  // This function isn't supported by the by the heap managers and doesn't
  // really makes sense in an ASan build.
  // Return true to avoid crashing if a process try to set some heap information
  // at startup.
  return TRUE;
}

BOOL WindowsHeapAdapter::HeapQueryInformation(HANDLE heap,
                                              HEAP_INFORMATION_CLASS info_class,
                                              PVOID info,
                                              SIZE_T info_length,
                                              PSIZE_T return_length) {
  DCHECK_NE(reinterpret_cast<HeapManagerInterface*>(NULL), heap_manager_);
  // This function isn't supported by the by the heap managers and doesn't
  // really makes sense in an ASan build.
  return FALSE;
}

}  // namespace asan
}  // namespace agent
