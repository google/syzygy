// Copyright 2012 Google Inc. All Rights Reserved.
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

#include "syzygy/agent/asan/asan_rtl_impl.h"

#include "base/bind.h"
#include "base/callback.h"
#include "base/logging.h"
#include "base/debug/alias.h"
#include "base/memory/scoped_ptr.h"
#include "syzygy/agent/asan/asan_heap.h"
#include "syzygy/agent/asan/asan_rtl_utils.h"
#include "syzygy/agent/asan/asan_runtime.h"
#include "syzygy/agent/asan/shadow.h"
#include "syzygy/agent/asan/stack_capture.h"
#include "syzygy/agent/common/scoped_last_error_keeper.h"

namespace {

using agent::asan::AsanErrorInfo;
using agent::asan::AsanRuntime;
using agent::asan::HeapProxy;
using agent::asan::Shadow;
using agent::asan::TestStructure;

HANDLE process_heap = NULL;
scoped_ptr<HeapProxy> asan_process_heap;

// The asan runtime manager.
AsanRuntime* asan_runtime = NULL;

}  // namespace

namespace agent {
namespace asan {

void SetUpRtl(AsanRuntime* runtime) {
  DCHECK(runtime != NULL);
  asan_runtime = runtime;
  process_heap = ::GetProcessHeap();

  asan_process_heap.reset(new HeapProxy());
  asan_process_heap->UseHeap(process_heap);
  asan_runtime->AddHeap(asan_process_heap.get());

  // Set the instance used by the helper functions.
  SetAsanRuntimeInstance(runtime);
}

void TearDownRtl() {
  DCHECK_NE(reinterpret_cast<HANDLE>(NULL), process_heap);
  DCHECK_NE(reinterpret_cast<HeapProxy*>(NULL), asan_process_heap);

  if (!asan_process_heap->Destroy()) {
    LOG(ERROR) << "Unable to destroy the process heap.";
    return;
  }

  // This needs to happen after the heap is destroyed so that the error handling
  // callback is still available to report any errors encountered while cleaning
  // up the quarantine.
  asan_runtime->RemoveHeap(asan_process_heap.get());

  asan_process_heap.reset(NULL);
  process_heap = NULL;
}

}  // namespace asan
}  // namespace agent

extern "C" {

HANDLE WINAPI asan_GetProcessHeap() {
  DCHECK_NE(reinterpret_cast<HeapProxy*>(NULL), asan_process_heap.get());
  DCHECK_NE(reinterpret_cast<HANDLE>(NULL), asan_process_heap->heap());
  DCHECK_EQ(process_heap, asan_process_heap->heap());
  return HeapProxy::ToHandle(asan_process_heap.get());
}

HANDLE WINAPI asan_HeapCreate(DWORD options,
                              SIZE_T initial_size,
                              SIZE_T maximum_size) {
  DCHECK(asan_runtime != NULL);
  scoped_ptr<HeapProxy> proxy(new HeapProxy());
  if (!proxy->Create(options, initial_size, maximum_size))
    return NULL;

  asan_runtime->AddHeap(proxy.get());

  return HeapProxy::ToHandle(proxy.release());
}

BOOL WINAPI asan_HeapDestroy(HANDLE heap) {
  DCHECK(process_heap != NULL);
  if (heap == process_heap)
    return ::HeapDestroy(heap);

  HeapProxy* proxy = HeapProxy::FromHandle(heap);
  if (!proxy)
    return FALSE;

  // Clean up the heap before removing it, so that it remains attached to our
  // callback in the event of any heap errors.
  bool success = proxy->Destroy();
  asan_runtime->RemoveHeap(proxy);
  delete proxy;

  if (success)
    return TRUE;

  return FALSE;
}

LPVOID WINAPI asan_HeapAlloc(HANDLE heap,
                             DWORD flags,
                             SIZE_T bytes) {
  DCHECK(process_heap != NULL);
  if (heap == process_heap)
    return ::HeapAlloc(heap, flags, bytes);

  HeapProxy* proxy = HeapProxy::FromHandle(heap);
  if (!proxy)
    return NULL;

  return proxy->Alloc(flags, bytes);
}

LPVOID WINAPI asan_HeapReAlloc(HANDLE heap,
                               DWORD flags,
                               LPVOID mem,
                               SIZE_T bytes) {
  DCHECK(process_heap != NULL);
  if (heap == process_heap)
    return ::HeapReAlloc(heap, flags, mem, bytes);

  HeapProxy* proxy = HeapProxy::FromHandle(heap);
  if (!proxy)
    return NULL;

  return proxy->ReAlloc(flags, mem, bytes);
}

BOOL WINAPI asan_HeapFree(HANDLE heap,
                          DWORD flags,
                          LPVOID mem) {
  DCHECK(process_heap != NULL);
  if (heap == process_heap)
    return ::HeapFree(heap, flags, mem);

  HeapProxy* proxy = HeapProxy::FromHandle(heap);
  if (!proxy)
    return FALSE;

  if (!proxy->Free(flags, mem))
    return false;

  return true;
}

SIZE_T WINAPI asan_HeapSize(HANDLE heap,
                            DWORD flags,
                            LPCVOID mem) {
  DCHECK(process_heap != NULL);
  if (heap == process_heap)
    return ::HeapSize(heap, flags, mem);

  HeapProxy* proxy = HeapProxy::FromHandle(heap);
  if (!proxy)
    return static_cast<SIZE_T>(-1);

  return proxy->Size(flags, mem);
}

BOOL WINAPI asan_HeapValidate(HANDLE heap,
                              DWORD flags,
                              LPCVOID mem) {
  DCHECK(process_heap != NULL);
  if (heap == process_heap)
    return ::HeapValidate(heap, flags, mem);

  HeapProxy* proxy = HeapProxy::FromHandle(heap);
  if (!proxy)
    return FALSE;

  return proxy->Validate(flags, mem);
}

SIZE_T WINAPI asan_HeapCompact(HANDLE heap,
                               DWORD flags) {
  DCHECK(process_heap != NULL);
  if (heap == process_heap)
    return ::HeapCompact(heap, flags);

  HeapProxy* proxy = HeapProxy::FromHandle(heap);
  if (!proxy)
    return 0;

  return proxy->Compact(flags);
}

BOOL WINAPI asan_HeapLock(HANDLE heap) {
  DCHECK(process_heap != NULL);
  if (heap == process_heap)
    return ::HeapLock(heap);

  HeapProxy* proxy = HeapProxy::FromHandle(heap);
  if (!proxy)
    return FALSE;

  return proxy->Lock();
}

BOOL WINAPI asan_HeapUnlock(HANDLE heap) {
  DCHECK(process_heap != NULL);
  if (heap == process_heap)
    return ::HeapUnlock(heap);

  HeapProxy* proxy = HeapProxy::FromHandle(heap);
  if (!proxy)
    return FALSE;

  return proxy->Unlock();
}

BOOL WINAPI asan_HeapWalk(HANDLE heap,
                          LPPROCESS_HEAP_ENTRY entry) {
  DCHECK(process_heap != NULL);
  if (heap == process_heap)
    return ::HeapWalk(heap, entry);

  HeapProxy* proxy = HeapProxy::FromHandle(heap);
  if (!proxy)
    return FALSE;

  return proxy->Walk(entry);
}

BOOL WINAPI asan_HeapSetInformation(
    HANDLE heap, HEAP_INFORMATION_CLASS info_class,
    PVOID info, SIZE_T info_length) {
  DCHECK(process_heap != NULL);
  if (heap == NULL || heap == process_heap)
    return ::HeapSetInformation(heap, info_class, info, info_length);

  HeapProxy* proxy = HeapProxy::FromHandle(heap);
  if (!proxy)
    return FALSE;

  return proxy->SetInformation(info_class, info, info_length);
}

BOOL WINAPI asan_HeapQueryInformation(
    HANDLE heap, HEAP_INFORMATION_CLASS info_class,
    PVOID info, SIZE_T info_length, PSIZE_T return_length) {
  DCHECK(process_heap != NULL);
  if (heap == NULL || heap == process_heap) {
    return ::HeapQueryInformation(heap,
                                  info_class,
                                  info,
                                  info_length,
                                  return_length);
  }

  HeapProxy* proxy = HeapProxy::FromHandle(heap);
  if (!proxy)
    return FALSE;

  bool ret = proxy->QueryInformation(info_class,
                                     info,
                                     info_length,
                                     return_length);
  return ret == true;
}

void WINAPI asan_SetCallBack(AsanErrorCallBack callback) {
  DCHECK(asan_runtime != NULL);
  asan_runtime->SetErrorCallBack(base::Bind(callback));
}

// Unittesting seam.
AsanRuntime* WINAPI asan_GetActiveRuntime() {
  return asan_runtime;
}

}  // extern "C"
