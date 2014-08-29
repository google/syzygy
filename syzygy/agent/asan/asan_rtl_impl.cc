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
#include "syzygy/agent/asan/asan_rtl_utils.h"
#include "syzygy/agent/asan/asan_runtime.h"
#include "syzygy/agent/asan/heap_manager.h"
#include "syzygy/agent/asan/shadow.h"
#include "syzygy/agent/asan/stack_capture.h"
#include "syzygy/agent/asan/windows_heap_adapter.h"
#include "syzygy/agent/common/scoped_last_error_keeper.h"

namespace {

using agent::asan::AsanErrorInfo;
using agent::asan::AsanRuntime;
using agent::asan::HeapManagerInterface;
using agent::asan::Shadow;
using agent::asan::TestStructure;
using agent::asan::WindowsHeapAdapter;

HANDLE process_heap = NULL;
HeapManagerInterface::HeapId asan_process_heap = NULL;

// The asan runtime manager.
AsanRuntime* asan_runtime = NULL;

}  // namespace

namespace agent {
namespace asan {

void SetUpRtl(AsanRuntime* runtime) {
  DCHECK(runtime != NULL);
  asan_runtime = runtime;
  process_heap = ::GetProcessHeap();

  // Set the instance used by the helper functions.
  SetAsanRuntimeInstance(runtime);

  asan_process_heap = runtime->GetProcessHeap();
}

void TearDownRtl() {
  DCHECK_NE(static_cast<HANDLE>(NULL), process_heap);
  DCHECK_NE(static_cast<HeapManagerInterface::HeapId>(NULL), asan_process_heap);
  process_heap = NULL;
  asan_process_heap = NULL;
}

}  // namespace asan
}  // namespace agent

extern "C" {

HANDLE WINAPI asan_GetProcessHeap() {
  DCHECK_NE(static_cast<HANDLE>(NULL), process_heap);
  DCHECK_NE(static_cast<HeapManagerInterface::HeapId>(NULL), asan_process_heap);
  return reinterpret_cast<HANDLE>(asan_process_heap);
}

HANDLE WINAPI asan_HeapCreate(DWORD options,
                              SIZE_T initial_size,
                              SIZE_T maximum_size) {
  return WindowsHeapAdapter::HeapCreate(options, initial_size, maximum_size);
}

BOOL WINAPI asan_HeapDestroy(HANDLE heap) {
  DCHECK(process_heap != NULL);
  if (heap == process_heap)
    return ::HeapDestroy(heap);

  return WindowsHeapAdapter::HeapDestroy(heap);
}

LPVOID WINAPI asan_HeapAlloc(HANDLE heap,
                             DWORD flags,
                             SIZE_T bytes) {
  DCHECK(process_heap != NULL);
  if (heap == process_heap)
    return ::HeapAlloc(heap, flags, bytes);

  return WindowsHeapAdapter::HeapAlloc(heap, flags, bytes);
}

LPVOID WINAPI asan_HeapReAlloc(HANDLE heap,
                               DWORD flags,
                               LPVOID mem,
                               SIZE_T bytes) {
  DCHECK(process_heap != NULL);
  if (heap == process_heap)
    return ::HeapReAlloc(heap, flags, mem, bytes);

  return WindowsHeapAdapter::HeapReAlloc(heap, flags, mem, bytes);
}

BOOL WINAPI asan_HeapFree(HANDLE heap,
                          DWORD flags,
                          LPVOID mem) {
  DCHECK(process_heap != NULL);
  if (heap == process_heap)
    return ::HeapFree(heap, flags, mem);

  return WindowsHeapAdapter::HeapFree(heap, flags, mem);
}

SIZE_T WINAPI asan_HeapSize(HANDLE heap,
                            DWORD flags,
                            LPCVOID mem) {
  DCHECK(process_heap != NULL);
  if (heap == process_heap)
    return ::HeapSize(heap, flags, mem);

  return WindowsHeapAdapter::HeapSize(heap, flags, mem);
}

BOOL WINAPI asan_HeapValidate(HANDLE heap,
                              DWORD flags,
                              LPCVOID mem) {
  DCHECK(process_heap != NULL);
  if (heap == process_heap)
    return ::HeapValidate(heap, flags, mem);

  return WindowsHeapAdapter::HeapValidate(heap, flags, mem);
}

SIZE_T WINAPI asan_HeapCompact(HANDLE heap,
                               DWORD flags) {
  DCHECK(process_heap != NULL);
  if (heap == process_heap)
    return ::HeapCompact(heap, flags);

  return WindowsHeapAdapter::HeapCompact(heap, flags);
}

BOOL WINAPI asan_HeapLock(HANDLE heap) {
  DCHECK(process_heap != NULL);
  if (heap == process_heap)
    return ::HeapLock(heap);

  return WindowsHeapAdapter::HeapLock(heap);
}

BOOL WINAPI asan_HeapUnlock(HANDLE heap) {
  DCHECK(process_heap != NULL);
  if (heap == process_heap)
    return ::HeapUnlock(heap);

  return WindowsHeapAdapter::HeapUnlock(heap);
}

BOOL WINAPI asan_HeapWalk(HANDLE heap,
                          LPPROCESS_HEAP_ENTRY entry) {
  DCHECK(process_heap != NULL);
  if (heap == process_heap)
    return ::HeapWalk(heap, entry);

  return WindowsHeapAdapter::HeapWalk(heap, entry);
}

BOOL WINAPI asan_HeapSetInformation(
    HANDLE heap, HEAP_INFORMATION_CLASS info_class,
    PVOID info, SIZE_T info_length) {
  DCHECK(process_heap != NULL);
  if (heap == NULL || heap == process_heap)
    return ::HeapSetInformation(heap, info_class, info, info_length);

  return WindowsHeapAdapter::HeapSetInformation(heap, info_class, info,
      info_length);
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

  return WindowsHeapAdapter::HeapQueryInformation(heap,
                                                  info_class,
                                                  info,
                                                  info_length,
                                                  return_length);
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
