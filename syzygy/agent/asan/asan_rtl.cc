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

#include <windows.h>  // NOLINT

#include <algorithm>
#include <list>

#include "base/at_exit.h"
#include "base/bind.h"
#include "base/logging.h"
#include "base/memory/scoped_ptr.h"
#include "syzygy/agent/asan/asan_heap.h"
#include "syzygy/agent/asan/asan_shadow.h"
#include "syzygy/agent/common/dlist.h"

namespace {

typedef base::Callback<void()> AsanCallBack;
AsanCallBack asan_callback;

// A helper function to find if an intrusive list contains a given entry.
// @param list The list in which we want to look for the entry.
// @param item The entry we want to look for.
// @returns true if the list contains this entry, false otherwise.
bool HeapListContainsEntry(const LIST_ENTRY* list, const LIST_ENTRY* item) {
  LIST_ENTRY* current = list->Flink;
  while (current != NULL) {
    LIST_ENTRY* next_item = NULL;
    if (current->Flink != list) {
      next_item = current->Flink;
    }

    if (current == item) {
      return true;
    }

    current = next_item;
  }
  return false;
}

void OnAsanError() {
  ::RaiseException(EXCEPTION_ACCESS_VIOLATION, 0, 0, NULL);
}

}  // namespace

extern "C" {
using agent::asan::HeapProxy;

static HANDLE process_heap = NULL;
LIST_ENTRY heap_proxy_dlist = {};

HANDLE WINAPI asan_HeapCreate(DWORD options,
                              SIZE_T initial_size,
                              SIZE_T maximum_size) {
  scoped_ptr<HeapProxy> proxy(new HeapProxy());
  if (!proxy->Create(options, initial_size, maximum_size))
    proxy.reset();

  InsertTailList(&heap_proxy_dlist, HeapProxy::ToListEntry(proxy.get()));

  return HeapProxy::ToHandle(proxy.release());
}

BOOL WINAPI asan_HeapDestroy(HANDLE heap) {
  if (heap == process_heap)
    return ::HeapDestroy(heap);

  HeapProxy* proxy = HeapProxy::FromHandle(heap);
  if (!proxy)
    return FALSE;

  DCHECK(HeapListContainsEntry(&heap_proxy_dlist, HeapProxy::ToListEntry(proxy))
      == TRUE);
  RemoveEntryList(HeapProxy::ToListEntry(proxy));

  if (proxy->Destroy()) {
    delete proxy;
    return TRUE;
  }

  return FALSE;
}

LPVOID WINAPI asan_HeapAlloc(HANDLE heap,
                             DWORD flags,
                             SIZE_T bytes) {
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
  if (heap == process_heap)
    return ::HeapFree(heap, flags, mem);

  HeapProxy* proxy = HeapProxy::FromHandle(heap);
  if (!proxy)
    return FALSE;

  return proxy->Free(flags, mem);
}

SIZE_T WINAPI asan_HeapSize(HANDLE heap,
                            DWORD flags,
                            LPCVOID mem) {
  if (heap == process_heap)
    return ::HeapSize(heap, flags, mem);

  HeapProxy* proxy = HeapProxy::FromHandle(heap);
  if (!proxy)
    return -1;

  return proxy->Size(flags, mem);
}

BOOL WINAPI asan_HeapValidate(HANDLE heap,
                              DWORD flags,
                              LPCVOID mem) {
  if (heap == process_heap)
    return ::HeapValidate(heap, flags, mem);

  HeapProxy* proxy = HeapProxy::FromHandle(heap);
  if (!proxy)
    return FALSE;

  return proxy->Validate(flags, mem);
}

SIZE_T WINAPI asan_HeapCompact(HANDLE heap,
                               DWORD flags) {
  if (heap == process_heap)
    return ::HeapCompact(heap, flags);

  HeapProxy* proxy = HeapProxy::FromHandle(heap);
  if (!proxy)
    return 0;

  return proxy->Compact(flags);
}

BOOL WINAPI asan_HeapLock(HANDLE heap) {
  if (heap == process_heap)
    return ::HeapLock(heap);

  HeapProxy* proxy = HeapProxy::FromHandle(heap);
  if (!proxy)
    return FALSE;

  return proxy->Lock();
}

BOOL WINAPI asan_HeapUnlock(HANDLE heap) {
  if (heap == process_heap)
    return ::HeapUnlock(heap);

  HeapProxy* proxy = HeapProxy::FromHandle(heap);
  if (!proxy)
    return FALSE;

  return proxy->Unlock();
}

BOOL WINAPI asan_HeapWalk(HANDLE heap,
                          LPPROCESS_HEAP_ENTRY entry) {
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
  if (heap == process_heap)
    return ::HeapSetInformation(heap, info_class, info, info_length);

  HeapProxy* proxy = HeapProxy::FromHandle(heap);
  if (!proxy)
    return FALSE;

  return proxy->SetInformation(info_class, info, info_length);
}

BOOL WINAPI asan_HeapQueryInformation(
    HANDLE heap, HEAP_INFORMATION_CLASS info_class,
    PVOID info, SIZE_T info_length, PSIZE_T return_length) {
  if (heap == process_heap) {
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

void WINAPI asan_SetCallBack(void (*callback)()) {
  asan_callback = base::Bind(callback);
  return;
}

BOOL WINAPI DllMain(HMODULE instance, DWORD reason, LPVOID reserved) {
  // Our AtExit manager required by base.
  static base::AtExitManager* at_exit = NULL;

  switch (reason) {
    case DLL_PROCESS_ATTACH:
      DCHECK(at_exit == NULL);
      at_exit = new base::AtExitManager();
      InitializeListHead(&heap_proxy_dlist);
      asan_SetCallBack(&OnAsanError);
      process_heap = GetProcessHeap();
      break;

    case DLL_THREAD_ATTACH:
      break;

    case DLL_THREAD_DETACH:
      break;

    case DLL_PROCESS_DETACH:
      DCHECK(IsListEmpty(&heap_proxy_dlist) == TRUE);
      DCHECK(at_exit != NULL);
      DCHECK(asan_callback.is_null() == FALSE);
      asan_callback.Reset();
      delete at_exit;
      at_exit = NULL;
      break;

    default:
      NOTREACHED();
      break;
  }

  return TRUE;
}
}  // extern "C"

namespace agent {
namespace asan {

void __cdecl CheckAccessSlow(const uint8* location) {
  if (!Shadow::IsAccessible(location)) {
    // Iterates over the HeapProxy list to find a memory block containing this
    // address.
    LIST_ENTRY* item = heap_proxy_dlist.Flink;
    while (item != NULL) {
      LIST_ENTRY* next_item = NULL;
      if (item->Flink != &heap_proxy_dlist) {
        next_item = item->Flink;
      }

      if (HeapProxy::FromListEntry(item)->OnBadAccess(location)) {
        break;
      }

      item = next_item;
    }
    // If we didn't found a heap with a memory block containing this address we
    // report an unknown crash.
    if (item == NULL) {
      HeapProxy::ReportUnknownError(location);
    }

    // Call the callback to handle this error.
    DCHECK(asan_callback.is_null() == FALSE);
    asan_callback.Run();
  }
}

}  // namespace asan
}  // namespace agent

// On entry, eax is the byte to check, e.g. the last byte accessed.
// On stack above the return address we have the saved values of eax.
extern "C" __declspec(naked) void asan_check_access() {
  __asm {
    // Save the flags and save eax for the slow case.
    pushfd
    push eax

    // Check for zero shadow - fast case.
    shr eax, 3
    mov al, byte ptr[eax + agent::asan::Shadow::shadow_]
    test al, 0xFF

    // Uh-oh - non-zero shadow byte means we go to the slow case.
    jne non_zero_shadow

    // Drop the slow path's copy of the address.
    add esp, 4
    // Restore flags and original eax.
    popfd
    mov eax, DWORD PTR[esp + 4]
    ret 4

 non_zero_shadow:
    // Save ecx/edx, they're caller-save.
    push edx
    push ecx
    // Push the address to check.
    push dword ptr[esp + 8]
    call agent::asan::CheckAccessSlow
    add esp, 4

    // Restore everything.
    pop ecx
    pop edx
    add esp, 4
    popfd
    mov eax, DWORD PTR[esp + 4]
    ret 4
  }
}
