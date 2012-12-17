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
#include "base/atomicops.h"
#include "base/bind.h"
#include "base/command_line.h"
#include "base/environment.h"
#include "base/logging.h"
#include "base/stringprintf.h"
#include "base/utf_string_conversions.h"
#include "base/memory/scoped_ptr.h"
#include "base/synchronization/lock.h"
#include "syzygy/agent/asan/asan_flags.h"
#include "syzygy/agent/asan/asan_heap.h"
#include "syzygy/agent/asan/asan_logger.h"
#include "syzygy/agent/asan/asan_shadow.h"
#include "syzygy/agent/common/dlist.h"
#include "syzygy/trace/protocol/call_trace_defs.h"
#include "syzygy/trace/rpc/logger_rpc.h"
#include "syzygy/trace/rpc/rpc_helpers.h"
namespace {

using agent::asan::HeapProxy;
using agent::asan::AsanLogger;

// Our AtExit manager required by base.
base::AtExitManager* at_exit = NULL;

// The global asan callback functor.
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

std::wstring GetInstanceId() {
  scoped_ptr<base::Environment> env(base::Environment::Create());
  CHECK(env.get() != NULL);
  std::string value;
  env->GetVar(kSyzygyRpcInstanceIdEnvVar, &value);
  return UTF8ToWide(value);
}

void SetUpAtExitManager() {
  DCHECK(at_exit == NULL);
  at_exit = new base::AtExitManager();
  CHECK(at_exit != NULL);
}

void TearDownAtExitManager() {
  DCHECK(at_exit != NULL);
  delete at_exit;
  at_exit = NULL;
}

void SetUpLogger() {
  DCHECK(AsanLogger::Instance() == NULL);

  // Setup variables we're going to use.
  scoped_ptr<base::Environment> env(base::Environment::Create());
  scoped_ptr<AsanLogger> client(new AsanLogger);
  CHECK(env.get() != NULL);
  CHECK(client.get() != NULL);

  // Initialize the client.
  std::string instance_id;
  if (env->GetVar(kSyzygyRpcInstanceIdEnvVar, &instance_id))
    client->set_instance_id(UTF8ToWide(instance_id));
  client->Init();

  // Register the client singleton instance.
  AsanLogger::SetInstance(client.release());
}

void TearDownLogger() {
  AsanLogger* temp_instance = AsanLogger::Instance();
  DCHECK(temp_instance != NULL);
  AsanLogger::SetInstance(NULL);
  delete temp_instance;
}

}  // namespace

extern "C" {
using agent::asan::FlagsManager;

static HANDLE process_heap = NULL;
base::Lock heap_proxy_list_lock;
LIST_ENTRY heap_proxy_dlist = {};  // Under heap_proxy_list_lock.

HANDLE WINAPI asan_HeapCreate(DWORD options,
                              SIZE_T initial_size,
                              SIZE_T maximum_size) {
  scoped_ptr<HeapProxy> proxy(new HeapProxy());
  if (!proxy->Create(options, initial_size, maximum_size))
    proxy.reset();

  base::AutoLock lock(heap_proxy_list_lock);
  InsertTailList(&heap_proxy_dlist, HeapProxy::ToListEntry(proxy.get()));

  return HeapProxy::ToHandle(proxy.release());
}

BOOL WINAPI asan_HeapDestroy(HANDLE heap) {
  if (heap == process_heap)
    return ::HeapDestroy(heap);

  HeapProxy* proxy = HeapProxy::FromHandle(heap);
  if (!proxy)
    return FALSE;

  base::AutoLock lock(heap_proxy_list_lock);
  DCHECK(HeapListContainsEntry(&heap_proxy_dlist,
                               HeapProxy::ToListEntry(proxy)));
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
  switch (reason) {
    case DLL_PROCESS_ATTACH:
      // Create the At-Exit manager.
      SetUpAtExitManager();

      // Initialize the command-line structures. This is needed so that
      // SetUpLogger() can include the command-line in the message announcing
      // this process. Note: this is mostly for debugging purposes.
      CommandLine::Init(0, NULL);

      // Setup the "global" state.
      SetUpLogger();
      InitializeListHead(&heap_proxy_dlist);
      FlagsManager::Instance()->InitializeFlagsWithEnvVar();
      asan_SetCallBack(&OnAsanError);
      process_heap = GetProcessHeap();
      break;

    case DLL_THREAD_ATTACH:
      // Nothing to do here.
      break;

    case DLL_THREAD_DETACH:
      // Nothing to do here.
      break;

    case DLL_PROCESS_DETACH:
      // This should be the last thing called in the agent DLL before it
      // gets unloaded. Everything should otherwise have been initialized
      // and we're now just cleaning it up again.
      DCHECK(asan_callback.is_null() == FALSE);
      // We should check that all the heap have been destroyed but this is not
      // the case in Chrome, so the heap list may not be empty here.
      asan_callback.Reset();
      TearDownLogger();
      TearDownAtExitManager();
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

// Report a bad @p access_mode access of @p access_size at the address
// @p location.
void __stdcall ReportBadMemoryAccess(const uint8* location,
                                     HeapProxy::AccessMode access_mode,
                                     size_t access_size) {
  // Iterates over the HeapProxy list to find a memory block containing this
  // address.
  base::AutoLock lock(heap_proxy_list_lock);
  LIST_ENTRY* item = heap_proxy_dlist.Flink;
  while (item != NULL) {
    LIST_ENTRY* next_item = NULL;
    if (item->Flink != &heap_proxy_dlist) {
      next_item = item->Flink;
    }
    if (HeapProxy::FromListEntry(item)->OnBadAccess(location,
                                                    access_mode,
                                                    access_size)) {
      break;
    }
    item = next_item;
  }
  // If we didn't find a heap with a memory block containing this address we
  // report an unknown crash.
  if (item == NULL) {
    HeapProxy::ReportUnknownError(location,
                                  access_mode,
                                  access_size);
  }
  // Call the callback to handle this error.
  DCHECK_EQ(false, asan_callback.is_null());
  asan_callback.Run();
}

}  // namespace asan
}  // namespace agent

// Generates the asan check access functions. The name of the generated method
// will be asan_check_(@p access_size)_byte_(@p access_mode_str)().
// @param access_size The size of the access (in byte).
// @param access_mode_str The string representing the access mode (read_access
//     or write_access).
// @param access_mode_value The internal value representing this kind of access.
#define ASAN_CHECK_FUNCTION(access_size, access_mode_str, access_mode_value)  \
  extern "C" __declspec(naked)  \
      void asan_check_ ## access_size ## _byte_ ## access_mode_str ## () {  \
    __asm {  \
      /* Save the flags and save eax for the slow case. */  \
      __asm pushfd  \
      __asm push eax  \
      /* Check for zero shadow - fast case. */  \
      __asm shr eax, 3  \
      __asm mov al, BYTE ptr[eax + agent::asan::Shadow::shadow_]  \
      __asm test al, al  \
      __asm jnz check_access_slow  \
      /* Restore flags and original eax. */  \
    __asm restore_eax_and_flags:  \
      __asm add esp, 4  \
      __asm mov eax, DWORD PTR[esp + 8]  \
      __asm popfd  \
      __asm ret 4  \
    __asm check_access_slow:  \
      /* Uh-oh - non-zero shadow byte means we go to the slow case. */  \
      /* Save ecx/edx, they're caller-save. */  \
      __asm push edx  \
      __asm push ecx  \
      /* Push the address to check. */  \
      __asm push DWORD ptr[esp + 8]  \
      __asm call agent::asan::Shadow::IsAccessible  \
      /* We restore ecx and edx before testing the return value. */  \
      __asm pop ecx  \
      __asm pop edx  \
      __asm test al, al  \
      /* We've found a bad access, report this failure. */  \
      __asm jz report_failure  \
      /* Same code as in the restore_eax_and_flags label, we could jump */  \
      /* there but it'll add an instruction. */  \
      __asm add esp, 4  \
      __asm mov eax, DWORD PTR[esp + 8]  \
      __asm popfd  \
      __asm ret 4  \
    __asm report_failure:  \
      /* Push the access size, mode and address and call the function to */  \
      /* report the error. */  \
      __asm push access_size  \
      __asm push access_mode_value  \
      __asm push DWORD ptr[esp + 8]  \
      __asm call agent::asan::ReportBadMemoryAccess  \
      __asm jmp restore_eax_and_flags  \
    }  \
  }

enum AccessMode {
  AsanReadAccess = HeapProxy::ASAN_READ_ACCESS,
  AsanWriteAccess = HeapProxy::ASAN_WRITE_ACCESS,
};

ASAN_CHECK_FUNCTION(1, read_access, AsanReadAccess)
ASAN_CHECK_FUNCTION(2, read_access, AsanReadAccess)
ASAN_CHECK_FUNCTION(4, read_access, AsanReadAccess)
ASAN_CHECK_FUNCTION(8, read_access, AsanReadAccess)
ASAN_CHECK_FUNCTION(10, read_access, AsanReadAccess)
ASAN_CHECK_FUNCTION(16, read_access, AsanReadAccess)
ASAN_CHECK_FUNCTION(32, read_access, AsanReadAccess)
ASAN_CHECK_FUNCTION(1, write_access, AsanWriteAccess)
ASAN_CHECK_FUNCTION(2, write_access, AsanWriteAccess)
ASAN_CHECK_FUNCTION(4, write_access, AsanWriteAccess)
ASAN_CHECK_FUNCTION(8, write_access, AsanWriteAccess)
ASAN_CHECK_FUNCTION(10, write_access, AsanWriteAccess)
ASAN_CHECK_FUNCTION(16, write_access, AsanWriteAccess)
ASAN_CHECK_FUNCTION(32, write_access, AsanWriteAccess)

#undef ASAN_CHECK_FUNCTION
