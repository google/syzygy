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

#include "base/logging.h"
#include "syzygy/agent/asan/asan_heap.h"
#include "syzygy/agent/asan/asan_runtime.h"
#include "syzygy/agent/asan/asan_shadow.h"

namespace {

using agent::asan::AsanRuntime;
using agent::asan::HeapProxy;

HANDLE process_heap = NULL;

// The asan runtime manager.
AsanRuntime* asan_runtime = NULL;

}  // namespace

namespace agent {
namespace asan {

void SetUpRtl(AsanRuntime* runtime) {
  DCHECK(runtime != NULL);
  asan_runtime = runtime;
  process_heap = GetProcessHeap();
}

void TearDownRtl() {
  process_heap = NULL;
}

}  // namespace asan
}  // namespace agent

extern "C" {

HANDLE WINAPI asan_HeapCreate(DWORD options,
                              SIZE_T initial_size,
                              SIZE_T maximum_size) {
  DCHECK(asan_runtime != NULL);
  scoped_ptr<HeapProxy> proxy(new HeapProxy(asan_runtime->stack_cache(),
                                            asan_runtime->logger()));
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

  asan_runtime->RemoveHeap(proxy);

  if (proxy->Destroy()) {
    delete proxy;
    return TRUE;
  }

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

  if (!proxy->Free(flags, mem)) {
    CONTEXT context;
    ::RtlCaptureContext(&context);
    asan_runtime->OnError(&context);
    return false;
  }

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
    return -1;

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

void WINAPI asan_SetCallBack(void (*callback)(CONTEXT*)) {
  DCHECK(asan_runtime != NULL);
  asan_runtime->SetErrorCallBack(callback);
}

}  // extern "C"

namespace agent {
namespace asan {

// Represent the content of the stack before calling the error function.
// The original_* fields store the value of the registers as they were before
// calling the asan hook, the do_not_use_* values are some stack variables used
// by asan but shouldn't be used to produce the stack trace.
// NOTE: As this structure describes the state of the stack at the time
// ReportBadMemoryAccess is called. It is intimately tied to the implementation
// of the asan_check functions.
#pragma pack(push, 1)
struct AsanContext {
  DWORD original_edi;
  DWORD original_esi;
  DWORD original_ebp;
  DWORD do_not_use_esp;
  DWORD original_ebx;
  DWORD do_not_use_edx;
  DWORD original_ecx;
  DWORD do_not_use_eax;
  DWORD original_eflags;
  // This is the location of the bad access for this context.
  DWORD do_not_use_flags;
  void* location;
  DWORD original_eax;
  DWORD original_eip;
  DWORD original_edx;
};
#pragma pack(pop)

// Report a bad access to the memory.
// @param access_mode The mode of the access.
// @param access_size The size of the access.
// @param asan_context The context of the access.
void __stdcall ReportBadMemoryAccess(HeapProxy::AccessMode access_mode,
                                     size_t access_size,
                                     struct AsanContext* asan_context) {
  // Capture the context and restore the value of the register as before calling
  // the asan hook.

  // Capture the current context.
  CONTEXT context = {};

  // We need to call ::RtlCaptureContext if we want SegSS and SegCS to be
  // properly set.
  ::RtlCaptureContext(&context);
  context.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;

  // Restore the original value of the registers.
  context.Eip = asan_context->original_eip;
  context.Eax = asan_context->original_eax;
  context.Ecx = asan_context->original_ecx;
  context.Edx = asan_context->original_edx;
  context.Ebx = asan_context->original_ebx;
  context.Ebp = asan_context->original_ebp;
  context.Esi = asan_context->original_esi;
  context.Edi = asan_context->original_edi;
  context.EFlags = asan_context->original_eflags;

  // Our AsanContext structure is in fact the whole stack frame for the asan
  // hook, to compute the value of esp before the call to the hook we can just
  // calculate the top address of this structure.
  context.Esp = reinterpret_cast<DWORD>(asan_context) + sizeof(AsanContext);

  StackCapture stack;
  stack.InitFromStack();
  // We need to compute a relative stack id so that for the same stack trace
  // we'll get the same value every time even if the modules are loaded at a
  // different base address.
  stack.set_stack_id(stack.ComputeRelativeStackId());

  asan_runtime->ReportAsanErrorDetails(asan_context->location,
                                       context,
                                       stack,
                                       access_mode,
                                       access_size);

  // TODO(sebmarchand): Use the stack id to check if we need to ignore this
  //     error or if this has already been reported. We also may want to have a
  //     flag to allow multiple reports of the same error.

  // Call the callback to handle this error.
  asan_runtime->OnError(&context);
}

}  // namespace asan
}  // namespace agent

// Generates the asan check access functions. The name of the generated method
// will be asan_check_(@p access_size)_byte_(@p access_mode_str)().
// @param access_size The size of the access (in byte).
// @param access_mode_str The string representing the access mode (read_access
//     or write_access).
// @param access_mode_value The internal value representing this kind of access.
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
      /* Save eax as we'll use it to save the value of the flags. */  \
      __asm push eax  \
      /* Save the low byte of the flags into ah. We use this instruction */  \
      /* instead of pushfd/popfd because it's much faster. We also save */  \
      /* the overflow flag into al. We can do this because our hooks are */  \
      /* simple and don't touch the other flags. */  \
      __asm lahf  \
      __asm seto al  \
      /* Save edx for the slow path. */  \
      __asm push edx  \
      /* Check for zero shadow - fast case. */  \
      __asm shr edx, 3  \
      __asm mov dl, BYTE ptr[edx + agent::asan::Shadow::shadow_]  \
      __asm test dl, dl  \
      __asm jnz check_access_slow  \
      /* Restore original edx. */  \
      __asm add esp, 4  \
      __asm mov edx, DWORD PTR[esp + 8]  \
      /* al is set to 1 if the overflow flag was set before the call to */  \
      /* our hook, 0 otherwise. We add 0x7f to it so it'll restore the */  \
      /* flag. */  \
      __asm add al, 0x7f  \
      /* Restore the low byte of the flags. */  \
      __asm sahf  \
      /* Restore original eax */  \
      __asm pop eax  \
      __asm ret 4  \
    __asm check_access_slow:  \
      /* Save flags on stack (keep in eax in the fastpath) */  \
      __asm push eax  \
      /* Uh-oh - non-zero shadow byte means we go to the slow case. */  \
      /* Save ecx, it's caller-save (eax, ecx and edx are caller-save). */  \
      __asm push ecx  \
      /* Push the address to check. */  \
      __asm push DWORD ptr[esp + 8]  \
      __asm call agent::asan::Shadow::IsAccessible  \
      __asm test al, al  \
      __asm pop ecx  \
      /* We've found a bad access, report this failure. */  \
      __asm jz report_failure  \
      /* Same code as in the fast path, we could jump there but it'll add */  \
      /* an instruction. */  \
     __asm epilogue:  \
      __asm pop eax  \
      __asm add esp, 4  \
      __asm add al, 0x7f  \
      __asm sahf  \
      __asm mov edx, DWORD PTR[esp + 8]  \
      __asm pop eax  \
      __asm ret 4  \
    __asm report_failure:  \
      /* As we give the user the ability to change the error handler, we */  \
      /* need to save the flags with pushfd because now we can't guarantee */  \
      /* that the direction flag won't be touched. */  \
      /* We start by restoring the flags. */  \
      __asm mov eax, DWORD PTR[esp]  \
      __asm add al, 0x7f  \
      __asm sahf  \
      /* Then we push them. */  \
      __asm pushfd  \
      /* Push all the register to have the full asan context on the stack.*/  \
      __asm pushad  \
      /* Push a pointer to this context. */  \
      __asm push esp  \
      /* Push the access size. */  \
      __asm push access_size  \
      /* Push the access type. */  \
      __asm push access_mode_value  \
      /* Call the error handler. */  \
      __asm call agent::asan::ReportBadMemoryAccess  \
      __asm popad  \
      __asm popfd  \
      __asm jmp epilogue  \
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
