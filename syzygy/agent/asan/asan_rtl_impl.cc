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
#include "syzygy/agent/asan/asan_runtime.h"
#include "syzygy/agent/asan/asan_shadow.h"
#include "syzygy/agent/asan/stack_capture.h"
#include "syzygy/agent/common/scoped_last_error_keeper.h"

namespace {

using agent::asan::AsanErrorInfo;
using agent::asan::AsanRuntime;
using agent::asan::HeapProxy;

HANDLE process_heap = NULL;
scoped_ptr<HeapProxy> asan_process_heap;

// The asan runtime manager.
AsanRuntime* asan_runtime = NULL;

// A callback that will be used in the functions interceptors once the call
// to the intercepted function has been done. This is for testing purposes
// only.
InterceptorTailCallback interceptor_tail_callback = NULL;

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
}

void TearDownRtl() {
  DCHECK_NE(reinterpret_cast<HANDLE>(NULL), process_heap);
  DCHECK_NE(reinterpret_cast<HeapProxy*>(NULL), asan_process_heap);
  asan_runtime->RemoveHeap(asan_process_heap.get());

  if (!asan_process_heap->Destroy()) {
    LOG(ERROR) << "Unable to destroy the process heap.";
    return;
  }

  asan_process_heap.reset(NULL);
  process_heap = NULL;
}

// Contents of the registers before calling the ASAN memory check function.
#pragma pack(push, 1)
struct AsanContext {
  DWORD original_edi;
  DWORD original_esi;
  DWORD original_ebp;
  DWORD original_esp;
  DWORD original_ebx;
  DWORD original_edx;
  DWORD original_ecx;
  DWORD original_eax;
  DWORD original_eflags;
  DWORD original_eip;
};
#pragma pack(pop)

// Report a bad access to the memory.
// @param location The memory address of the access.
// @param access_mode The mode of the access.
// @param access_size The size of the access.
// @param asan_context The context of the access.
void ReportBadMemoryAccess(void* location,
                           HeapProxy::AccessMode access_mode,
                           size_t access_size,
                           struct AsanContext* asan_context) {
  // Capture the context and restore the value of the register as before calling
  // the asan hook.

  // Save the last error value so this function will be able to restore it.
  agent::common::ScopedLastErrorKeeper scoped_last_error_keeper;

  // We keep a structure with all the useful information about this bad access
  // on the stack.
  AsanErrorInfo bad_access_info = {};

  // We need to call ::RtlCaptureContext if we want SegSS and SegCS to be
  // properly set.
  ::RtlCaptureContext(&bad_access_info.context);
  bad_access_info.context.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;

  // Restore the original value of the registers.
  bad_access_info.context.Eip = asan_context->original_eip;
  bad_access_info.context.Eax = asan_context->original_eax;
  bad_access_info.context.Ecx = asan_context->original_ecx;
  bad_access_info.context.Edx = asan_context->original_edx;
  bad_access_info.context.Ebx = asan_context->original_ebx;
  bad_access_info.context.Ebp = asan_context->original_ebp;
  bad_access_info.context.Esp = asan_context->original_esp;
  bad_access_info.context.Esi = asan_context->original_esi;
  bad_access_info.context.Edi = asan_context->original_edi;
  bad_access_info.context.EFlags = asan_context->original_eflags;

  StackCapture stack;
  stack.InitFromStack();
  // We need to compute a relative stack id so that for the same stack trace
  // we'll get the same value every time even if the modules are loaded at a
  // different base address.
  stack.set_stack_id(stack.ComputeRelativeStackId());

  // Check if we can ignore this error.
  if (asan_runtime->ShouldIgnoreError(stack.stack_id()))
    return;

  bad_access_info.crash_stack_id = stack.stack_id();
  bad_access_info.location = location;
  bad_access_info.access_mode = access_mode;
  bad_access_info.access_size = access_size;
  bad_access_info.alloc_stack_size = 0U;
  bad_access_info.alloc_tid = 0U;
  bad_access_info.error_type = HeapProxy::UNKNOWN_BAD_ACCESS;
  bad_access_info.free_stack_size = 0U;
  bad_access_info.free_tid = 0U;
  bad_access_info.microseconds_since_free = 0U;

  // Make sure this structure is not optimized out.
  base::debug::Alias(&bad_access_info);

  asan_runtime->GetBadAccessInformation(&bad_access_info);

  // Report this error.
  asan_runtime->OnError(&bad_access_info);
}

// Check if the memory location is accessible and report an error on bad memory
// accesses.
// @param location The memory address of the access.
// @param access_mode The mode of the access.
// @param access_size The size of the access.
// @param context The registers context of the access.
void CheckMemoryAccess(void* location,
                       HeapProxy::AccessMode access_mode,
                       size_t access_size,
                       AsanContext* context) {
  if (!agent::asan::Shadow::IsAccessible(location))
    ReportBadMemoryAccess(location, access_mode, access_size, context);
}

// Check if the memory accesses done by a string instructions are valid.
// @param dst The destination memory address of the access.
// @param dst_access_mode The destination mode of the access.
// @param src The source memory address of the access.
// @param src_access_mode The source mode of the access.
// @param length The number of memory accesses.
// @param access_size The size of each the access in byte.
// @param increment The increment to move dst/src after each access.
// @param compare Flag to activate shortcut of the execution on difference.
// @param context The registers context of the access.
void CheckStringsMemoryAccesses(
    uint8* dst, HeapProxy::AccessMode dst_access_mode,
    uint8* src, HeapProxy::AccessMode src_access_mode,
    uint32 length, size_t access_size, int32 increment, bool compare,
    AsanContext* context) {
  int32 offset = 0;

  for (uint32 i = 0; i < length; ++i) {
    // Check next memory location at src[offset].
    if (src_access_mode != HeapProxy::ASAN_UNKNOWN_ACCESS)
      CheckMemoryAccess(&src[offset], src_access_mode, access_size, context);

    // Check next memory location at dst[offset].
    if (dst_access_mode != HeapProxy::ASAN_UNKNOWN_ACCESS)
      CheckMemoryAccess(&dst[offset], dst_access_mode, access_size, context);

    // For CMPS instructions, we shortcut the execution of prefix REPZ when
    // memory contents differ.
    if (compare) {
      uint32 src_content = 0;
      uint32 dst_content = 0;
      switch (access_size) {
      case 4:
        src_content = *reinterpret_cast<uint32*>(&src[offset]);
        dst_content = *reinterpret_cast<uint32*>(&dst[offset]);
        break;
      case 2:
        src_content = *reinterpret_cast<uint16*>(&src[offset]);
        dst_content = *reinterpret_cast<uint16*>(&dst[offset]);
        break;
      case 1:
        src_content = *reinterpret_cast<uint8*>(&src[offset]);
        dst_content = *reinterpret_cast<uint8*>(&dst[offset]);
        break;
      default:
        NOTREACHED() << "Unexpected access_size.";
        break;
      }

      if (src_content != dst_content)
        return;
    }

    // Increments offset of dst/src to the next memory location.
    offset += increment;
  }
}

}  // namespace asan
}  // namespace agent

// This is a trick for efficient saving/restoring part of the flags register.
// see http://blog.freearrow.com/archives/396
// Flags (bits 16-31) probably need a pipeline flush on update (POPFD). Thus,
// using LAHF/SAHF instead gives better performance.
//   PUSHFD/POPFD: 23.314684 ticks
//   LAHF/SAHF:     8.838665 ticks

// This macro starts by saving EAX onto the stack and then loads the value of
// the flags into it.
#define ASAN_SAVE_EFLAGS  \
    __asm push eax  \
    __asm lahf  \
    __asm seto al

// This macro restores the flags, their previous value is assumed to be in EAX
// and we expect to have the previous value of EAX on the top of the stack.
// AL is set to 1 if the overflow flag was set before the call to our hook, 0
// otherwise. We add 0x7f to it so it'll restore the flag. Then we restore the
// low bytes of the flags and EAX.
#define ASAN_RESTORE_EFLAGS  \
    __asm add al, 0x7f  \
    __asm sahf  \
    __asm pop eax

// This is the common part of the fast path shared between the different
// implementations of the hooks, this does the following:
//     - Saves the memory location in EDX for the slow path.
//     - Checks if the address we're trying to access is signed, if so this mean
//         that this is an access to the upper region of the memory (over the
//         2GB limit) and we should report this as an invalid wild access.
//     - Checks for zero shadow for this memory location. We use the cmp
//         instruction so it'll set the sign flag if the upper bit of the shadow
//         value of this memory location is set to 1.
//     - If the shadow byte is not equal to zero then it jumps to the slow path.
//     - Otherwise it removes the memory location from the top of the stack.
#define ASAN_FAST_PATH  \
    __asm push edx  \
    __asm sar edx, 3  \
    __asm js report_failure  \
    __asm movzx edx, BYTE PTR[edx + agent::asan::Shadow::shadow_]  \
    __asm cmp dl, 0  \
    __asm jnz check_access_slow  \
    __asm add esp, 4

// This is the common part of the slow path shared between the different
// implementations of the hooks. The memory location is expected to be on top of
// the stack and the shadow value for it is assumed to be in DL at this point.
// This also relies on the fact that the shadow non accessible byte mask has its
// upper bit set to 1 and that we jump to this macro after doing a
// "cmp shadow_byte, 0", so the sign flag would be set to 1 if the value isn't
// accessible.
// We inline the Shadow::IsAccessible function for performance reasons.
// This function does the following:
//     - Checks if this byte is accessible and jump to the error path if it's
//       not.
//     - Removes the memory location from the top of the stack.
#define ASAN_SLOW_PATH  \
    __asm js report_failure  \
    __asm mov dh, BYTE PTR[esp]  \
    __asm and dh, 7  \
    __asm cmp dh, dl  \
    __asm jae report_failure  \
    __asm add esp, 4

// This is the error path. It expects to have the previous value of EDX at
// [ESP + 4] and the address of the faulty instruction at [ESP].
// This macro take cares of saving and restoring the flags.
#define ASAN_ERROR_PATH(access_size, access_mode_value)  \
    /* Restore original value of EDX, and put memory location on stack. */  \
    __asm xchg edx, DWORD PTR[esp + 4]  \
    /* Create an ASAN registers context on the stack. */  \
    __asm pushfd  \
    __asm pushad  \
    /* Fix the original value of ESP in the ASAN registers context. */  \
    /* Removing 12 bytes (e.g. EFLAGS / EIP / Original EDX). */  \
    __asm add DWORD PTR[esp + 12], 12  \
    /* Push ARG4: the address of ASAN context on stack. */  \
    __asm push esp  \
    /* Push ARG3: the access size. */  \
    __asm push access_size  \
    /* Push ARG2: the access type. */  \
    __asm push access_mode_value  \
    /* Push ARG1: the memory location. */  \
    __asm push DWORD PTR[esp + 52]  \
    __asm call agent::asan::ReportBadMemoryAccess  \
    /* Remove 4 x ARG on stack. */  \
    __asm add esp, 16  \
    /* Restore original registers. */  \
    __asm popad  \
    __asm popfd  \
    /* Return and remove memory location on stack. */  \
    __asm ret 4

// Generates the asan check access functions. The name of the generated method
// will be asan_check_(@p access_size)_byte_(@p access_mode_str)().
// @param access_size The size of the access (in byte).
// @param access_mode_str The string representing the access mode (read_access
//     or write_access).
// @param access_mode_value The internal value representing this kind of access.
// @note Calling this function doesn't alter any register.
#define ASAN_CHECK_FUNCTION(access_size, access_mode_str, access_mode_value)  \
  extern "C" __declspec(naked)  \
      void asan_check_ ## access_size ## _byte_ ## access_mode_str ## () {  \
    __asm {  \
      /* Save the EFLAGS. */  \
      ASAN_SAVE_EFLAGS  \
      ASAN_FAST_PATH  \
      /* Restore original EDX. */  \
      __asm mov edx, DWORD PTR[esp + 8]  \
      /* Restore the EFLAGS. */  \
      ASAN_RESTORE_EFLAGS  \
      __asm ret 4  \
    __asm check_access_slow:  \
      ASAN_SLOW_PATH  \
      /* Restore original EDX. */  \
      __asm mov edx, DWORD PTR[esp + 8]  \
      /* Restore the EFLAGS. */  \
      ASAN_RESTORE_EFLAGS  \
      __asm ret 4  \
    __asm report_failure:  \
      /* Restore memory location in EDX. */  \
      __asm pop edx  \
      /* Restore the EFLAGS. */  \
      ASAN_RESTORE_EFLAGS  \
      ASAN_ERROR_PATH(access_size, access_mode_value)  \
    }  \
  }

// Generates a variant of the asan check access functions that don't save the
// flags. The name of the generated method will be
// asan_check_(@p access_size)_byte_(@p access_mode_str)_no_flags().
// @param access_size The size of the access (in byte).
// @param access_mode_str The string representing the access mode (read_access
//     or write_access).
// @param access_mode_value The internal value representing this kind of access.
// @note Calling this function may alter the EFLAGS register only.
#define ASAN_CHECK_FUNCTION_NO_FLAGS(access_size,  \
                                     access_mode_str,  \
                                     access_mode_value)  \
  extern "C" __declspec(naked)  \
      void asan_check_ ## access_size ## _byte_ ## access_mode_str ##  \
          _no_flags() {  \
    __asm {  \
      ASAN_FAST_PATH  \
      /* Restore original EDX. */  \
      __asm mov edx, DWORD PTR[esp + 4]  \
      __asm ret 4  \
    __asm check_access_slow:  \
      ASAN_SLOW_PATH  \
      /* Restore original EDX. */  \
      __asm mov edx, DWORD PTR[esp + 4]  \
      __asm ret 4  \
    __asm report_failure:  \
      /* Restore memory location in EDX. */  \
      __asm pop edx  \
      ASAN_ERROR_PATH(access_size, access_mode_value)  \
    }  \
  }

// Redefine some enums to make them accessible in the inlined assembly.
// @{
enum AccessMode {
  AsanReadAccess = HeapProxy::ASAN_READ_ACCESS,
  AsanWriteAccess = HeapProxy::ASAN_WRITE_ACCESS,
  AsanUnknownAccess = HeapProxy::ASAN_UNKNOWN_ACCESS,
};
// @}

// The slow path rely on the fact that the shadow memory non accessible byte
// mask have its upper bit set to 1..
COMPILE_ASSERT(
    (agent::asan::Shadow::kHeapNonAccessibleByteMask & (1 << 7)) != 0,
        asan_shadow_mask_upper_bit_is_0);

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

ASAN_CHECK_FUNCTION_NO_FLAGS(1, read_access, AsanReadAccess)
ASAN_CHECK_FUNCTION_NO_FLAGS(2, read_access, AsanReadAccess)
ASAN_CHECK_FUNCTION_NO_FLAGS(4, read_access, AsanReadAccess)
ASAN_CHECK_FUNCTION_NO_FLAGS(8, read_access, AsanReadAccess)
ASAN_CHECK_FUNCTION_NO_FLAGS(10, read_access, AsanReadAccess)
ASAN_CHECK_FUNCTION_NO_FLAGS(16, read_access, AsanReadAccess)
ASAN_CHECK_FUNCTION_NO_FLAGS(32, read_access, AsanReadAccess)
ASAN_CHECK_FUNCTION_NO_FLAGS(1, write_access, AsanWriteAccess)
ASAN_CHECK_FUNCTION_NO_FLAGS(2, write_access, AsanWriteAccess)
ASAN_CHECK_FUNCTION_NO_FLAGS(4, write_access, AsanWriteAccess)
ASAN_CHECK_FUNCTION_NO_FLAGS(8, write_access, AsanWriteAccess)
ASAN_CHECK_FUNCTION_NO_FLAGS(10, write_access, AsanWriteAccess)
ASAN_CHECK_FUNCTION_NO_FLAGS(16, write_access, AsanWriteAccess)
ASAN_CHECK_FUNCTION_NO_FLAGS(32, write_access, AsanWriteAccess)

#undef ASAN_CHECK_FUNCTION_NO_FLAGS
#undef ASAN_SAVE_EFLAGS
#undef ASAN_RESTORE_EFLAGS
#undef ASAN_FAST_PATH
#undef ASAN_SLOW_PATH
#undef ASAN_ERROR_PATH

// Generates the asan check access functions for a string instruction.
// The name of the generated method will be
// asan_check_(@p prefix)(@p access_size)_byte_(@p inst)_access().
// @param inst The instruction mnemonic.
// @param prefix The prefix of the instruction (repz or nothing).
// @param counter The number of times the instruction must be executed (ECX). It
//     may be a register or a constant.
// @param dst_mode The memory access mode for destination (EDI).
// @param src_mode The memory access mode for destination (ESI).
// @param access_size The size of the access (in byte).
// @param compare A flag to enable shortcut execution by comparing memory
//     contents.
#define ASAN_CHECK_STRINGS(func, prefix, counter, dst_mode, src_mode, \
    access_size, compare)  \
  extern "C" __declspec(naked)  \
  void asan_check ## prefix ## access_size ## _byte_ ## func ## _access() {  \
    __asm {  \
      /* Prologue, save context. */  \
      __asm pushfd  \
      __asm pushad  \
      /* Fix the original value of ESP in the ASAN registers context. */  \
      /* Removing 8 bytes (e.g.EFLAGS / EIP was on stack). */  \
      __asm add DWORD PTR[esp + 12], 8  \
      /* Setup increment in EBX (depends on direction flag in EFLAGS). */  \
      __asm mov ebx, access_size  \
      __asm pushfd  \
      __asm pop eax  \
      __asm test eax, 0x400  \
      __asm jz skip_neg_direction  \
      __asm neg ebx  \
    __asm skip_neg_direction:  \
      /* By standard calling convention, direction flag must be forward. */  \
      __asm cld  \
      /* Push ARG(context), the ASAN registers context. */  \
      __asm push esp  \
      /* Push ARG(compare), shortcut when memory contents differ. */  \
      __asm push compare  \
      /* Push ARG(increment), increment for EDI/EDI. */  \
      __asm push ebx  \
      /* Push ARG(access_size), the access size. */  \
      __asm push access_size  \
      /* Push ARG(length), the number of memory accesses. */  \
      __asm push counter  \
      /* Push ARG(src_access_mode), source access type. */  \
      __asm push src_mode \
      /* Push ARG(src), the source pointer. */  \
      __asm push esi  \
      /* Push ARG(dst_access_mode), destination access type. */  \
      __asm push dst_mode \
      /* Push ARG(dst), the destination pointer. */  \
      __asm push edi  \
      /* Call the generic check strings function. */  \
      __asm call agent::asan::CheckStringsMemoryAccesses  \
      __asm add esp, 36  \
      /* Epilogue, restore context. */  \
      __asm popad  \
      __asm popfd  \
      __asm ret  \
    }  \
  }

ASAN_CHECK_STRINGS(cmps, _repz_, ecx, AsanReadAccess, AsanReadAccess, 4, 1)
ASAN_CHECK_STRINGS(cmps, _repz_, ecx, AsanReadAccess, AsanReadAccess, 2, 1)
ASAN_CHECK_STRINGS(cmps, _repz_, ecx, AsanReadAccess, AsanReadAccess, 1, 1)
ASAN_CHECK_STRINGS(cmps, _, 1, AsanReadAccess, AsanReadAccess, 4, 1)
ASAN_CHECK_STRINGS(cmps, _, 1, AsanReadAccess, AsanReadAccess, 2, 1)
ASAN_CHECK_STRINGS(cmps, _, 1, AsanReadAccess, AsanReadAccess, 1, 1)

ASAN_CHECK_STRINGS(movs, _repz_, ecx, AsanWriteAccess, AsanReadAccess, 4, 0)
ASAN_CHECK_STRINGS(movs, _repz_, ecx, AsanWriteAccess, AsanReadAccess, 2, 0)
ASAN_CHECK_STRINGS(movs, _repz_, ecx, AsanWriteAccess, AsanReadAccess, 1, 0)
ASAN_CHECK_STRINGS(movs, _, 1, AsanWriteAccess, AsanReadAccess, 4, 0)
ASAN_CHECK_STRINGS(movs, _, 1, AsanWriteAccess, AsanReadAccess, 2, 0)
ASAN_CHECK_STRINGS(movs, _, 1, AsanWriteAccess, AsanReadAccess, 1, 0)

ASAN_CHECK_STRINGS(stos, _repz_, ecx, AsanWriteAccess, AsanUnknownAccess, 4, 0)
ASAN_CHECK_STRINGS(stos, _repz_, ecx, AsanWriteAccess, AsanUnknownAccess, 2, 0)
ASAN_CHECK_STRINGS(stos, _repz_, ecx, AsanWriteAccess, AsanUnknownAccess, 1, 0)
ASAN_CHECK_STRINGS(stos, _, 1, AsanWriteAccess, AsanUnknownAccess, 4, 0)
ASAN_CHECK_STRINGS(stos, _, 1, AsanWriteAccess, AsanUnknownAccess, 2, 0)
ASAN_CHECK_STRINGS(stos, _, 1, AsanWriteAccess, AsanUnknownAccess, 1, 0)

#undef ASAN_CHECK_STRINGS

namespace {

void ContextToAsanContext(const CONTEXT& context,
                          agent::asan::AsanContext* asan_context) {
  DCHECK(asan_context != NULL);
  asan_context->original_eax = context.Eax;
  asan_context->original_ebp = context.Ebp;
  asan_context->original_ebx = context.Ebx;
  asan_context->original_ecx = context.Ecx;
  asan_context->original_edi = context.Edi;
  asan_context->original_edx = context.Edx;
  asan_context->original_eflags = context.EFlags;
  asan_context->original_eip = context.Eip;
  asan_context->original_esi = context.Esi;
  asan_context->original_esp = context.Esp;
}

// Report an invalid access to @p location.
// @param location The memory address of the access.
// @param access_mode The mode of the access.
void ReportBadAccess(const uint8* location, HeapProxy::AccessMode access_mode) {
  agent::asan::AsanContext asan_context = {};
  CONTEXT context = {};
  ::RtlCaptureContext(&context);
  ContextToAsanContext(context, &asan_context);
  ReportBadMemoryAccess(const_cast<uint8*>(location),
                        access_mode,
                        1U,
                        &asan_context);
}

// Test that a memory range is accessible. Report an error if it's not.
// @param memory The pointer to the beginning of the memory range that we want
//     to check.
// @param size The size of the memory range that we want to check.
// @param access_mode The access mode.
void TestMemoryRange(const uint8* memory,
                     size_t size,
                     HeapProxy::AccessMode access_mode) {
  if (size == 0U)
    return;
  // TODO(sebmarchand): This approach is pretty limited because it only check
  //     if the first and the last elements are accessible. Once we have the
  //     plumbing in place we should benchmark a check that looks at each
  //     address to be touched (via the shadow memory, 8 bytes at a time).
  if (!agent::asan::Shadow::IsAccessible(memory) ||
      !agent::asan::Shadow::IsAccessible(memory + size - 1)) {
    const uint8* location = NULL;
    if (!agent::asan::Shadow::IsAccessible(memory))
      location = memory;
    else
      location = memory + size - 1;
    ReportBadAccess(location, access_mode);
  }
}

// Helper function to test if the memory range of a given structure is
// accessible.
// @tparam T the type of the structure to be tested.
// @param structure A pointer to this structure.
// @param access mode The access mode.
template <typename T>
void TestStructure(const T* structure, HeapProxy::AccessMode access_mode) {
  TestMemoryRange(reinterpret_cast<const uint8*>(structure),
                  sizeof(T),
                  access_mode);
}

}  // namespace

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
    AsanErrorInfo error_info = {};
    ::RtlCaptureContext(&error_info.context);
    error_info.location = mem;
    error_info.error_type = HeapProxy::DOUBLE_FREE;
    proxy->GetBadAccessInformation(&error_info);
    agent::asan::StackCapture stack;
    stack.InitFromStack();
    error_info.crash_stack_id = stack.ComputeRelativeStackId();
    asan_runtime->OnError(&error_info);
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

void* __cdecl asan_memcpy(unsigned char* destination,
                          const unsigned char* source,
                          size_t num) {
  TestMemoryRange(source, num, HeapProxy::ASAN_READ_ACCESS);
  TestMemoryRange(destination, num, HeapProxy::ASAN_WRITE_ACCESS);
  return memcpy(destination, source, num);
}

void* __cdecl asan_memmove(unsigned char* destination,
                           const unsigned char* source,
                           size_t num) {
  TestMemoryRange(source, num, HeapProxy::ASAN_READ_ACCESS);
  TestMemoryRange(destination, num, HeapProxy::ASAN_WRITE_ACCESS);
  return memmove(destination, source, num);
}

void* __cdecl asan_memset(unsigned char* ptr, int value, size_t num) {
  TestMemoryRange(ptr, num, HeapProxy::ASAN_WRITE_ACCESS);
  return memset(ptr, value, num);
}

const void* __cdecl asan_memchr(const unsigned char* ptr,
                                int value,
                                size_t num) {
  TestMemoryRange(ptr, num, HeapProxy::ASAN_READ_ACCESS);
  return memchr(ptr, value, num);
}

size_t __cdecl asan_strcspn(const char* str1,
                            const char* str2) {
  size_t size = 0;
  if (!agent::asan::Shadow::GetNullTerminatedArraySize(str1, &size, 0U)) {
    ReportBadAccess(reinterpret_cast<const uint8*>(str1) + size,
                    HeapProxy::ASAN_READ_ACCESS);
  }
  if (!agent::asan::Shadow::GetNullTerminatedArraySize(str2, &size, 0U)) {
    ReportBadAccess(reinterpret_cast<const uint8*>(str2) + size,
                    HeapProxy::ASAN_READ_ACCESS);
  }
  return strcspn(str1, str2);
}

size_t __cdecl asan_strlen(const char* str) {
  size_t size = 0;
  if (!agent::asan::Shadow::GetNullTerminatedArraySize(str, &size, 0U)) {
    ReportBadAccess(reinterpret_cast<const uint8*>(str) + size,
                    HeapProxy::ASAN_READ_ACCESS);
    return strlen(str);
  }
  return size - 1;
}

const char* __cdecl asan_strrchr(const char* str, int character) {
  size_t size = 0;
  if (!agent::asan::Shadow::GetNullTerminatedArraySize(str, &size, 0U)) {
    ReportBadAccess(reinterpret_cast<const uint8*>(str) + size,
                    HeapProxy::ASAN_READ_ACCESS);
  }
  return strrchr(str, character);
}

int __cdecl asan_strcmp(const char* str1, const char* str2) {
  size_t size = 0;
  if (!agent::asan::Shadow::GetNullTerminatedArraySize(str1, &size, 0U)) {
    ReportBadAccess(reinterpret_cast<const uint8*>(str1) + size,
                    HeapProxy::ASAN_READ_ACCESS);
  }
  if (!agent::asan::Shadow::GetNullTerminatedArraySize(str2, &size, 0U)) {
    ReportBadAccess(reinterpret_cast<const uint8*>(str2) + size,
                    HeapProxy::ASAN_READ_ACCESS);
  }
  return strcmp(str1, str2);
}

const char* __cdecl asan_strpbrk(const char* str1, const char* str2) {
  size_t size = 0;
  if (!agent::asan::Shadow::GetNullTerminatedArraySize(str1, &size, 0U)) {
    ReportBadAccess(reinterpret_cast<const uint8*>(str1) + size,
                    HeapProxy::ASAN_READ_ACCESS);
  }
  if (!agent::asan::Shadow::GetNullTerminatedArraySize(str2, &size, 0U)) {
    ReportBadAccess(reinterpret_cast<const uint8*>(str2) + size,
                    HeapProxy::ASAN_READ_ACCESS);
  }
  return strpbrk(str1, str2);
}

const char* __cdecl asan_strstr(const char* str1, const char* str2) {
  size_t size = 0;
  if (!agent::asan::Shadow::GetNullTerminatedArraySize(str1, &size, 0U)) {
    ReportBadAccess(reinterpret_cast<const uint8*>(str1) + size,
                    HeapProxy::ASAN_READ_ACCESS);
  }
  if (!agent::asan::Shadow::GetNullTerminatedArraySize(str2, &size, 0U)) {
    ReportBadAccess(reinterpret_cast<const uint8*>(str2) + size,
                    HeapProxy::ASAN_READ_ACCESS);
  }
  return strstr(str1, str2);
}

size_t __cdecl asan_strspn(const char* str1, const char* str2) {
  size_t size = 0;
  if (!agent::asan::Shadow::GetNullTerminatedArraySize(str1, &size, 0U)) {
    ReportBadAccess(reinterpret_cast<const uint8*>(str1) + size,
                    HeapProxy::ASAN_READ_ACCESS);
  }
  if (!agent::asan::Shadow::GetNullTerminatedArraySize(str2, &size, 0U)) {
    ReportBadAccess(reinterpret_cast<const uint8*>(str2) + size,
                    HeapProxy::ASAN_READ_ACCESS);
  }
  return strspn(str1, str2);
}

char* __cdecl asan_strncpy(char* destination, const char* source, size_t num) {
  if (num != 0U) {
    size_t src_size = 0;
    if (!agent::asan::Shadow::GetNullTerminatedArraySize(source,
                                                         &src_size,
                                                         num) &&
        src_size <= num) {
      ReportBadAccess(reinterpret_cast<const uint8*>(source) + src_size,
                      HeapProxy::ASAN_READ_ACCESS);
    }
    // We can't use the GetNullTerminatedArraySize function here, as destination
    // might not be null terminated.
    TestMemoryRange(reinterpret_cast<const uint8*>(destination),
                    num,
                    HeapProxy::ASAN_WRITE_ACCESS);
  }
  return strncpy(destination, source, num);
}

char* __cdecl asan_strncat(char* destination, const char* source, size_t num) {
  if (num != 0U) {
    size_t src_size = 0;
    if (!agent::asan::Shadow::GetNullTerminatedArraySize(source,
                                                         &src_size,
                                                         num) &&
        src_size <= num) {
      ReportBadAccess(reinterpret_cast<const uint8*>(source) + src_size,
                      HeapProxy::ASAN_READ_ACCESS);
    }
    size_t dst_size = 0;
    if (!agent::asan::Shadow::GetNullTerminatedArraySize(destination,
                                                         &dst_size,
                                                         0U)) {
      ReportBadAccess(reinterpret_cast<const uint8*>(destination) + dst_size,
                      HeapProxy::ASAN_WRITE_ACCESS);
    } else {
      // Test if we can append the source to the destination.
      TestMemoryRange(reinterpret_cast<const uint8*>(destination + dst_size),
                      std::min(num, src_size),
                      HeapProxy::ASAN_WRITE_ACCESS);
    }
  }
  return strncat(destination, source, num);
}

void asan_SetInterceptorCallback(InterceptorTailCallback callback) {
  interceptor_tail_callback = callback;
}

BOOL WINAPI asan_ReadFile(HANDLE file_handle,
                          LPVOID buffer,
                          DWORD bytes_to_read,
                          LPDWORD bytes_read,
                          LPOVERLAPPED overlapped) {
  // TODO(sebmarchand): Add more checks for the asynchronous calls to this
  //     function. More details about the asynchronous calls to ReadFile are
  //     available here: http://support.microsoft.com/kb/156932.

  // Ensures that the input values are accessible.

  TestMemoryRange(reinterpret_cast<uint8*>(buffer),
                  bytes_to_read,
                  HeapProxy::ASAN_WRITE_ACCESS);

  if (bytes_read != NULL)
    TestStructure<DWORD>(bytes_read, HeapProxy::ASAN_WRITE_ACCESS);

  if (overlapped != NULL)
    TestStructure<OVERLAPPED>(overlapped, HeapProxy::ASAN_READ_ACCESS);

  BOOL ret = ::ReadFile(file_handle,
                        buffer,
                        bytes_to_read,
                        bytes_read,
                        overlapped);

  // Run the interceptor callback if it has been set.
  if (interceptor_tail_callback != NULL)
    (*interceptor_tail_callback)();

  if (ret == FALSE)
    return ret;

  // Even if the overlapped pointer wasn't NULL it might become invalid after
  // the call to ReadFile, and so we can't test that this structure is
  // accessible.

  DCHECK_EQ(TRUE, ret);
  CHECK(bytes_read == NULL || *bytes_read <= bytes_to_read);
  TestMemoryRange(reinterpret_cast<uint8*>(buffer),
                  bytes_to_read,
                  HeapProxy::ASAN_WRITE_ACCESS);

  if (bytes_read != NULL)
    TestStructure<DWORD>(bytes_read, HeapProxy::ASAN_WRITE_ACCESS);

  return ret;
}

BOOL WINAPI asan_WriteFile(HANDLE file_handle,
                           LPCVOID buffer,
                           DWORD bytes_to_write,
                           LPDWORD bytes_written,
                           LPOVERLAPPED overlapped) {
  // Ensures that the input values are accessible.

  TestMemoryRange(reinterpret_cast<const uint8*>(buffer),
                  bytes_to_write,
                  HeapProxy::ASAN_READ_ACCESS);

  if (bytes_written != NULL)
    TestStructure<DWORD>(bytes_written, HeapProxy::ASAN_WRITE_ACCESS);

  if (overlapped != NULL)
    TestStructure<OVERLAPPED>(overlapped, HeapProxy::ASAN_READ_ACCESS);

  BOOL ret = ::WriteFile(file_handle,
                         buffer,
                         bytes_to_write,
                         bytes_written,
                         overlapped);

  // Run the interceptor callback if it has been set.
  if (interceptor_tail_callback != NULL)
    (*interceptor_tail_callback)();

  if (ret == FALSE)
    return ret;

  // Even if the overlapped pointer wasn't NULL it might become invalid after
  // the call to WriteFile, and so we can't test that this structure is
  // accessible.

  DCHECK_EQ(TRUE, ret);
  CHECK(bytes_written == NULL || *bytes_written <= bytes_to_write);
  TestMemoryRange(reinterpret_cast<const uint8*>(buffer),
                  bytes_to_write,
                  HeapProxy::ASAN_READ_ACCESS);

  if (bytes_written != NULL)
    TestStructure<DWORD>(bytes_written, HeapProxy::ASAN_WRITE_ACCESS);

  return ret;
}

}  // extern "C"
