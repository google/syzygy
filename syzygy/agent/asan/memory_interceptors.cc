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
#include "syzygy/agent/asan/memory_interceptors.h"

#include "base/logging.h"
#include "syzygy/agent/asan/asan_rtl_utils.h"
#include "syzygy/agent/asan/shadow.h"

using agent::asan::Shadow;

namespace agent {
namespace asan {

// Check if the memory location is accessible and report an error on bad memory
// accesses.
// @param location The memory address of the access.
// @param access_mode The mode of the access.
// @param access_size The size of the access.
// @param context The registers context of the access.
void CheckMemoryAccess(void* location,
                       AccessMode access_mode,
                       size_t access_size,
                       const AsanContext& context) {
  if (!Shadow::IsAccessible(location))
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
    uint8* dst, AccessMode dst_access_mode,
    uint8* src, AccessMode src_access_mode,
    uint32 length, size_t access_size, int32 increment, bool compare,
    const AsanContext& context) {
  int32 offset = 0;

  for (uint32 i = 0; i < length; ++i) {
    // Check next memory location at src[offset].
    if (src_access_mode != agent::asan::ASAN_UNKNOWN_ACCESS)
      CheckMemoryAccess(&src[offset], src_access_mode, access_size, context);

    // Check next memory location at dst[offset].
    if (dst_access_mode != agent::asan::ASAN_UNKNOWN_ACCESS)
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
    __asm movzx edx, BYTE PTR[edx + Shadow::shadow_]  \
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
  AsanReadAccess = agent::asan::ASAN_READ_ACCESS,
  AsanWriteAccess = agent::asan::ASAN_WRITE_ACCESS,
  AsanUnknownAccess = agent::asan::ASAN_UNKNOWN_ACCESS,
};
// @}

// The slow path relies on the fact that the shadow memory non accessible byte
// mask has its upper bit set to 1.
COMPILE_ASSERT(
    (Shadow::kHeapNonAccessibleByteMask & (1 << 7)) != 0,
        asan_shadow_mask_upper_bit_is_0);

// Generate the flag-saving memory access intercept functions.
ASAN_MEM_INTERCEPT_FUNCTIONS(ASAN_CHECK_FUNCTION)

#undef ASAN_CHECK_FUNCTION

// Generate the non-flag saving memory access intercept functions.
ASAN_MEM_INTERCEPT_FUNCTIONS(ASAN_CHECK_FUNCTION_NO_FLAGS)

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

// Generate the string instruction intercept functions.
ASAN_STRING_INTERCEPT_FUNCTIONS(ASAN_CHECK_STRINGS)

#undef ASAN_CHECK_STRINGS
