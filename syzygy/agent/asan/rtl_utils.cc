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

#include "syzygy/agent/asan/rtl_utils.h"

#include <memory>

#include "base/bind.h"
#include "base/callback.h"
#include "base/logging.h"
#include "base/debug/alias.h"
#include "syzygy/agent/asan/heap_checker.h"
#include "syzygy/agent/asan/runtime.h"
#include "syzygy/agent/asan/shadow.h"
#include "syzygy/agent/common/scoped_last_error_keeper.h"
#include "syzygy/agent/common/stack_capture.h"

namespace {

// The asan runtime manager.
agent::asan::AsanRuntime* asan_runtime = NULL;

}  // namespace

namespace agent {
namespace asan {

void SetAsanRuntimeInstance(AsanRuntime* runtime) {
  asan_runtime = runtime;
}

void ReportBadMemoryAccess(const void* location,
                           AccessMode access_mode,
                           size_t access_size,
                           const AsanContext& asan_context) {
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
#ifdef _WIN64
  // TODO(loskutov): add more x64 registers or eliminate this piece of code.
  bad_access_info.context.Rip = asan_context.original_rip;
  bad_access_info.context.Rax = asan_context.original_rax;
  bad_access_info.context.Rcx = asan_context.original_rcx;
  bad_access_info.context.Rdx = asan_context.original_rdx;
  bad_access_info.context.Rbx = asan_context.original_rbx;
  bad_access_info.context.Rbp = asan_context.original_rbp;
  bad_access_info.context.Rsp = asan_context.original_rsp;
  bad_access_info.context.Rsi = asan_context.original_rsi;
  bad_access_info.context.Rdi = asan_context.original_rdi;
#else
  bad_access_info.context.Eip = asan_context.original_eip;
  bad_access_info.context.Eax = asan_context.original_eax;
  bad_access_info.context.Ecx = asan_context.original_ecx;
  bad_access_info.context.Edx = asan_context.original_edx;
  bad_access_info.context.Ebx = asan_context.original_ebx;
  bad_access_info.context.Ebp = asan_context.original_ebp;
  bad_access_info.context.Esp = asan_context.original_esp;
  bad_access_info.context.Esi = asan_context.original_esi;
  bad_access_info.context.Edi = asan_context.original_edi;
#endif
  bad_access_info.context.EFlags = asan_context.original_eflags;

  common::StackCapture stack;
  stack.InitFromStack();
  // We need to use the relative stack id so that for the same stack trace we
  // get the same value every time even if the modules are loaded at a different
  // base address.
  //
  // Check if we can ignore this error.
  if (asan_runtime->ShouldIgnoreError(stack.relative_stack_id()))
    return;

  bad_access_info.crash_stack_id = stack.relative_stack_id();
  bad_access_info.location = location;
  bad_access_info.access_mode = access_mode;
  bad_access_info.access_size = access_size;
  bad_access_info.error_type = UNKNOWN_BAD_ACCESS;
  bad_access_info.block_info.alloc_stack_size = 0U;
  bad_access_info.block_info.alloc_tid = 0U;
  bad_access_info.block_info.free_stack_size = 0U;
  bad_access_info.block_info.free_tid = 0U;
  bad_access_info.block_info.milliseconds_since_free = 0U;
  bad_access_info.corrupt_ranges = NULL;
  bad_access_info.corrupt_range_count = 0;

  // Make sure this structure is not optimized out.
  base::debug::Alias(&bad_access_info);

  // TODO(sebmarchand): Check if the heap is corrupt and store the information
  //     about the corrupt blocks if it's the case.
  bad_access_info.heap_is_corrupt = false;

  asan_runtime->GetBadAccessInformation(&bad_access_info);

  // Accesses to the first 64k of the memory (invalid address) should not be
  // reported by SyzyASAN unless we detect a heap corruption or if it has been
  // requested by the user. By returning early, we let the unhandled exception
  // filter do the heap corruption check. The check is not done here because we
  // don't want to duplicate the work.
  if (!asan_runtime->params().report_invalid_accesses &&
      bad_access_info.location <
          reinterpret_cast<void*>(Shadow::kAddressLowerBound)) {
    return;
  }

  // Report this error.
  asan_runtime->OnError(&bad_access_info);
}

void ContextToAsanContext(const CONTEXT& context, AsanContext* asan_context) {
  DCHECK(asan_context != NULL);
#ifdef _WIN64
  asan_context->original_rax = context.Rax;
  asan_context->original_rbp = context.Rbp;
  asan_context->original_rbx = context.Rbx;
  asan_context->original_rcx = context.Rcx;
  asan_context->original_rdi = context.Rdi;
  asan_context->original_rdx = context.Rdx;
  asan_context->original_rip = context.Rip;
  asan_context->original_rsi = context.Rsi;
  asan_context->original_rsp = context.Rsp;
#else
  asan_context->original_eax = context.Eax;
  asan_context->original_ebp = context.Ebp;
  asan_context->original_ebx = context.Ebx;
  asan_context->original_ecx = context.Ecx;
  asan_context->original_edi = context.Edi;
  asan_context->original_edx = context.Edx;
  asan_context->original_eip = context.Eip;
  asan_context->original_esi = context.Esi;
  asan_context->original_esp = context.Esp;
#endif
  asan_context->original_eflags = context.EFlags;
}

void ReportBadAccess(const void* location, AccessMode access_mode) {
  AsanContext asan_context = {};
  CONTEXT context = {};
  ::RtlCaptureContext(&context);
  ContextToAsanContext(context, &asan_context);
  ReportBadMemoryAccess(location, access_mode, 1U, asan_context);
}

void TestMemoryRange(Shadow* shadow,
                     const uint8_t* memory,
                     size_t size,
                     AccessMode access_mode) {
  if (!shadow || size == 0U)
    return;

  // TODO(sebmarchand): This approach is pretty limited because it only checks
  //     if the first and the last elements are accessible. Once we have the
  //     plumbing in place we should benchmark a check that looks at each
  //     address to be touched (via the shadow memory, 8 bytes at a time).
  if (!shadow->IsAccessible(memory) ||
      !shadow->IsAccessible(memory + size - 1)) {
    const void* location = shadow->FindFirstPoisonedByte(memory, size);
    // If this check hits, either you've lucked on a time-of-check race, and
    // there's a genuine bug in the call stack above, or else there's a bug
    // in the runtime.
    CHECK(location != nullptr);

    ReportBadAccess(location, access_mode);
  }
}

}  // namespace asan
}  // namespace agent
