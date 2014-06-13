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

#include "syzygy/agent/asan/asan_rtl_utils.h"

#include "base/bind.h"
#include "base/callback.h"
#include "base/logging.h"
#include "base/debug/alias.h"
#include "base/memory/scoped_ptr.h"
#include "syzygy/agent/asan/asan_heap_checker.h"
#include "syzygy/agent/asan/asan_runtime.h"
#include "syzygy/agent/asan/shadow.h"
#include "syzygy/agent/asan/stack_capture.h"
#include "syzygy/agent/common/scoped_last_error_keeper.h"

namespace {

// The asan runtime manager.
agent::asan::AsanRuntime* asan_runtime = NULL;

}  // namespace

namespace agent {
namespace asan {

void SetAsanRuntimeInstance(AsanRuntime* runtime) {
  asan_runtime = runtime;
}

void ReportBadMemoryAccess(void* location,
                           HeapProxy::AccessMode access_mode,
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
  bad_access_info.context.Eip = asan_context.original_eip;
  bad_access_info.context.Eax = asan_context.original_eax;
  bad_access_info.context.Ecx = asan_context.original_ecx;
  bad_access_info.context.Edx = asan_context.original_edx;
  bad_access_info.context.Ebx = asan_context.original_ebx;
  bad_access_info.context.Ebp = asan_context.original_ebp;
  bad_access_info.context.Esp = asan_context.original_esp;
  bad_access_info.context.Esi = asan_context.original_esi;
  bad_access_info.context.Edi = asan_context.original_edi;
  bad_access_info.context.EFlags = asan_context.original_eflags;

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
  bad_access_info.corrupt_ranges = NULL;
  bad_access_info.corrupt_range_count = 0;

  // Make sure this structure is not optimized out.
  base::debug::Alias(&bad_access_info);

  // TODO(sebmarchand): Check if the heap is corrupt and store the information
  //     about the corrupt blocks if it's the case.
  bad_access_info.heap_is_corrupt = false;

  asan_runtime->GetBadAccessInformation(&bad_access_info);

  // Report this error.
  asan_runtime->OnError(&bad_access_info);
}

void ContextToAsanContext(const CONTEXT& context, AsanContext* asan_context) {
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

void ReportBadAccess(const uint8* location, HeapProxy::AccessMode access_mode) {
  AsanContext asan_context = {};
  CONTEXT context = {};
  ::RtlCaptureContext(&context);
  ContextToAsanContext(context, &asan_context);
  ReportBadMemoryAccess(const_cast<uint8*>(location),
                        access_mode,
                        1U,
                        asan_context);
}

void TestMemoryRange(const uint8* memory,
                     size_t size,
                     HeapProxy::AccessMode access_mode) {
  if (size == 0U)
    return;
  // TODO(sebmarchand): This approach is pretty limited because it only checks
  //     if the first and the last elements are accessible. Once we have the
  //     plumbing in place we should benchmark a check that looks at each
  //     address to be touched (via the shadow memory, 8 bytes at a time).
  if (!Shadow::IsAccessible(memory) ||
      !Shadow::IsAccessible(memory + size - 1)) {
    const uint8* location = NULL;
    if (!Shadow::IsAccessible(memory)) {
      location = memory;
    } else {
      location = memory + size - 1;
    }
    ReportBadAccess(location, access_mode);
  }
}

}  // namespace asan
}  // namespace agent
