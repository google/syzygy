// Copyright 2015 Google Inc. All Rights Reserved.
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

#include "syzygy/refinery/analyzers/thread_analyzer.h"

#include <dbghelp.h>

#include "base/macros.h"
#include "syzygy/refinery/process_state/refinery.pb.h"

namespace refinery {

// static
const char ThreadAnalyzer::kThreadAnalyzerName[] = "ThreadAnalyzer";

Analyzer::AnalysisResult ThreadAnalyzer::Analyze(
    const Minidump& minidump, ProcessState* process_state) {
  DCHECK(process_state != nullptr);

  scoped_refptr<ProcessState::Layer<Stack>> stack_layer;
  process_state->FindOrCreateLayer(&stack_layer);

  Minidump::Stream thread_list =
    minidump.FindNextStream(nullptr, ThreadListStream);
  if (!thread_list.IsValid())
    return ANALYSIS_ERROR;

  ULONG32 num_threads = 0;
  if (!thread_list.ReadElement(&num_threads))
    return ANALYSIS_ERROR;

  for (size_t i = 0; i < num_threads; ++i) {
    // Note: if the dump were full memory, we would need to read a
    // MINIDUMP_THREAD based on a MINIDUMP_MEMORY_DESCRIPTOR64.
    MINIDUMP_THREAD thread = {};
    if (!thread_list.ReadElement(&thread))
      return ANALYSIS_ERROR;

    // Create the stack record.
    scoped_refptr<ProcessState::Record<Stack>> stack_record;
    AddressRange range(thread.Stack.StartOfMemoryRange,
                       thread.Stack.Memory.DataSize);
    if (!range.IsValid())
      return ANALYSIS_ERROR;
    stack_layer->CreateRecord(range, &stack_record);
    ThreadInformation* thread_info =
        stack_record->mutable_data()->mutable_thread_info();
    if (thread_info == nullptr)
      return ANALYSIS_ERROR;

    thread_info->set_thread_id(thread.ThreadId);
    thread_info->set_suspend_count(thread.SuspendCount);
    thread_info->set_priority_class(thread.PriorityClass);
    thread_info->set_priority(thread.Priority);
    thread_info->set_teb_address(thread.Teb);

    // TODO(siggi): Add to bytes layer?
    Minidump::Stream thread_memory =
        minidump.GetStreamFor(thread.Stack.Memory);
    if (!thread_memory.IsValid())
      return ANALYSIS_ERROR;

    Minidump::Stream thread_context =
        minidump.GetStreamFor(thread.ThreadContext);
    if (!thread_context.IsValid())
      return ANALYSIS_ERROR;

    // TODO(siggi): This ought to probe for the architecture somehow.
    CONTEXT ctx = {};
    if (!thread_context.ReadElement(&ctx))
      return ANALYSIS_ERROR;

    RegisterInformation* reg_info = thread_info->mutable_register_info();
    if (ctx.ContextFlags & CONTEXT_SEGMENTS) {
      reg_info->set_seg_gs(ctx.SegGs);
      reg_info->set_seg_fs(ctx.SegFs);
      reg_info->set_seg_es(ctx.SegEs);
      reg_info->set_seg_ds(ctx.SegDs);
    }
    if (ctx.ContextFlags & CONTEXT_INTEGER) {
      reg_info->set_edi(ctx.Edi);
      reg_info->set_esi(ctx.Esi);
      reg_info->set_ebx(ctx.Ebx);
      reg_info->set_edx(ctx.Edx);
      reg_info->set_ecx(ctx.Ecx);
      reg_info->set_eax(ctx.Eax);
    }
    if (ctx.ContextFlags & CONTEXT_CONTROL) {
      reg_info->set_ebp(ctx.Ebp);
      reg_info->set_eip(ctx.Eip);
      reg_info->set_seg_cs(ctx.SegCs);
      reg_info->set_eflags(ctx.EFlags);
      reg_info->set_esp(ctx.Esp);
      reg_info->set_seg_ss(ctx.SegSs);
    }
  }

  return ANALYSIS_COMPLETE;
}

}  // namespace refinery
