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
#include "syzygy/refinery/analyzers/analyzer_util.h"
#include "syzygy/refinery/process_state/refinery.pb.h"

namespace refinery {

// static
const char ThreadAnalyzer::kThreadAnalyzerName[] = "ThreadAnalyzer";

Analyzer::AnalysisResult ThreadAnalyzer::Analyze(
    const minidump::Minidump& minidump,
    const ProcessAnalysis& process_analysis) {
  DCHECK(process_analysis.process_state() != nullptr);

  StackLayerPtr stack_layer;
  process_analysis.process_state()->FindOrCreateLayer(&stack_layer);

  minidump::Minidump::TypedThreadList threads = minidump.GetThreadList();
  if (!threads.IsValid())
      return ANALYSIS_ERROR;

  for (const auto& thread : threads) {
    // Create the stack record.
    StackRecordPtr stack_record;
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
    minidump::Minidump::Stream thread_memory =
        minidump.GetStreamFor(thread.Stack.Memory);
    if (!thread_memory.IsValid())
      return ANALYSIS_ERROR;

    minidump::Minidump::Stream thread_context =
        minidump.GetStreamFor(thread.ThreadContext);
    if (!thread_context.IsValid())
      return ANALYSIS_ERROR;

    // TODO(siggi): This ought to probe for the architecture somehow.
    CONTEXT ctx = {};
    if (!thread_context.ReadAndAdvanceElement(&ctx))
      return ANALYSIS_ERROR;
    ParseContext(ctx, thread_info->mutable_register_info());
  }

  return ANALYSIS_COMPLETE;
}

}  // namespace refinery
