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

#include "syzygy/refinery/analyzers/stack_analyzer.h"

#include "syzygy/common/com_utils.h"
#include "syzygy/refinery/analyzers/stack_analyzer_impl.h"
#include "syzygy/refinery/process_state/refinery.pb.h"

namespace refinery {

// static
const char StackAnalyzer::kStackAnalyzerName[] = "StackAnalyzer";

StackAnalyzer::StackAnalyzer() {
}

Analyzer::AnalysisResult StackAnalyzer::Analyze(const Minidump& minidump,
                                                ProcessState* process_state) {
  DCHECK(process_state != nullptr);

  // Create stack walker and helper.
  HRESULT hr = stack_walker_.CreateInstance(CLSID_DiaStackWalker);
  if (hr != S_OK) {
    LOG(ERROR) << "Failed to create DiaStackWalker: " << common::LogHr(hr)
               << ".";
    return ANALYSIS_ERROR;
  }
  stack_walk_helper_ = new StackWalkHelper();

  // Get the stack layer - it must already have been populated.
  StackLayerPtr stack_layer;
  if (!process_state->FindLayer(&stack_layer))
    return ANALYSIS_ERROR;

  // Process each thread's stack.
  for (StackRecordPtr stack_record : *stack_layer) {
    if (StackWalk(stack_record, process_state) == ANALYSIS_ERROR)
      return ANALYSIS_ERROR;
  }

  return ANALYSIS_COMPLETE;
}

Analyzer::AnalysisResult StackAnalyzer::StackWalk(StackRecordPtr stack_record,
                                                  ProcessState* process_state) {
  stack_walk_helper_->SetState(stack_record, process_state);

  // Create the frame enumerator.
  base::win::ScopedComPtr<IDiaEnumStackFrames> frame_enumerator;
  // TODO(manzagop): this is for x86 platforms. Switch to getEnumFrames2.
  HRESULT hr = stack_walker_->getEnumFrames(
      static_cast<IDiaStackWalkHelper*>(stack_walk_helper_.get()),
      frame_enumerator.Receive());
  if (hr != S_OK)
    return ANALYSIS_ERROR;
  frame_enumerator->Reset();

  // Walk the stack frames.
  while (true) {
    base::win::ScopedComPtr<IDiaStackFrame> stack_frame;
    DWORD retrieved_cnt = 0;
    hr = frame_enumerator->Next(1, stack_frame.Receive(), &retrieved_cnt);
    if (!SUCCEEDED(hr))
      return ANALYSIS_ERROR;
    if (hr == S_FALSE || retrieved_cnt != 1)
      break;  // No frame.

    DWORD frame_size = 0;
    ULONGLONG frame_base = 0ULL;
    ULONGLONG frame_return_addr = 0ULL;
    if (stack_frame->get_size(&frame_size) != S_OK ||
        stack_frame->get_base(&frame_base) != S_OK ||
        stack_frame->get_returnAddress(&frame_return_addr) != S_OK)
      return ANALYSIS_ERROR;

    // TODO(manzagop): populate process state with stack frame information.

    if (frame_return_addr == 0ULL) {
      // WinDBG seems to use this as a termination criterion.
      break;
    }
  }

  return ANALYSIS_COMPLETE;
}

}  // namespace refinery
