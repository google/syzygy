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

#include "base/numerics/safe_math.h"
#include "base/strings/stringprintf.h"
#include "syzygy/common/com_utils.h"
#include "syzygy/pe/dia_util.h"
#include "syzygy/refinery/analyzers/stack_analyzer_impl.h"
#include "syzygy/refinery/process_state/refinery.pb.h"

namespace refinery {

namespace {

bool GetRegisterValue(IDiaStackFrame* frame,
                      CV_HREG_e register_index,
                      uint32_t* register_value) {
  DCHECK(frame); DCHECK(register_value);

  uint64_t value = 0ULL;
  if (!pe::GetRegisterValue(frame, register_index, &value)) {
    return false;
  }
  base::CheckedNumeric<uint32_t> checked_value =
      base::CheckedNumeric<uint32_t>::cast(value);
  if (!checked_value.IsValid()) {
    LOG(ERROR) << "register value is not a 32 bit value.";
    return false;
  }
  *register_value = checked_value.ValueOrDie();
  return true;
}

}  // namespace

// static
const char StackAnalyzer::kStackAnalyzerName[] = "StackAnalyzer";

StackAnalyzer::StackAnalyzer() : child_frame_context_(nullptr) {
}

Analyzer::AnalysisResult StackAnalyzer::Analyze(
    const minidump::Minidump& minidump,
    const ProcessAnalysis& process_analysis) {
  DCHECK(process_analysis.process_state() != nullptr);
  DCHECK(process_analysis.dia_symbol_provider() != nullptr);

  // Create stack walker and helper.
  if (!pe::CreateDiaObject(stack_walker_.Receive(),
                           CLSID_DiaStackWalker)) {
      return ANALYSIS_ERROR;
    }
  stack_walk_helper_ =
      new StackWalkHelper(process_analysis.dia_symbol_provider());

  // Get the stack layer - it must already have been populated.
  StackLayerPtr stack_layer;
  if (!process_analysis.process_state()->FindLayer(&stack_layer)) {
    LOG(ERROR) << "Missing stack layer.";
    return ANALYSIS_ERROR;
  }

  // Process each thread's stack.
  Analyzer::AnalysisResult result = ANALYSIS_COMPLETE;
  for (StackRecordPtr stack_record : *stack_layer) {
    // Attempt to stack walk. Note that the stack walk derailing is not an
    // analysis error.
    Analyzer::AnalysisResult stack_result =
        StackWalk(stack_record, process_analysis);
    if (stack_result == ANALYSIS_ERROR)
      return ANALYSIS_ERROR;
    if (stack_result == ANALYSIS_ITERATE)
      result = ANALYSIS_ITERATE;
  }

  return result;
}

Analyzer::AnalysisResult StackAnalyzer::StackWalk(
    StackRecordPtr stack_record,
    const ProcessAnalysis& process_analysis) {
  stack_walk_helper_->SetState(stack_record, process_analysis.process_state());
  child_frame_context_ = nullptr;

  // Create the frame enumerator.
  base::win::ScopedComPtr<IDiaEnumStackFrames> frame_enumerator;
  // TODO(manzagop): this is for x86 platforms. Switch to getEnumFrames2.
  HRESULT hr = stack_walker_->getEnumFrames(
      static_cast<IDiaStackWalkHelper*>(stack_walk_helper_.get()),
      frame_enumerator.Receive());
  if (hr != S_OK) {
    LOG(ERROR) << "Failed to get frame enumerator: " << common::LogHr(hr)
               << ".";
    return ANALYSIS_ERROR;
  }
  frame_enumerator->Reset();

  // Walk the stack frames.
  // TODO(manzagop): changes for non-X86 platforms (eg registers).
  while (true) {
    base::win::ScopedComPtr<IDiaStackFrame> stack_frame;
    DWORD retrieved_cnt = 0;
    hr = frame_enumerator->Next(1, stack_frame.Receive(), &retrieved_cnt);
    if (!SUCCEEDED(hr)) {
      // Stack walking derailed. Not an an analyzer error per se.
      LOG(ERROR) << "Failed to get stack frame: " << common::LogHr(hr) << ".";
      return ANALYSIS_COMPLETE;
    }
    if (hr == S_FALSE || retrieved_cnt != 1)
      break;  // No frame.

    if (!InsertStackFrameRecord(stack_frame.get(), process_analysis))
      return ANALYSIS_ERROR;

    // WinDBG seems to use a null return address as a termination criterion.
    ULONGLONG frame_return_addr = 0ULL;
    hr = stack_frame->get_returnAddress(&frame_return_addr);
    if (hr != S_OK) {
      LOG(ERROR) << "Failed to get frame's return address: "
                 << common::LogHr(hr) << ".";
      return ANALYSIS_ERROR;
    }
    if (frame_return_addr == 0ULL) {
      stack_record->mutable_data()->set_stack_walk_success(true);
      break;
    }
  }

  return ANALYSIS_COMPLETE;
}

// TODO(manzagop): revise when support expands beyond x86.
bool StackAnalyzer::InsertStackFrameRecord(
    IDiaStackFrame* stack_frame,
    const ProcessAnalysis& process_analysis) {
  RegisterInformation* child_context = child_frame_context_;
  child_frame_context_ = nullptr;

  // Get the frame's base.
  uint64_t frame_base = 0ULL;
  if (!pe::GetFrameBase(stack_frame, &frame_base))
    return false;

  // Get frame's top.
  uint64_t frame_top = 0ULL;
  if (!pe::GetRegisterValue(stack_frame, CV_REG_ESP, &frame_top))
    return false;

  // Get the frame's size. Note: this differs from the difference between
  // top of frame and base in that it excludes callee parameter size.
  uint32_t frame_size = 0U;
  if (!pe::GetSize(stack_frame, &frame_size))
    return false;

  // Get base address of locals.
  uint64_t locals_base = 0ULL;
  if (!pe::GetLocalsBase(stack_frame, &locals_base))
    return false;

  // TODO(manzagop): get register values and some notion about their validity.

  // Populate the stack frame layer.

  // Compute the frame's full size.
  DCHECK_LE(frame_top, frame_base);
  base::CheckedNumeric<Size> frame_full_size =
      base::CheckedNumeric<Size>::cast(frame_base - frame_top);
  if (!frame_full_size.IsValid()) {
    LOG(ERROR) << "Frame full size doesn't fit a 32bit integer.";
    return false;
  }

  if (frame_full_size.ValueOrDie() == 0U)
    return true;  // Skip empty frame.

  // Create the stack frame record.
  AddressRange range(static_cast<Address>(frame_top),
                     static_cast<Size>(frame_full_size.ValueOrDie()));
  if (!range.IsValid()) {
    LOG(ERROR) << "Invalid frame range.";
    return false;
  }

  StackFrameLayerPtr frame_layer;
  process_analysis.process_state()->FindOrCreateLayer(&frame_layer);

  StackFrameRecordPtr frame_record;
  frame_layer->CreateRecord(range, &frame_record);
  StackFrame* frame_proto = frame_record->mutable_data();

  // Populate the stack frame record.

  // Register context.
  // TODO(manzagop): flesh out the register context.
  RegisterInformation* context = frame_proto->mutable_register_info();
  uint32_t eip = 0U;
  if (!GetRegisterValue(stack_frame, CV_REG_EIP, &eip))
    return false;
  context->set_eip(eip);
  uint32_t allreg_vframe = 0U;
  if (GetRegisterValue(stack_frame, CV_ALLREG_VFRAME, &allreg_vframe)) {
    // Register doesn't seem to always be available. Not considered an error.
    context->set_allreg_vframe(allreg_vframe);
    if (child_context)
      child_context->set_parent_allreg_vframe(allreg_vframe);
  }

  frame_proto->set_frame_size_bytes(frame_size);
  frame_proto->set_locals_base(locals_base);

  child_frame_context_ = context;
  return true;
}

}  // namespace refinery
