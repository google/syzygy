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

#include "syzygy/refinery/analyzers/exception_analyzer.h"

#include <dbghelp.h>
#include <memory>

#include "syzygy/refinery/analyzers/analyzer_util.h"
#include "syzygy/refinery/process_state/process_state_util.h"
#include "syzygy/refinery/process_state/refinery.pb.h"

namespace refinery {

// static
const char ExceptionAnalyzer::kExceptionAnalyzerName[] = "ExceptionAnalyzer";

Analyzer::AnalysisResult ExceptionAnalyzer::Analyze(
    const minidump::Minidump& minidump,
    const ProcessAnalysis& process_analysis) {
  DCHECK(process_analysis.process_state() != nullptr);

  // Retrieve the unique exception stream.
  minidump::Minidump::Stream exception_stream =
      minidump.FindNextStream(nullptr, ExceptionStream);
  if (!exception_stream.IsValid()) {
    // Minidump has no exception data.
    return ANALYSIS_COMPLETE;
  }
  minidump::Minidump::Stream offending_stream =
      minidump.FindNextStream(&exception_stream, ExceptionStream);
  if (offending_stream.IsValid())
    return ANALYSIS_ERROR;

  MINIDUMP_EXCEPTION_STREAM minidump_exception_stream = {};
  if (!exception_stream.ReadAndAdvanceElement(&minidump_exception_stream))
    return ANALYSIS_ERROR;
  const MINIDUMP_EXCEPTION& exception_record =
      minidump_exception_stream.ExceptionRecord;

  // TODO(manzagop): Consider chained exceptions
  // (exception_record.ExceptionRecord).

  // Populate the exception information.
  Exception exception;
  exception.set_thread_id(minidump_exception_stream.ThreadId);
  exception.set_exception_code(exception_record.ExceptionCode);
  exception.set_exception_flags(exception_record.ExceptionFlags);
  exception.set_exception_record(exception_record.ExceptionRecord);
  exception.set_exception_address(exception_record.ExceptionAddress);
  for (int i = 0; i < exception_record.NumberParameters; ++i) {
    exception.add_exception_information(
        exception_record.ExceptionInformation[i]);
  }

  minidump::Minidump::Stream thread_context =
      minidump.GetStreamFor(minidump_exception_stream.ThreadContext);
  if (!thread_context.IsValid())
    return ANALYSIS_ERROR;
  // TODO(siggi): This ought to probe for the architecture somehow.
  CONTEXT ctx = {};
  if (!thread_context.ReadAndAdvanceElement(&ctx))
    return ANALYSIS_ERROR;
  ParseContext(ctx, exception.mutable_register_info());

  // Add the exception information to the process state.
  if (!process_analysis.process_state()->SetException(exception))
    return ANALYSIS_ERROR;

  return ANALYSIS_COMPLETE;
}

}  // namespace refinery
