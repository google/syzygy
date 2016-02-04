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

#ifndef SYZYGY_REFINERY_ANALYZERS_STACK_ANALYZER_H_
#define SYZYGY_REFINERY_ANALYZERS_STACK_ANALYZER_H_

#include <dia2.h>

#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/win/scoped_comptr.h"
#include "syzygy/refinery/analyzers/analyzer.h"
#include "syzygy/refinery/process_state/process_state_util.h"
#include "syzygy/refinery/symbols/dia_symbol_provider.h"

namespace refinery {

// fwd.
class StackWalkHelper;

// The stack analyzer populates the process state with information resulting
// from walking the stack.
// TODO(manzagop): Introduce a system for managing analyzer order prerequisites?
class StackAnalyzer : public Analyzer {
 public:
  StackAnalyzer();

  const char* name() const override { return kStackAnalyzerName; }

  AnalysisResult Analyze(const minidump::Minidump& minidump,
                         const ProcessAnalysis& process_analysis) override;

  ANALYZER_INPUT_LAYERS(ProcessState::BytesLayer,
                        ProcessState::ModuleLayer,
                        ProcessState::StackLayer)
  ANALYZER_OUTPUT_LAYERS(ProcessState::StackFrameLayer)

 private:
  AnalysisResult StackWalk(StackRecordPtr stack_record,
                           const ProcessAnalysis& process_analysis);

  // Inserts data about @p stack_frame into @p process_state.
  bool InsertStackFrameRecord(IDiaStackFrame* stack_frame,
                              const ProcessAnalysis& process_analysis);

  static const char kStackAnalyzerName[];

  base::win::ScopedComPtr<IDiaStackWalker> stack_walker_;
  scoped_refptr<StackWalkHelper> stack_walk_helper_;

  // A frame's data is often located relative to the CV_ALLREG_VFRAME. However,
  // we observe this is relative to the parent frame's value. For ease of
  // access, we store the parent frame's value in the frame's context.
  RegisterInformation* child_frame_context_;

  DISALLOW_COPY_AND_ASSIGN(StackAnalyzer);
};

}  // namespace refinery

#endif  // SYZYGY_REFINERY_ANALYZERS_STACK_ANALYZER_H_
