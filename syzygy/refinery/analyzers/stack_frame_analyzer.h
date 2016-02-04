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

#ifndef SYZYGY_REFINERY_ANALYZERS_STACK_FRAME_ANALYZER_H_
#define SYZYGY_REFINERY_ANALYZERS_STACK_FRAME_ANALYZER_H_

#include <dia2.h>

#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "syzygy/refinery/analyzers/analyzer.h"
#include "syzygy/refinery/process_state/process_state_util.h"
#include "syzygy/refinery/symbols/dia_symbol_provider.h"
#include "syzygy/refinery/symbols/symbol_provider.h"
#include "syzygy/refinery/types/type_repository.h"

namespace refinery {

// The stack frame analyzer populates the process state with information
// about the contents of stack frames.
class StackFrameAnalyzer : public Analyzer {
 public:
  StackFrameAnalyzer();

  const char* name() const override { return kStackFrameAnalyzerName; }

  AnalysisResult Analyze(const minidump::Minidump& minidump,
                         const ProcessAnalysis& process_analysis) override;

  ANALYZER_INPUT_LAYERS(ProcessState::BytesLayer,
                        ProcessState::ModuleLayer,
                        ProcessState::StackFrameLayer)
  ANALYZER_OUTPUT_LAYERS(ProcessState::TypedBlockLayer)

 private:
  bool AnalyzeFrame(StackFrameRecordPtr frame_record,
                    const ProcessAnalysis& process_analysis);
  bool SetSymbolInformation(Address instruction_pointer,
                            const ProcessAnalysis& process_analysis);

  static const char kStackFrameAnalyzerName[];

  // Symbol information for the frame being processed.
  base::win::ScopedComPtr<IDiaSession> dia_session_;
  scoped_refptr<TypeNameIndex> typename_index_;

  DISALLOW_COPY_AND_ASSIGN(StackFrameAnalyzer);
};

}  // namespace refinery

#endif  // SYZYGY_REFINERY_ANALYZERS_STACK_FRAME_ANALYZER_H_
