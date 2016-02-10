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

#ifndef SYZYGY_REFINERY_ANALYZERS_EXCEPTION_ANALYZER_H_
#define SYZYGY_REFINERY_ANALYZERS_EXCEPTION_ANALYZER_H_

#include "base/macros.h"
#include "syzygy/refinery/analyzers/analyzer.h"
#include "syzygy/refinery/process_state/process_state.h"

namespace refinery {

// The exception analyzer populates the stack layer with exception data from the
// minidump. The stack layer must be populated before analysis is performed.
// TODO(manzagop): parse the exception's context.
class ExceptionAnalyzer : public Analyzer {
 public:
  ExceptionAnalyzer() {}
  const char* name() const override { return kExceptionAnalyzerName; }

  AnalysisResult Analyze(const minidump::Minidump& minidump,
                         const ProcessAnalysis& process_analysis) override;

  ANALYZER_INPUT_LAYERS(ProcessState::StackLayer)
  ANALYZER_OUTPUT_LAYERS(ProcessState::StackLayer)

 private:
  static const char kExceptionAnalyzerName[];

  DISALLOW_COPY_AND_ASSIGN(ExceptionAnalyzer);
};

}  // namespace refinery

#endif  // SYZYGY_REFINERY_ANALYZERS_EXCEPTION_ANALYZER_H_
