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

#ifndef SYZYGY_REFINERY_ANALYZERS_ANALYSIS_RUNNER_H_
#define SYZYGY_REFINERY_ANALYZERS_ANALYSIS_RUNNER_H_

#include <memory>
#include <vector>

#include "base/macros.h"
#include "syzygy/minidump/minidump.h"
#include "syzygy/refinery/analyzers/analyzer.h"
#include "syzygy/refinery/process_state/process_state.h"

namespace refinery {

// The analysis runner runs analyzers over a minidump to populate a process
// state.
// TODO(manzagop): support iterative analysis (analyzers returning
// ANALYSIS_ITERATE).
class AnalysisRunner {
 public:
  AnalysisRunner();
  ~AnalysisRunner();

  // Adds @p analyzer to the runner.
  // @param analyzer an analyzer to take ownership of. Deleted on runner's
  //   destruction.
  void AddAnalyzer(std::unique_ptr<Analyzer> analyzer);

  // Runs analyzers over @p minidump and updates the ProcessState supplied
  // through @p process_analysis.
  // @param minidump the minidump to analyze.
  // @param process_analysis the process analysis passed to the analyzers.
  // @returns an analysis result. ANALYSIS_COMPLETE is returned if all analyzers
  //   return it. Otherwise, ANALYSIS_ERROR is returned in which case @p
  //   process_state may be inconsistent.
  Analyzer::AnalysisResult Analyze(
      const minidump::Minidump& minidump,
      const Analyzer::ProcessAnalysis& process_analysis);

 private:
  std::vector<Analyzer*> analyzers_;  // Owned.

  DISALLOW_COPY_AND_ASSIGN(AnalysisRunner);
};

}  // namespace refinery

#endif  // SYZYGY_REFINERY_ANALYZERS_ANALYSIS_RUNNER_H_
