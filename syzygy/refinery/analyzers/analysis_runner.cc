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

#include "syzygy/refinery/analyzers/analysis_runner.h"

#include "base/stl_util.h"

namespace refinery {

AnalysisRunner::AnalysisRunner() {
}

AnalysisRunner::~AnalysisRunner() {
  STLDeleteElements(&analyzers_);
}

void AnalysisRunner::AddAnalyzer(std::unique_ptr<Analyzer> analyzer) {
  DCHECK(analyzer);
  analyzers_.push_back(analyzer.release());
}

Analyzer::AnalysisResult AnalysisRunner::Analyze(
    const minidump::Minidump& minidump,
    const Analyzer::ProcessAnalysis& process_analysis) {
  for (Analyzer* analyzer : analyzers_) {
    Analyzer::AnalysisResult result =
        analyzer->Analyze(minidump, process_analysis);
    CHECK(result != Analyzer::ANALYSIS_ITERATE)
        << "Iterative analysis is not supported.";
    if (result != Analyzer::ANALYSIS_COMPLETE) {
      LOG(ERROR) << analyzer->name() << " analysis failed";
      return Analyzer::ANALYSIS_ERROR;
    }
  }
  return Analyzer::ANALYSIS_COMPLETE;
}

}  // namespace refinery
