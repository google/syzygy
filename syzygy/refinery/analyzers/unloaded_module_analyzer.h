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

#ifndef SYZYGY_REFINERY_ANALYZERS_UNLOADED_MODULE_ANALYZER_H_
#define SYZYGY_REFINERY_ANALYZERS_UNLOADED_MODULE_ANALYZER_H_

#include "base/macros.h"
#include "syzygy/refinery/analyzers/analyzer.h"

namespace refinery {

// The unloaded module analyzer populates the UnloadedModule layer from
// information in the minidump.
class UnloadedModuleAnalyzer : public Analyzer {
 public:
  UnloadedModuleAnalyzer() {}
  const char* name() const override { return kUnloadedModuleAnalyzerName; }

  AnalysisResult Analyze(const minidump::Minidump& minidump,
                         const ProcessAnalysis& process_state) override;

  ANALYZER_NO_INPUT_LAYERS()
  ANALYZER_NO_OUTPUT_LAYERS()

 private:
  static const char kUnloadedModuleAnalyzerName[];
  DISALLOW_COPY_AND_ASSIGN(UnloadedModuleAnalyzer);
};

}  // namespace refinery

#endif  // SYZYGY_REFINERY_ANALYZERS_UNLOADED_MODULE_ANALYZER_H_
