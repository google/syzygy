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

#ifndef SYZYGY_REFINERY_ANALYZERS_ANALYZER_H_
#define SYZYGY_REFINERY_ANALYZERS_ANALYZER_H_

#include "syzygy/minidump/minidump.h"
#include "syzygy/refinery/process_state/process_state.h"

namespace refinery {

// The interface implemented by analyzers. Each analyzer is responsible for
// analyzing some part of the minidump and/or the process state. Analyzers will
// for example extract memory/thread/module information from minidumps to
// fill in the appropriate layers in the process state.
// Other analyzers may work solely on the process state, by e.g. coalescing
// overlapping, consistent data in a layer, propagating type information,
// discovering references and the like.
class Analyzer {
 public:
  enum AnalysisResult {
    ANALYSIS_COMPLETE,
    ANALYSIS_ITERATE,
    ANALYSIS_ERROR,
  };

  virtual ~Analyzer() = 0 {};

  virtual const char* name() const = 0;

  // Analyze @p minidump and update @p process_state. Analysis may involve
  // examining @p process_state, and may be an iterative process.
  // @param minidump the minidump under analysis.
  // @param process_state the process_state that contains the results of the
  //     analysis.
  // @returns an analysis result. An analyzer may not be invoked again after
  //     it's returned ANALYSIS_COMPLETE. If an analyzer returns ANALYSIS_ERROR
  //     @p process_state may be inconsistent.
  // @note Analysis completes only once all analyzers have returned
  //     ANALYSIS_COMPLETED.
  virtual AnalysisResult Analyze(const minidump::Minidump& minidump,
                                 ProcessState* process_state) = 0;
};

}  // namespace refinery

#endif  // SYZYGY_REFINERY_ANALYZERS_ANALYZER_H_
