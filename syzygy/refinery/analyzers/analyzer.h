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
#include "syzygy/refinery/symbols/dia_symbol_provider.h"
#include "syzygy/refinery/symbols/symbol_provider.h"

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
    // Analyzer will not do any more work if re-invoked.
    ANALYSIS_COMPLETE,
    // Analyzer may do more work if re-invoked.
    ANALYSIS_ITERATE,
    // Analyzer encountered an error.
    ANALYSIS_ERROR,
  };
  class ProcessAnalysis;

  virtual ~Analyzer() = 0 {};
  // @returns the analyzer's name.
  virtual const char* name() const = 0;

  // Analyze @p minidump and update the ProcessState provided through
  //     @p process_analysis. Analysis may involve examining the ProcessState,
  //     and may be an iterative process.
  // @param minidump the minidump under analysis.
  // @param process_analysis provides the ProcessState to update, along with
  //     factories providing symbols etc, necessary to perform the analysis.
  // @returns an analysis result. An analyzer may not be invoked again after
  //     it's returned ANALYSIS_COMPLETE. If an analyzer returns ANALYSIS_ERROR
  //     the resultant ProcessState may be inconsistent.
  // @note Analysis completes only once all analyzers have returned
  //     ANALYSIS_COMPLETED.
  virtual AnalysisResult Analyze(const minidump::Minidump& minidump,
                                 const ProcessAnalysis& process_analysis) = 0;
};

// A process analysis brokers the state that analyzers may need during
// analysis. It vends the process state, symbol providers and so on.
class Analyzer::ProcessAnalysis {
 public:
  // The process state to update in this analysis.
  virtual ProcessState* process_state() const = 0;

  // A DIA symbol provider to use during this analysis.
  virtual scoped_refptr<DiaSymbolProvider> dia_symbol_provider() const = 0;

  // A symbol provider to use during this analysis.
  virtual scoped_refptr<SymbolProvider> symbol_provider() const = 0;
};

// @name Utility macros to allow declaring analyzer input and output layer
//     dependencies.
// @{
#define ANALYZER_INPUT_LAYERS(...)                          \
  static const ProcessState::LayerEnum* InputLayers() {     \
    static const ProcessState::LayerEnum kInputLayers[] = { \
        __VA_ARGS__, ProcessState::UnknownLayer};           \
    return kInputLayers;                                    \
  }

#define ANALYZER_NO_INPUT_LAYERS()                      \
  static const ProcessState::LayerEnum* InputLayers() { \
    static const ProcessState::LayerEnum kSentinel =    \
        ProcessState::UnknownLayer;                     \
    return &kSentinel;                                  \
  }

#define ANALYZER_OUTPUT_LAYERS(...)                          \
  static const ProcessState::LayerEnum* OutputLayers() {     \
    static const ProcessState::LayerEnum kOutputLayers[] = { \
        __VA_ARGS__, ProcessState::UnknownLayer};            \
    return kOutputLayers;                                    \
  }

#define ANALYZER_NO_OUTPUT_LAYERS()                      \
  static const ProcessState::LayerEnum* OutputLayers() { \
    static const ProcessState::LayerEnum kSentinel =     \
        ProcessState::UnknownLayer;                      \
    return &kSentinel;                                   \
  }

// @}

}  // namespace refinery

#endif  // SYZYGY_REFINERY_ANALYZERS_ANALYZER_H_
