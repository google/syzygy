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

#ifndef SYZYGY_REFINERY_ANALYZERS_TYPE_PROPAGATOR_ANALYZER_H_
#define SYZYGY_REFINERY_ANALYZERS_TYPE_PROPAGATOR_ANALYZER_H_

#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "syzygy/refinery/analyzers/analyzer.h"
#include "syzygy/refinery/symbols/symbol_provider.h"
#include "syzygy/refinery/types/typed_data.h"

namespace refinery {

// The type propagator looks for typed pointers in existing typed blocks,
// and propagates the type to the destination block.
// TODO(manzagop): The analyzer currently does a single analysis pass over the
// contents of the typed block layer. Add processing for the newly generated
// types.
// TODO(manzagop): The analyzer may be called more than once, eg if another
// analyzer produces new typed blocks. Have a mechanism to avoid re-processing
// previously analyzed typed blocks.
class TypePropagatorAnalyzer : public Analyzer {
 public:
  TypePropagatorAnalyzer();
  const char* name() const override { return kTypePropagatorAnalyzerName; }

  AnalysisResult Analyze(const minidump::Minidump& minidump,
                         const ProcessAnalysis& process_analysis) override;

  ANALYZER_INPUT_LAYERS(ProcessState::BytesLayer, ProcessState::TypedBlockLayer)
  ANALYZER_OUTPUT_LAYERS(ProcessState::TypedBlockLayer)

 private:
  bool AnalyzeTypedData(const TypedData& data, ProcessState* process_state);
  bool AnalyzeTypedDataUDT(const TypedData& typed_data,
                           ProcessState* process_state);
  bool AnalyzeTypedDataPointer(const TypedData& typed_data,
                               ProcessState* process_state);
  bool AnalyzeTypedDataArray(const TypedData& typed_data,
                             ProcessState* process_state);

  bool AddTypedBlock(const TypedData& typed_data, ProcessState* process_state);

  static const char kTypePropagatorAnalyzerName[];

  DISALLOW_COPY_AND_ASSIGN(TypePropagatorAnalyzer);
};

}  // namespace refinery

#endif  // SYZYGY_REFINERY_ANALYZERS_TYPE_PROPAGATOR_ANALYZER_H_
