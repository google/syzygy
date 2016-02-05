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

#include "syzygy/refinery/analyzers/analyzer_list.h"

#include "syzygy/refinery/analyzers/exception_analyzer.h"
#include "syzygy/refinery/analyzers/heap_analyzer.h"
#include "syzygy/refinery/analyzers/memory_analyzer.h"
#include "syzygy/refinery/analyzers/module_analyzer.h"
#include "syzygy/refinery/analyzers/stack_analyzer.h"
#include "syzygy/refinery/analyzers/stack_frame_analyzer.h"
#include "syzygy/refinery/analyzers/teb_analyzer.h"
#include "syzygy/refinery/analyzers/thread_analyzer.h"
#include "syzygy/refinery/analyzers/type_propagator_analyzer.h"
#include "syzygy/refinery/analyzers/unloaded_module_analyzer.h"

namespace refinery {

// The list of analyzers known to the AnalyzerList. Add new analyzers here.
#define ANALYZER_LIST(DECL) \
  DECL(Exception)           \
  DECL(Heap)                \
  DECL(Memory)              \
  DECL(Module)              \
  DECL(Stack)               \
  DECL(StackFrame)          \
  DECL(Teb)                 \
  DECL(Thread)              \
  DECL(TypePropagator)      \
  DECL(UnloadedModule)

namespace {
typedef const ProcessState::LayerEnum* (*GetLayersFunction)();

struct AnalyzerDescription {
  const char* name;
  GetLayersFunction input_layers;
  GetLayersFunction output_layers;
};

const AnalyzerDescription kKnownAnalyzers[] = {
#define DECLARE_KNOWN_ANALYZER(analyzer_name)                         \
  {                                                                   \
    #analyzer_name "Analyzer", &analyzer_name##Analyzer::InputLayers, \
        &analyzer_name##Analyzer::OutputLayers,                       \
  }                                                                   \
  ,

    ANALYZER_LIST(DECLARE_KNOWN_ANALYZER)

#undef DECLARE_KNOWN_ANALYZER
};

bool CopyLayers(GetLayersFunction fn, StaticAnalyzerList::Layers* layers) {
  DCHECK(fn);
  DCHECK(layers);

  const ProcessState::LayerEnum* l = fn();
  if (l == nullptr)
    return false;

  for (; *l != ProcessState::UnknownLayer; ++l)
    layers->push_back(*l);

  return true;
}

}  // namespace

void StaticAnalyzerList::GetAnalyzerNames(AnalyzerNames* names) const {
  DCHECK(names);

  names->clear();
  for (const auto& dep : kKnownAnalyzers)
    names->push_back(dep.name);
}

Analyzer* StaticAnalyzerList::CreateAnalyzer(
    const base::StringPiece& name) const {
#define CREATE_ANALYZER(analyzer_name)   \
  if (name == #analyzer_name "Analyzer") \
    return new analyzer_name##Analyzer();

  ANALYZER_LIST(CREATE_ANALYZER)

#undef CREATE_ANALYZER

  return nullptr;
}

bool StaticAnalyzerList::GetInputLayers(const base::StringPiece& name,
                                        Layers* layers) const {
  DCHECK(layers);
  layers->clear();

  for (const auto& dep : kKnownAnalyzers) {
    if (name == dep.name)
      return CopyLayers(dep.input_layers, layers);
  }

  return false;
}

bool StaticAnalyzerList::GetOutputLayers(const base::StringPiece& name,
                                         Layers* layers) const {
  DCHECK(layers);
  layers->clear();

  for (const auto& dep : kKnownAnalyzers) {
    if (name == dep.name)
      return CopyLayers(dep.output_layers, layers);
  }

  return false;
}

}  // namespace refinery
