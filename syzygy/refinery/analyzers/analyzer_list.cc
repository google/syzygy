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

namespace {
typedef const ProcessState::LayerEnum* (*GetLayersFunction)();

struct DepsStruct {
  const char* name;
  GetLayersFunction input_layers;
  GetLayersFunction output_layers;
};

const DepsStruct kLayerDeps[] = {
#define DECLARE_ANALYZER_DEPS(analyzer_name)                          \
  {                                                                   \
    #analyzer_name "Analyzer", &analyzer_name##Analyzer::InputLayers, \
        &analyzer_name##Analyzer::OutputLayers,                       \
  }                                                                   \
  ,

    ANALYZER_LIST(DECLARE_ANALYZER_DEPS)

#undef DECLARE_ANALYZER_DEPS
};

bool CopyLayers(GetLayersFunction fn, AnalyzerList::Layers* layers) {
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

Analyzer* AnalyzerList::CreateAnalyzer(const base::StringPiece& name) {
#define CREATE_ANALYZER(analyzer_name)   \
  if (name == #analyzer_name "Analyzer") \
    return new analyzer_name##Analyzer();

  ANALYZER_LIST(CREATE_ANALYZER)

#undef CREATE_ANALYZER

  return nullptr;
}

bool AnalyzerList::GetInputLayers(const base::StringPiece& name,
                                  Layers* layers) {
  DCHECK(layers);
  layers->clear();

  for (const auto& dep : kLayerDeps) {
    if (name == dep.name)
      return CopyLayers(dep.input_layers, layers);
  }

  return false;
}

bool AnalyzerList::GetOutputLayers(const base::StringPiece& name,
                                   Layers* layers) {
  DCHECK(layers);
  layers->clear();

  for (const auto& dep : kLayerDeps) {
    if (name == dep.name)
      return CopyLayers(dep.output_layers, layers);
  }

  return false;
}

}  // namespace refinery
