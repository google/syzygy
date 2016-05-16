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

#include "syzygy/refinery/analyzers/module_analyzer.h"

#include <dbghelp.h>

#include <memory>
#include <string>
#include <vector>

#include "base/strings/utf_string_conversions.h"
#include "syzygy/refinery/process_state/process_state_util.h"
#include "syzygy/refinery/process_state/refinery.pb.h"

namespace refinery {

// static
const char ModuleAnalyzer::kModuleAnalyzerName[] = "ModuleAnalyzer";

Analyzer::AnalysisResult ModuleAnalyzer::Analyze(
    const minidump::Minidump& minidump,
    const ProcessAnalysis& process_analysis) {
  DCHECK(process_analysis.process_state() != nullptr);

  ModuleLayerAccessor layer_accessor(process_analysis.process_state());

  minidump::Minidump::TypedModuleList modules = minidump.GetModuleList();
  if (!modules.IsValid())
      return ANALYSIS_ERROR;

  for (const auto& module : modules) {
    AddressRange range(module.BaseOfImage, module.SizeOfImage);
    if (!range.IsValid())
      return ANALYSIS_ERROR;

    // Determine module's name.
    MINIDUMP_LOCATION_DESCRIPTOR name_location = {};
    name_location.DataSize =
        static_cast<ULONG32>(-1);  // Note: actual size is in the stream.
    name_location.Rva = module.ModuleNameRva;
    minidump::Minidump::Stream name_stream =
        minidump.GetStreamFor(name_location);
    DCHECK(name_stream.IsValid());
    std::wstring module_name;
    if (!name_stream.ReadAndAdvanceString(&module_name))
      return ANALYSIS_ERROR;

    // TODO(manzagop): get version / debug info by also reading VersionInfo,
    // CvRecord and MiscRecord.

    layer_accessor.AddModuleRecord(range, module.CheckSum, module.TimeDateStamp,
                                   module_name);
  }

  return ANALYSIS_COMPLETE;
}

}  // namespace refinery
