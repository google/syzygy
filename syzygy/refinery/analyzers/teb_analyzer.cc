// Copyright 2016 Google Inc. All Rights Reserved.
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

#include "syzygy/refinery/analyzers/teb_analyzer.h"

#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "syzygy/refinery/process_state/process_state_util.h"
#include "syzygy/refinery/types/typed_data.h"

namespace refinery {

namespace {

// TODO(siggi): This functionality needs to move somewhere central.
scoped_refptr<TypeRepository> GetNtdllTypes(ProcessState* process_state,
                                            SymbolProvider* symbol_provider,
                                            ModuleId* module_id) {
  DCHECK(process_state);
  DCHECK(symbol_provider);
  DCHECK(module_id);
  *module_id = kNoModuleId;

  ModuleLayerPtr modules;
  if (!process_state->FindLayer(&modules)) {
    LOG(ERROR) << "No modules layer.";
    return nullptr;
  }

  for (const auto& module_sig : modules->data().signatures()) {
    if (base::EndsWith(module_sig.path, L"ntdll.dll",
                       base::CompareCase::INSENSITIVE_ASCII)) {
      pe::PEFile::Signature signature(
          module_sig.path, core::AbsoluteAddress(0U), module_sig.module_size,
          module_sig.module_checksum, module_sig.module_time_date_stamp);
      ModuleLayerAccessor module_access(process_state);

      *module_id = module_access.GetModuleId(signature);
      if (*module_id == kNoModuleId)
        return nullptr;

      scoped_refptr<TypeRepository> ret;
      if (symbol_provider->FindOrCreateTypeRepository(signature, &ret))
        return ret;
    }
  }

  return nullptr;
}

}  // namespace

// static
const char TebAnalyzer::kTebAnalyzerName[] = "TebAnalyzer";

TebAnalyzer::TebAnalyzer() {
}

Analyzer::AnalysisResult TebAnalyzer::Analyze(
    const minidump::Minidump& minidump,
    const ProcessAnalysis& process_analysis) {
  DCHECK(process_analysis.process_state() != nullptr);

  // Start by finding the NTDLL module record and symbols, as that's where we
  // come by the symbols that describe the heap.
  ModuleId module_id = kNoModuleId;
  scoped_refptr<TypeRepository> ntdll_repo =
      GetNtdllTypes(process_analysis.process_state(),
                    process_analysis.symbol_provider().get(), &module_id);
  if (!ntdll_repo || module_id == kNoModuleId) {
    LOG(ERROR) << "Couldn't get types for NTDLL.";
    return ANALYSIS_ERROR;
  }

  UserDefinedTypePtr teb_type;
  for (const auto& type : *ntdll_repo) {
    if (type->GetName() == L"_TEB" && type->CastTo(&teb_type))
      break;
  }

  if (!teb_type) {
    LOG(ERROR) << "Unable to find TEB UDT.";
    return ANALYSIS_ERROR;
  }

  minidump::Minidump::TypedThreadList threads = minidump.GetThreadList();
  if (!threads.IsValid()) {
    LOG(ERROR) << "No threads in minidump.";
    return ANALYSIS_ERROR;
  }

  for (const auto& thread : threads) {
    TypedData teb(process_analysis.process_state(), teb_type,
                  Address(thread.Teb));

    if (!AddTypedBlockRecord(teb.GetRange(), teb_type->GetName(), module_id,
                             teb_type->type_id(),
                             process_analysis.process_state())) {
      LOG(ERROR) << "Failed to add TEB record for thread " << thread.ThreadId;
      return ANALYSIS_ERROR;
    }
  }

  return ANALYSIS_COMPLETE;
}

}  // namespace refinery
