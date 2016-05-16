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

#include "syzygy/refinery/analyzers/stack_frame_analyzer.h"

#include <vector>

#include "base/bind.h"
#include "base/strings/stringprintf.h"
#include "base/win/scoped_comptr.h"
#include "syzygy/common/com_utils.h"
#include "syzygy/pe/dia_util.h"
#include "syzygy/refinery/analyzers/stack_frame_analyzer_impl.h"
#include "syzygy/refinery/process_state/layer_data.h"
#include "syzygy/refinery/process_state/process_state.h"
#include "syzygy/refinery/process_state/process_state_util.h"
#include "syzygy/refinery/types/type_repository.h"

namespace refinery {

namespace {

bool GetInnerMostScopeForVA(IDiaSession* session,
                            Address va,
                            base::win::ScopedComPtr<IDiaSymbol>* scope) {
  DCHECK(session);
  DCHECK(scope);

  // Attempt to get a block.
  HRESULT hr = session->findSymbolByVA(va, SymTagBlock, scope->Receive());
  if (hr != S_OK) {
    // No SymTagBlock. Attempt to get a SymTagFunction.
    hr = session->findSymbolByVA(va, SymTagFunction, scope->Receive());
    if (hr != S_OK) {
      LOG(ERROR) << base::StringPrintf(
                        "Failed to find block or function for VA (%08llx): ",
                        va) << common::LogHr(hr);
      return false;
    }
  }

  return true;
}

}  // namespace

// static
const char StackFrameAnalyzer::kStackFrameAnalyzerName[] = "StackFrameAnalyzer";

StackFrameAnalyzer::StackFrameAnalyzer() {
}

Analyzer::AnalysisResult StackFrameAnalyzer::Analyze(
    const minidump::Minidump& minidump,
    const ProcessAnalysis& process_analysis) {
  DCHECK(process_analysis.process_state() != nullptr);

  ProcessState* process_state = process_analysis.process_state();
  DCHECK(process_state != nullptr);

  // Ensure the stack frame layer has already been populated.
  StackFrameLayerPtr frame_layer;
  if (!process_state->FindLayer(&frame_layer)) {
    LOG(ERROR) << "StackFrameAnalyzer: no stack frame layer.";
    return ANALYSIS_ERROR;
  }

  // Process each stack frame.
  for (StackFrameRecordPtr frame_record : *frame_layer) {
    // TODO(manzagop): figure out the proper return value and handling for
    // AnalyzeFrame. We won't always be able to analyze frame (eg no symbols)
    // and that's acceptable.
    AnalyzeFrame(frame_record, process_analysis);
  }

  return ANALYSIS_COMPLETE;
}

bool StackFrameAnalyzer::AnalyzeFrame(StackFrameRecordPtr frame_record,
                                      const ProcessAnalysis& process_analysis) {
  DCHECK(frame_record.get() != nullptr);
  DCHECK(process_analysis.process_state() != nullptr);

  const StackFrame& frame_proto = frame_record->data();
  Address instruction_pointer =
      static_cast<Address>(frame_proto.register_info().eip());

  // Retrieve symbol information.
  if (!SetSymbolInformation(instruction_pointer, process_analysis)) {
    LOG(INFO) << "Unable to get symbol information for frame. Skipping.";
    return true;  // Not an error.
  }
  ModuleLayerAccessor accessor(process_analysis.process_state());
  ModuleId module_id = accessor.GetModuleId(instruction_pointer);
  if (module_id == kNoModuleId) {
    LOG(INFO) << "No module corresponding to instruction pointer.";
    return false;
  }

  // Get the innermost scope, be it a block or the function itself.
  // TODO(manzagop): Identical code folding means there may be more than one
  // symbol for a given address. Look into this.
  base::win::ScopedComPtr<IDiaSymbol> scope;
  if (!GetInnerMostScopeForVA(dia_session_.get(), instruction_pointer, &scope))
    return false;

  // Walk up the scopes, processing scope's data.
  StackFrameDataAnalyzer data_analyzer(frame_record, typename_index_, module_id,
                                       process_analysis.process_state());
  while (true) {
    // Process each SymTagData child in the block / function.
    // TODO(manzagop): the data visitor will stop visiting at the first error.
    // Figure out how to surface issues without preventing processing (eg
    // with a callback).
    pe::ChildVisitor data_visitor(scope.get(), SymTagData);
    if (!data_visitor.VisitChildren(
            base::Bind(&StackFrameDataAnalyzer::Analyze,
                       base::Unretained(&data_analyzer)))) {
      LOG(ERROR) << "Error while analyzing scope. Continuing to next scope.";
      return false;
    }

    // Stop processing when function has been processed.
    enum SymTagEnum sym_tag_scope = SymTagNull;
    if (!pe::GetSymTag(scope.get(), &sym_tag_scope))
      return false;
    if (sym_tag_scope == SymTagFunction)
      break;

    // Move up to lexical parent.
    base::win::ScopedComPtr<IDiaSymbol> lexical_parent;
    if (!pe::GetSymLexicalParent(scope.get(), &lexical_parent))
      return false;  // We should be able to get to a function.
    scope = lexical_parent;
  }

  return true;
}

bool StackFrameAnalyzer::SetSymbolInformation(
    Address instruction_pointer,
    const ProcessAnalysis& process_analysis) {
  DCHECK(process_analysis.symbol_provider().get() != nullptr);
  DCHECK(process_analysis.dia_symbol_provider().get() != nullptr);

  dia_session_.Release();
  typename_index_ = nullptr;

  // Get the module's signature.
  ModuleLayerAccessor accessor(process_analysis.process_state());
  pe::PEFile::Signature signature;
  if (!accessor.GetModuleSignature(instruction_pointer, &signature))
    return false;

  // Get the typename index for the module.
  if (!process_analysis.symbol_provider()->FindOrCreateTypeNameIndex(
          signature, &typename_index_)) {
    return false;
  }

  // Get dia session for the module and set its address.
  base::win::ScopedComPtr<IDiaSession> session_tmp;
  if (!process_analysis.dia_symbol_provider()->FindOrCreateDiaSession(
          signature, &session_tmp))
    return false;
  HRESULT hr = session_tmp->put_loadAddress(signature.base_address.value());
  if (FAILED(hr)) {
    LOG(ERROR) << "Unable to set session's load address: " << common::LogHr(hr);
    return false;
  }
  dia_session_ = session_tmp;

  return true;
}

}  // namespace refinery
