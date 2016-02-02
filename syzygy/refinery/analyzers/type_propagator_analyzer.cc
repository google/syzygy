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

#include "syzygy/refinery/analyzers/type_propagator_analyzer.h"

#include <queue>

#include "syzygy/refinery/process_state/process_state_util.h"
#include "syzygy/refinery/process_state/refinery.pb.h"
#include "syzygy/refinery/types/type.h"

namespace refinery {

// static
const char TypePropagatorAnalyzer::kTypePropagatorAnalyzerName[] =
    "TypePropagatorAnalyzer";

TypePropagatorAnalyzer::TypePropagatorAnalyzer() {
}

Analyzer::AnalysisResult TypePropagatorAnalyzer::Analyze(
    const minidump::Minidump& minidump,
    const ProcessAnalysis& process_analysis) {
  ProcessState* process_state = process_analysis.process_state();
  DCHECK(process_state != nullptr);

  // Analyzers that build content for the bytes and typed block layer must have
  // already run. We use the existence of a bytes layer and a typed block layer
  // as a proxy for this. Longer term, a proper notion of analyzer dependencies
  // should be introduced.
  BytesLayerPtr bytes_layer;
  if (!process_state->FindLayer(&bytes_layer)) {
    LOG(ERROR) << "Missing bytes layer.";
    return ANALYSIS_ERROR;
  }
  TypedBlockLayerPtr typed_layer;
  if (!process_state->FindLayer(&typed_layer)) {
    LOG(ERROR) << "Missing typed block layer.";
    return ANALYSIS_ERROR;
  }

  ModuleLayerAccessor accessor(process_state);

  std::queue<TypedData> process_queue;

  scoped_refptr<SymbolProvider> symbol_provider =
      process_analysis.symbol_provider();
  DCHECK(symbol_provider != nullptr);

  // Recover typed data from the typed block layer.
  for (TypedBlockRecordPtr rec : *typed_layer) {
    const TypedBlock& typedblock = rec->data();

    // Recover the type.
    pe::PEFile::Signature signature;
    if (!accessor.GetModuleSignature(typedblock.module_id(), &signature))
      return ANALYSIS_ERROR;

    scoped_refptr<TypeRepository> type_repository;
    if (!symbol_provider->FindOrCreateTypeRepository(signature,
                                                     &type_repository)) {
      return ANALYSIS_ERROR;
    }

    TypePtr type = type_repository->GetType(typedblock.type_id());
    if (type == nullptr)
      return ANALYSIS_ERROR;

    // Queue typed data for processing.
    process_queue.push(TypedData(process_state, type, rec->range().start()));
  }

  // Process typed data looking for pointers or contained pointers.
  while (!process_queue.empty()) {
    if (!AnalyzeTypedData(process_queue.front(), process_state))
      return ANALYSIS_ERROR;
    process_queue.pop();
  }

  return ANALYSIS_COMPLETE;
}

bool TypePropagatorAnalyzer::AnalyzeTypedData(const TypedData& typed_data,
                                              ProcessState* process_state) {
  DCHECK(process_state != nullptr);

  TypePtr type = typed_data.type();
  DCHECK(type.get());

  switch (type->kind()) {
    case Type::USER_DEFINED_TYPE_KIND:
      return AnalyzeTypedDataUDT(typed_data, process_state);
    case Type::POINTER_TYPE_KIND:
      return AnalyzeTypedDataPointer(typed_data, process_state);
    case Type::ARRAY_TYPE_KIND:
      return AnalyzeTypedDataArray(typed_data, process_state);
    case Type::BASIC_TYPE_KIND:
    case Type::FUNCTION_TYPE_KIND:
    case Type::GLOBAL_TYPE_KIND:
    case Type::WILDCARD_TYPE_KIND:
      // Nothing to do with these.
      return true;
    default:
      DCHECK(false);
      return false;
  }
}

bool TypePropagatorAnalyzer::AnalyzeTypedDataUDT(const TypedData& typed_data,
                                                 ProcessState* process_state) {
  DCHECK_EQ(Type::USER_DEFINED_TYPE_KIND, typed_data.type()->kind());
  DCHECK(process_state != nullptr);

  size_t field_count = 0U;
  if (!typed_data.GetFieldCount(&field_count))
    return false;

  for (size_t i = 0; i < field_count; ++i) {
    TypedData field_data;
    if (!typed_data.GetField(i, &field_data))
      return false;  // No valid reason for this to fail.
    if (!AnalyzeTypedData(field_data, process_state))
      return false;
  }

  return true;
}

bool TypePropagatorAnalyzer::AnalyzeTypedDataPointer(
    const TypedData& typed_data,
    ProcessState* process_state) {
  DCHECK(typed_data.IsPointerType());
  DCHECK(process_state != nullptr);

  TypedData content_data;
  if (!typed_data.Dereference(&content_data)) {
    // Unable to dereference. This may be because the pointer's contents (the
    // address of the pointee) are not available.
    // TODO(manzagop): have a better way to distinguish a failure (can't cast
    // pointer) from an acceptable negative result (missing the required bytes)
    // and have counters for these kinds of events.
    return true;
  }

  return AddTypedBlock(content_data, process_state);
}

bool TypePropagatorAnalyzer::AnalyzeTypedDataArray(
    const TypedData& typed_data,
    ProcessState* process_state) {
  DCHECK(typed_data.IsArrayType());
  DCHECK(process_state != nullptr);

  ArrayTypePtr array_type;
  if (!typed_data.type()->CastTo(&array_type))
    return false;

  for (int i = 0; i < array_type->num_elements(); ++i) {
    TypedData element;
    if (!typed_data.GetArrayElement(i, &element))
      continue;  // Not an error.

    if (!AnalyzeTypedData(element, process_state))
      return false;
  }

  return true;
}

bool TypePropagatorAnalyzer::AddTypedBlock(const TypedData& typed_data,
                                           ProcessState* process_state) {
  ModuleLayerAccessor accessor(process_state);
  pe::PEFile::Signature signature;
  if (!typed_data.type()->repository()->GetModuleSignature(&signature))
    return false;
  ModuleId module_id = accessor.GetModuleId(signature);
  if (module_id == kNoModuleId)
    return false;

  return AddTypedBlockRecord(typed_data.GetRange(), L"", module_id,
                             typed_data.type()->type_id(), process_state);
}

}  // namespace refinery
