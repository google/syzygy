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

#include "syzygy/refinery/validators/vftable_ptr_validator.h"

#include <string>

#include "base/strings/stringprintf.h"
#include "syzygy/refinery/process_state/process_state_util.h"
#include "syzygy/refinery/process_state/refinery.pb.h"
#include "syzygy/refinery/types/type.h"

namespace refinery {

namespace {

TypePtr RecoverType(ModuleLayerAccessor* accessor,
                    SymbolProvider* provider,
                    const TypedBlock& typedblock) {
  DCHECK(accessor);
  DCHECK(provider);

  pe::PEFile::Signature signature;
  if (!accessor->GetModuleSignature(typedblock.module_id(), &signature))
    return nullptr;

  scoped_refptr<TypeRepository> type_repository;
  if (!provider->FindOrCreateTypeRepository(signature, &type_repository))
    return nullptr;

  return type_repository->GetType(typedblock.type_id());
}

void AddViolation(const TypedData& typed_data, ValidationReport* report) {
  DCHECK(typed_data.IsValid());
  DCHECK(report);

  Violation* violation = report->add_error();
  violation->set_type(VIOLATION_VFPTR);

  std::string description = base::StringPrintf(
      "Type %ls at address %08X has an incorrect vfptr.",
      typed_data.type()->GetName().c_str(), typed_data.GetRange().start());
  violation->set_description(description);
}

}  // namespace

VftablePtrValidator::VftablePtrValidator(
    scoped_refptr<SymbolProvider> symbol_provider)
    : symbol_provider_(symbol_provider) {
  DCHECK(symbol_provider);
}

Validator::ValidationResult VftablePtrValidator::Validate(
    ProcessState* process_state,
    ValidationReport* report) {
  DCHECK(process_state);
  DCHECK(report);

  // Analyzers that build content for the bytes and typed block layer must have
  // already run. We use the existence of a bytes layer and a typed block layer
  // as a proxy for this.
  BytesLayerPtr bytes_layer;
  if (!process_state->FindLayer(&bytes_layer)) {
    LOG(ERROR) << "Missing bytes layer.";
    return VALIDATION_ERROR;
  }
  TypedBlockLayerPtr typed_layer;
  if (!process_state->FindLayer(&typed_layer)) {
    LOG(ERROR) << "Missing typed block layer.";
    return VALIDATION_ERROR;
  }

  // Get the set of valid vftable ptrs.
  // Go through the typed block layer for validation.
  base::hash_set<Address> vftable_vas;
  if (!GetVFTableVAs(process_state, symbol_provider_.get(), &vftable_vas)) {
    LOG(ERROR) << "Failed to get vfptr VAs.";
    return VALIDATION_ERROR;
  }

  // Validate each typed block.
  ModuleLayerAccessor accessor(process_state);
  for (TypedBlockRecordPtr rec : *typed_layer) {
    TypePtr type = RecoverType(&accessor, symbol_provider_.get(), rec->data());
    if (type == nullptr)
      return VALIDATION_ERROR;

    TypedData typed_data(process_state, type, rec->range().start());
    ValidateTypedData(typed_data, vftable_vas, report);
  }

  return VALIDATION_COMPLETE;
}

bool VftablePtrValidator::GetVFTableVAs(
    ProcessState* process_state,
    SymbolProvider* symbol_provider,
    base::hash_set<RelativeAddress>* vftable_vas) {
  DCHECK(process_state);
  DCHECK(symbol_provider);
  DCHECK(vftable_vas);

  ModuleLayerPtr layer;
  if (!process_state->FindLayer(&layer))
    return false;  // We expect to find a module layer (though possibly empty).
  ModuleLayerAccessor accessor(process_state);

  // Note: no optimisation for multiples instances of the same module.
  for (ModuleRecordPtr record : *layer) {
    pe::PEFile::Signature signature;
    if (!accessor.GetModuleSignature(record->data().module_id(), &signature))
      return false;

    base::hash_set<Address> vftable_rvas;
    if (!symbol_provider->GetVFTableRVAs(signature, &vftable_rvas))
      return false;

    Address module_base = record->range().start();
    for (Address rva : vftable_rvas) {
      base::CheckedNumeric<Address> virtual_address = module_base;
      virtual_address += rva;
      if (!virtual_address.IsValid())
        return false;

      vftable_vas->insert(virtual_address.ValueOrDie());
    }
  }

  return true;
}

bool VftablePtrValidator::ValidateTypedData(
    const TypedData& typed_data,
    const base::hash_set<Address>& vftable_vas,
    ValidationReport* report) {
  DCHECK(typed_data.IsValid());
  DCHECK(report);

  // Restrict to UDTs.
  if (!typed_data.IsUserDefinedType())
    return false;

  size_t field_cnt;
  if (!typed_data.GetFieldCount(&field_cnt))
    return false;

  for (size_t i = 0; i < field_cnt; ++i) {
    FieldPtr field;
    if (!typed_data.GetField(i, &field))
      return false;
    TypedData field_data;
    if (!typed_data.GetField(i, &field_data))
      return false;

    switch (field->kind()) {
      case UserDefinedType::Field::VFPTR_KIND: {
        Address vfptr;
        if (field_data.GetPointerValue(&vfptr) &&
            vftable_vas.find(vfptr) == vftable_vas.end()) {
          // The value of the vfptr was retrieved but it's not in the allowed
          // set. Add a violation.
          AddViolation(typed_data, report);
        }
        break;
      }
      case UserDefinedType::Field::BASE_CLASS_KIND:
      case UserDefinedType::Field::MEMBER_KIND: {
        // Recurse on "nested" UDTs (base classes and members).
        if (!ValidateTypedData(field_data, vftable_vas, report))
          return false;
        break;
      }
    }
  }

  return true;
}

}  // namespace refinery
