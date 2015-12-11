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

#include "syzygy/refinery/process_state/process_state_util.h"

namespace refinery {

Validator::ValidationResult VftablePtrValidator::Validate(
    ProcessState* process_state,
    ValidationReport* report) {
  DCHECK(process_state); DCHECK(report);

  // TODO(manzagop): implement.
  // Get the set of valid vftable ptrs.
  // Go through the typed block layer for validation.

  return VALIDATION_COMPLETE;
}

bool VftablePtrValidator::GetVFTableVAs(
    ProcessState* process_state,
    scoped_refptr<DiaSymbolProvider> dia_symbol_provider,
    base::hash_set<Address>* vftable_vas) {
  DCHECK(process_state); DCHECK(dia_symbol_provider.get()); DCHECK(vftable_vas);

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
    if (!dia_symbol_provider->GetVFTableRVAs(signature, &vftable_rvas))
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

}  // namespace refinery
