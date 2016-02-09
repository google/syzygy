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

#ifndef SYZYGY_REFINERY_VALIDATORS_VFTABLE_PTR_VALIDATOR_H_
#define SYZYGY_REFINERY_VALIDATORS_VFTABLE_PTR_VALIDATOR_H_

#include "base/macros.h"
#include "base/containers/hash_tables.h"
#include "base/memory/ref_counted.h"
#include "syzygy/refinery/core/address.h"
#include "syzygy/refinery/symbols/symbol_provider.h"
#include "syzygy/refinery/types/typed_data.h"
#include "syzygy/refinery/validators/validator.h"

namespace refinery {

// A validator for vftable ptr values. This simple implementation validates
// that an object's vftable ptr is within the valid set for the process.
// TODO(manzagop): tighter checking of a vftable ptr's possible values.
class VftablePtrValidator : public Validator {
 public:
  // TODO(manzagop): Is this a validator? Take in a symbol provider?
  explicit VftablePtrValidator(scoped_refptr<SymbolProvider> symbol_provider);

  ValidationResult Validate(ProcessState* process_state,
                            ValidationReport* report) override;

 protected:
  // Retrieves the set of vftable virtual addresses for @p process_state.
  // @param process_state the process_state.
  // @param vftable_vas on success, contains zero or more addresses.
  // @returns true on success, false on failure.
  static bool GetVFTableVAs(
      ProcessState* process_state,
      SymbolProvider* symbol_provider,
      base::hash_set<Address>* vftable_vas);

 private:
  bool ValidateTypedData(const TypedData& typed_data,
                         const base::hash_set<RelativeAddress>& vftable_vas,
                         ValidationReport* report);

  scoped_refptr<SymbolProvider> symbol_provider_;

  DISALLOW_COPY_AND_ASSIGN(VftablePtrValidator);
};

}  // namespace refinery

#endif  // SYZYGY_REFINERY_VALIDATORS_VFTABLE_PTR_VALIDATOR_H_
