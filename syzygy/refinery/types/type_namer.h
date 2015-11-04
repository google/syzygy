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

#ifndef SYZYGY_REFINERY_TYPES_TYPE_NAMER_H_
#define SYZYGY_REFINERY_TYPES_TYPE_NAMER_H_

#include <dia2.h>

#include "base/macros.h"
#include "syzygy/refinery/types/type.h"

namespace refinery {

bool GetSymBaseTypeName(IDiaSymbol* symbol, base::string16* type_name);

// Handles naming for types whose name depends on other types' names.
class TypeNamer {
 public:
  // @param set_decorated_name whether the namer should handle decorated names.
  // @note Decorated name handling should be disabled when accessing type
  //    information through DIA as it does not expose decorated names.
  explicit TypeNamer(bool set_decorated_name);
  ~TypeNamer();

  // Assign names for types whose name depends on the name of other types.
  // @returns true on success, false on failure.
  bool EnsureTypeName(TypePtr type) const;

 private:
  bool AssignPointerName(PointerTypePtr ptr) const;
  bool AssignArrayName(ArrayTypePtr array) const;
  bool AssignFunctionName(FunctionTypePtr function) const;

  bool set_decorated_name_;

  DISALLOW_COPY_AND_ASSIGN(TypeNamer);
};

}  // namespace refinery

#endif  // SYZYGY_REFINERY_TYPES_TYPE_NAMER_H_
