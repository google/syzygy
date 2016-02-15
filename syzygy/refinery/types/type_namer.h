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
#include "base/strings/string16.h"
#include "syzygy/refinery/types/type.h"

namespace refinery {

bool GetSymBaseTypeName(IDiaSymbol* symbol, base::string16* type_name);

// Computes type names for types whose name depends on other types.
// @note array names do not depend on the index type.
class TypeNamer {
 public:
  static bool GetName(ConstTypePtr type, base::string16* type_name);
  static bool GetDecoratedName(ConstTypePtr type, base::string16* type_name);

 private:
  static bool GetName(ConstTypePtr type,
                      bool decorated,
                      base::string16* type_name);

  static bool GetPointerName(ConstPointerTypePtr ptr,
                             bool decorated,
                             base::string16* type_name);
  static bool GetArrayName(ConstArrayTypePtr array,
                           bool decorated,
                           base::string16* type_name);
  static bool GetFunctionName(ConstFunctionTypePtr function,
                              bool decorated,
                              base::string16* type_name);
};

class DiaTypeNamer {
 public:
  static bool GetTypeName(IDiaSymbol* type, base::string16* type_name);

 private:
  static bool GetPointerName(IDiaSymbol* type, base::string16* type_name);
  static bool GetArrayName(IDiaSymbol* type, base::string16* type_name);
  static bool GetFunctionName(IDiaSymbol* type, base::string16* type_name);
};

}  // namespace refinery

#endif  // SYZYGY_REFINERY_TYPES_TYPE_NAMER_H_
