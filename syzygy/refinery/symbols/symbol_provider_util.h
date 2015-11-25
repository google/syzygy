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
//
// Declares utilities for symbol providers.

#ifndef SYZYGY_REFINERY_SYMBOLS_SYMBOL_PROVIDER_UTIL_H_
#define SYZYGY_REFINERY_SYMBOLS_SYMBOL_PROVIDER_UTIL_H_

#include "syzygy/pe/pe_file.h"
#include "syzygy/refinery/core/address.h"

namespace refinery {

// Fwd.
class ProcessState;

// Retrieves a pdb path corresponding to a module signature.
// @param signature the signature of the module for which to get a pdb path.
// @param on success, the path to a pdb file for the module signature.
// @returns true on success, false on failure.
bool GetPdbPath(const pe::PEFile::Signature& signature,
                base::FilePath* pdb_path);

}  // namespace refinery

#endif  // SYZYGY_REFINERY_SYMBOLS_SYMBOL_PROVIDER_UTIL_H_
