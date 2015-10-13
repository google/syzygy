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

#ifndef SYZYGY_REFINERY_SYMBOLS_DIA_SYMBOL_PROVIDER_H_
#define SYZYGY_REFINERY_SYMBOLS_DIA_SYMBOL_PROVIDER_H_

#include <dia2.h>

#include "base/macros.h"
#include "base/containers/hash_tables.h"
#include "base/memory/ref_counted.h"
#include "base/strings/string16.h"
#include "base/win/scoped_comptr.h"
#include "syzygy/pe/pe_file.h"
#include "syzygy/refinery/core/address.h"

namespace refinery {

// Fwd.
class ProcessState;

// The DiaSymbolProvider provides symbol information via the DIA interfaces.
class DiaSymbolProvider : public base::RefCounted<DiaSymbolProvider> {
 public:
  DiaSymbolProvider();
  ~DiaSymbolProvider();

  // Retrieves or creates an IDiaSession for the module within @p process_state
  // corresponding to @p va.
  // @note on success, the session's load address is set.
  // @param va virtual address for which to get a session.
  // @param process_state the process state within which to interpret @p va.
  // @param session on success, returns a session for the module. On failure,
  //   contains nullptr.
  // @returns true on success, false on failure.
  bool FindOrCreateDiaSession(const Address va,
                              ProcessState* process_state,
                              base::win::ScopedComPtr<IDiaSession>* session);

  // Retrieves or creates an IDiaSession for the module corresponding to @p
  // signature.
  // @note on success, the session's load address is not set.
  // @param signature the signature of the module for which to get a session.
  // @param session on success, returns a session for the module. On failure,
  //   contains nullptr.
  // @returns true on success, false on failure.
  bool FindOrCreateDiaSession(const pe::PEFile::Signature& signature,
                              base::win::ScopedComPtr<IDiaSession>* session);

 private:
  // Caching for dia pdb file sources and sessions (matching entries). The cache
  // key is "<basename>:<size>:<checksum>:<timestamp>". The cache may contain
  // negative entries (indicating a failed attempt at creating a session) in the
  // form of null pointers.
  base::hash_map<base::string16, base::win::ScopedComPtr<IDiaDataSource>>
      pdb_sources_;
  base::hash_map<base::string16, base::win::ScopedComPtr<IDiaSession>>
      pdb_sessions_;

  DISALLOW_COPY_AND_ASSIGN(DiaSymbolProvider);
};

}  // namespace refinery

#endif  // SYZYGY_REFINERY_SYMBOLS_DIA_SYMBOL_PROVIDER_H_
