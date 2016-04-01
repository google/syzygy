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

// The DiaSymbolProvider provides symbol information via the DIA interfaces.
// @note It is *not* safe to interleave access to a session in the context of
//     different process states, as the session's load address may be different.
// @note use of virtual is to allow mocking.
// TODO(manzagop): this class should share an interface with SymbolProvider, for
// providing type repositories. This would enable replacing one implementation
// for the other and possibly sharing some implementation.
class DiaSymbolProvider : public base::RefCounted<DiaSymbolProvider> {
 public:
  DiaSymbolProvider();
  virtual ~DiaSymbolProvider();

  // Retrieves or creates an IDiaSession for the module corresponding to @p
  // signature.
  // @note on success, the session's load address is not set.
  // @param signature the signature of the module for which to get a session.
  // @param session on success, returns a session for the module. On failure,
  //   contains nullptr.
  // @returns true on success, false on failure.
  virtual bool FindOrCreateDiaSession(
      const pe::PEFile::Signature& signature,
      base::win::ScopedComPtr<IDiaSession>* session);

  // Retrieves the relative virtual addresses of all virtual function tables in
  // the module identified by @p signature.
  // @param signature the signature of the module.
  // @param vftable_rvas on success contains zero or more relative addresses.
  // @returns true on success, false on failure.
  virtual bool GetVFTableRVAs(const pe::PEFile::Signature& signature,
                              base::hash_set<RelativeAddress>* vftable_rvas);

 private:
  // TODO(manzagop): this function is duplicated in SymbolProvider. It should
  // likely be extracted to a cross-platform Signature class.
  static void GetCacheKey(const pe::PEFile::Signature& signature,
                          base::string16* cache_key);

  bool GetOrLoad(const pe::PEFile::Signature& signature,
                 base::win::ScopedComPtr<IDiaDataSource>* source,
                 base::win::ScopedComPtr<IDiaSession>* session);

  // Caching for dia pdb file sources and sessions (matching entries). The cache
  // key is "<basename>:<size>:<checksum>:<timestamp>". The cache may contain
  // negative entries (indicating a failed attempt at creating a session) in the
  // form of null pointers.
  // The caches must be consistent: the presence of a valid source implies the
  // presence of a valid session, and vice versa.
  std::unordered_map<base::string16, base::win::ScopedComPtr<IDiaDataSource>>
      pdb_sources_;
  std::unordered_map<base::string16, base::win::ScopedComPtr<IDiaSession>>
      pdb_sessions_;

  DISALLOW_COPY_AND_ASSIGN(DiaSymbolProvider);
};

}  // namespace refinery

#endif  // SYZYGY_REFINERY_SYMBOLS_DIA_SYMBOL_PROVIDER_H_
