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

#include "syzygy/refinery/symbols/dia_symbol_provider.h"

#include <string>

#include "base/strings/stringprintf.h"
#include "syzygy/common/com_utils.h"
#include "syzygy/pe/dia_util.h"
#include "syzygy/refinery/process_state/process_state.h"
#include "syzygy/refinery/process_state/process_state_util.h"
#include "syzygy/refinery/symbols/symbol_provider_util.h"

namespace refinery {

DiaSymbolProvider::DiaSymbolProvider() {
}

DiaSymbolProvider::~DiaSymbolProvider() {
}

bool DiaSymbolProvider::FindOrCreateDiaSession(
    const Address va,
    ProcessState* process_state,
    base::win::ScopedComPtr<IDiaSession>* session) {
  DCHECK(process_state != nullptr);
  DCHECK(session != nullptr);
  *session = nullptr;

  // Get the module's signature.
  ModuleLayerAccessor accessor(process_state);
  pe::PEFile::Signature signature;
  if (!accessor.GetModuleSignature(va, &signature))
    return false;

  // Retrieve the session.
  base::win::ScopedComPtr<IDiaSession> session_temp;
  if (!FindOrCreateDiaSession(signature, &session_temp))
    return false;

  // Set the load address (the same module might be loaded at multiple VAs).
  HRESULT hr = session_temp->put_loadAddress(signature.base_address.value());
  if (FAILED(hr)) {
    LOG(ERROR) << "Unable to set session's load address: " << common::LogHr(hr);
    return false;
  }

  *session = session_temp;
  return true;
}

// TODO(manzagop): revise this function using the code from dia_util.h.
bool DiaSymbolProvider::FindOrCreateDiaSession(
    const pe::PEFile::Signature& signature,
    base::win::ScopedComPtr<IDiaSession>* session) {
  DCHECK(session != nullptr);
  *session = nullptr;

  // Determine the cache key. Note that the cache key does not contain the
  // module's base address.
  base::string16 cache_key;
  base::SStringPrintf(&cache_key, L"%ls:%d:%d:%d",
                      base::FilePath(signature.path).BaseName().value().c_str(),
                      signature.module_size, signature.module_checksum,
                      signature.module_time_date_stamp);

  // Look for a pre-existing entry.
  auto session_it = pdb_sessions_.find(cache_key);
  if (session_it != pdb_sessions_.end()) {
    if (session_it->second == nullptr)
      return false;  // Negative cache entry.
    *session = session_it->second;
    return true;
  }

  // The module is not in the cache. Create negative cache entries, which will
  // be replaced on success.
  pdb_sources_[cache_key] = base::win::ScopedComPtr<IDiaDataSource>();
  pdb_sessions_[cache_key] = base::win::ScopedComPtr<IDiaSession>();

  // Attempt to create a dia session for the module.
  base::FilePath pdb_path;
  if (!GetPdbPath(signature, &pdb_path))
    return false;

  // Get a source for the pdb.
  base::win::ScopedComPtr<IDiaDataSource> pdb_source;
  if (!pe::CreateDiaSource(pdb_source.Receive()))
    return false;

  // Get the session.
  base::win::ScopedComPtr<IDiaSession> pdb_session;
  if (!pe::CreateDiaSession(pdb_path, pdb_source.get(), pdb_session.Receive()))
    return false;

  // Cache source and session.
  pdb_sources_[cache_key] = pdb_source;
  pdb_sessions_[cache_key] = pdb_session;

  *session = pdb_session;
  return true;
}

}  // namespace refinery
