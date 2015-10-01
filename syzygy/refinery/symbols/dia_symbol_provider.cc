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

#include "base/environment.h"
#include "base/strings/stringprintf.h"
#include "base/strings/utf_string_conversions.h"
#include "syzygy/common/com_utils.h"
#include "syzygy/pe/find.h"

namespace refinery {

namespace {

// TODO(manzagop): this probably exists somewhere?
bool GetEnvVar(const char* name, base::string16* value) {
  DCHECK(name != NULL);
  DCHECK(value != NULL);
  value->clear();

  scoped_ptr<base::Environment> env(base::Environment::Create());
  if (env.get() == NULL) {
    LOG(ERROR) << "base::Environment::Create returned NULL.";
    return false;
  }

  // If this fails, the environment variable simply does not exist.
  std::string var;
  if (!env->GetVar(name, &var))
    return true;

  if (!base::UTF8ToUTF16(var.c_str(), var.size(), value)) {
    LOG(ERROR) << "base::UTF8ToUTF16(\"" << var << "\" failed.";
    return false;
  }

  return true;
}

bool GetPdbPath(const pe::PEFile::Signature& signature,
                base::FilePath* pdb_path) {
  DCHECK(pdb_path);

  // Get the module's path.
  base::string16 symbol_paths;
  GetEnvVar("_NT_SYMBOL_PATH", &symbol_paths);
  base::FilePath module_local_path;
  if (!pe::FindModuleBySignature(signature, symbol_paths, &module_local_path) ||
      module_local_path.empty()) {
    LOG(ERROR) << "Failed to find module (name, size, timestamp): "
               << signature.path << ", " << signature.module_size << ", "
               << signature.module_time_date_stamp;
    return false;
  }

  // Get the pdb's path.
  if (!pe::FindPdbForModule(module_local_path, symbol_paths, pdb_path) ||
      pdb_path->empty()) {
    LOG(ERROR) << "Failed to find pdb for module " << signature.path;
    return false;
  }

  return true;
}

}  // namespace

DiaSymbolProvider::DiaSymbolProvider() {
}

DiaSymbolProvider::~DiaSymbolProvider() {
}

bool DiaSymbolProvider::GetDiaSession(
    const pe::PEFile::Signature& signature,
    base::win::ScopedComPtr<IDiaSession>* session) {
  base::string16 cache_key;
  if (!EnsurePdbSessionCached(signature, &cache_key))
    return false;

  auto session_it = pdb_sessions_.find(cache_key);
  DCHECK(session_it != pdb_sessions_.end());
  *session = session_it->second;

  if (!session->get())
    return false;  // Negative cache entry.

  return true;
}

// TODO(manzagop): revise this function using the code from dia_util.h.
bool DiaSymbolProvider::EnsurePdbSessionCached(
    const pe::PEFile::Signature& signature,
    base::string16* cache_key) {
  DCHECK(cache_key != NULL);

  // Determine the cache key. Note that the cache key does not contain the
  // module's base address.
  base::SStringPrintf(cache_key, L"%ls:%d:%d:%d", signature.path,
                      signature.module_size, signature.module_checksum,
                      signature.module_time_date_stamp);
  auto session_it = pdb_sessions_.find(*cache_key);
  if (session_it != pdb_sessions_.end())
    return true;  // A session (or lack thereof) is cached.

  // The module is not in the cache. Attempt to create a dia session for the
  // module.

  // Create negative cache entries, which will be replaced on success.
  pdb_sources_[*cache_key] = base::win::ScopedComPtr<IDiaDataSource>();
  pdb_sessions_[*cache_key] = base::win::ScopedComPtr<IDiaSession>();

  base::FilePath pdb_path;
  if (!GetPdbPath(signature, &pdb_path))
    return false;

  // Get a source for the pdb.
  base::win::ScopedComPtr<IDiaDataSource> pdb_source;
  HRESULT hr = pdb_source.CreateInstance(CLSID_DiaSource);
  if (FAILED(hr)) {
    LOG(ERROR) << "Unable to create DIA source: " << common::LogHr(hr);
    return false;
  }
  hr = pdb_source->loadDataFromPdb(pdb_path.value().c_str());
  if (FAILED(hr)) {
    LOG(ERROR) << "Unable to load PDB: " << common::LogHr(hr);
    return false;
  }

  // Get the session.
  base::win::ScopedComPtr<IDiaSession> pdb_session;
  hr = pdb_source->openSession(pdb_session.Receive());
  if (FAILED(hr)) {
    LOG(ERROR) << "Unable to open session: " << common::LogHr(hr);
    return false;
  }

  // Cache source and session.
  pdb_sources_[*cache_key] = pdb_source;
  pdb_sessions_[*cache_key] = pdb_session;

  return true;
}

}  // namespace refinery
