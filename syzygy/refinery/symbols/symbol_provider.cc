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

#include "syzygy/refinery/symbols/symbol_provider.h"

#include "base/strings/stringprintf.h"
#include "syzygy/refinery/process_state/process_state.h"
#include "syzygy/refinery/symbols/symbol_provider_util.h"
#include "syzygy/refinery/types/pdb_crawler.h"

namespace refinery {

SymbolProvider::SymbolProvider() {
}

SymbolProvider::~SymbolProvider() {
}

bool SymbolProvider::FindOrCreateTypeRepository(
    const Address va,
    ProcessState* process_state,
    scoped_refptr<TypeRepository>* type_repo) {
  DCHECK(process_state);
  DCHECK(type_repo);
  *type_repo = nullptr;

  // Get the module's signature.
  pe::PEFile::Signature signature;
  if (!GetModuleSignature(va, process_state, &signature))
    return false;

  // Retrieve the type repository.
  return FindOrCreateTypeRepository(signature, type_repo);
}

bool SymbolProvider::FindOrCreateTypeRepository(
    const pe::PEFile::Signature& signature,
    scoped_refptr<TypeRepository>* type_repo) {
  DCHECK(type_repo);
  *type_repo = nullptr;

  // Determine the cache key. Note that the cache key does not contain the
  // module's base address.
  base::string16 cache_key;
  base::SStringPrintf(&cache_key, L"%ls:%d:%d:%d",
                      base::FilePath(signature.path).BaseName().value().c_str(),
                      signature.module_size, signature.module_checksum,
                      signature.module_time_date_stamp);

  // Look for a pre-existing entry.
  auto repo_it = type_repos_.find(cache_key);
  if (repo_it != type_repos_.end()) {
    *type_repo = repo_it->second;
    return true;
  }

  // The module is not in the cache. Create a negative cache entry, which will
  // be replaced on success.
  type_repos_[cache_key] = scoped_refptr<TypeRepository>();

  // Create a type repository.
  base::FilePath pdb_path;
  if (!GetPdbPath(signature, &pdb_path))
    return false;

  scoped_refptr<TypeRepository> repository = new TypeRepository();
  PdbCrawler crawler;
  if (!crawler.InitializeForFile(pdb_path) ||
      !crawler.GetTypes(repository.get())) {
    return false;
  }

  // Cache the type repository.
  type_repos_[cache_key] = repository;

  *type_repo = repository;
  return true;
}

}  // namespace refinery
