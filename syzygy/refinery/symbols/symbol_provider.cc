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

#include "base/bind.h"
#include "base/strings/stringprintf.h"
#include "syzygy/refinery/symbols/symbol_provider_util.h"
#include "syzygy/refinery/types/pdb_crawler.h"

namespace refinery {

SymbolProvider::SymbolProvider() {
}

SymbolProvider::~SymbolProvider() {
}

bool SymbolProvider::FindOrCreateTypeRepository(
    const pe::PEFile::Signature& signature,
    scoped_refptr<TypeRepository>* type_repo) {
  DCHECK(type_repo);
  *type_repo = nullptr;

  base::string16 cache_key;
  GetCacheKey(signature, &cache_key);

  SimpleCache<TypeRepository>::LoadingCallback load_cb = base::Bind(
      &SymbolProvider::CreateTypeRepository, base::Unretained(this), signature);

  type_repos_.GetOrLoad(cache_key, load_cb, type_repo);
  return type_repo->get() != nullptr;
}

bool SymbolProvider::FindOrCreateTypeNameIndex(
    const pe::PEFile::Signature& signature,
    scoped_refptr<TypeNameIndex>* typename_index) {
  DCHECK(typename_index);
  *typename_index = nullptr;

  base::string16 cache_key;
  GetCacheKey(signature, &cache_key);

  SimpleCache<TypeNameIndex>::LoadingCallback load_cb = base::Bind(
      &SymbolProvider::CreateTypeNameIndex, base::Unretained(this), signature);

  typename_indices_.GetOrLoad(cache_key, load_cb, typename_index);
  return typename_index->get() != nullptr;
}

bool SymbolProvider::GetVFTableRVAs(
    const pe::PEFile::Signature& signature,
    base::hash_set<RelativeAddress>* vftable_rvas) {
  DCHECK(vftable_rvas);
  vftable_rvas->clear();

  base::FilePath pdb_path;
  if (!GetPdbPath(signature, &pdb_path))
    return false;

  PdbCrawler crawler;
  if (!crawler.InitializeForFile(pdb_path))
    return false;

  return crawler.GetVFTableRVAs(vftable_rvas);
}

void SymbolProvider::GetCacheKey(const pe::PEFile::Signature& signature,
                                 base::string16* cache_key) {
  DCHECK(cache_key);
  // Note that the cache key does not contain the module's base address.
  base::SStringPrintf(cache_key, L"%ls:%d:%d:%d",
                      base::FilePath(signature.path).BaseName().value().c_str(),
                      signature.module_size, signature.module_checksum,
                      signature.module_time_date_stamp);
}

bool SymbolProvider::CreateTypeRepository(
    const pe::PEFile::Signature& signature,
    scoped_refptr<TypeRepository>* type_repo) {
  DCHECK(type_repo);
  *type_repo = nullptr;

  base::FilePath pdb_path;
  if (!GetPdbPath(signature, &pdb_path))
    return false;

  scoped_refptr<TypeRepository> repository = new TypeRepository();
  PdbCrawler crawler;
  if (!crawler.InitializeForFile(pdb_path) ||
      !crawler.GetTypes(repository.get())) {
    return false;
  }

  *type_repo = repository;
  return true;
}

bool SymbolProvider::CreateTypeNameIndex(const pe::PEFile::Signature& signature,
                                         scoped_refptr<TypeNameIndex>* index) {
  DCHECK(index);

  scoped_refptr<TypeRepository> repository;
  if (!FindOrCreateTypeRepository(signature, &repository))
    return false;

  *index = new TypeNameIndex(repository);
  return true;
}

}  // namespace refinery
