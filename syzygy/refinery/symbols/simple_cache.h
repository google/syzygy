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

#ifndef SYZYGY_REFINERY_SYMBOLS_SIMPLE_CACHE_H_
#define SYZYGY_REFINERY_SYMBOLS_SIMPLE_CACHE_H_

#include "base/callback.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/containers/hash_tables.h"
#include "base/memory/ref_counted.h"
#include "base/strings/string16.h"

namespace refinery {

// A simple cache which uses negative entries in the form of null pointers.
template <typename EntryType>
class SimpleCache {
 public:
  typedef base::Callback<bool(scoped_refptr<EntryType>*)> LoadingCallback;

  SimpleCache() {}
  ~SimpleCache() {}

  // Retrieves a cache entry.
  // @param key the desired entry's cache key.
  // @param entry on success, returns the desired entry or nullptr to indicate a
  //     negative entry.
  // @returns true if the cache contains an entry for @p key, false otherwise.
  bool Get(const base::string16& key, scoped_refptr<EntryType>* entry) const;

  // Retrieves a cache entry, loading it if required.
  // @param key the desired entry's cache key.
  // @param load_cb a LoadingCallback for use if the entry is not in cache.
  // @param entry on success, returns the desired entry or nullptr to indicate a
  //     failure to load and the insertion of a negative entry.
  void GetOrLoad(const base::string16& key,
                 const LoadingCallback& load_cb,
                 scoped_refptr<EntryType>* entry);

  // Stores a cache entry.
  // @note replaces any previous entry at @p key.
  // @param key the key to store at.
  // @param entry the entry to store at @p key.
  void Store(const base::string16& key, scoped_refptr<EntryType> entry);

 private:
  std::unordered_map<base::string16, scoped_refptr<EntryType>> entries_;

  DISALLOW_COPY_AND_ASSIGN(SimpleCache);
};

template <typename EntryType>
bool SimpleCache<EntryType>::Get(const base::string16& key,
                                 scoped_refptr<EntryType>* entry) const {
  DCHECK(entry);
  *entry = nullptr;

  auto it = entries_.find(key);
  if (it == entries_.end())
    return false;  // Not present in the cache.

  *entry = it->second;
  return true;
}

template <typename EntryType>
void SimpleCache<EntryType>::GetOrLoad(const base::string16& key,
                                       const LoadingCallback& load_cb,
                                       scoped_refptr<EntryType>* entry) {
  DCHECK(entry);
  *entry = nullptr;

  if (Get(key, entry))
    return;  // There's a pre-existing entry.

  // No entry in the cache. Create a negative cache entry, which will be
  // replaced on success.
  Store(key, *entry);

  if (!load_cb.Run(entry))
    return;  // Load failed. Keep the negative entry.

  Store(key, *entry);
}

template <typename EntryType>
void SimpleCache<EntryType>::Store(const base::string16& key,
                                   scoped_refptr<EntryType> entry) {
  entries_[key] = entry;
}

}  // namespace refinery

#endif  // SYZYGY_REFINERY_SYMBOLS_SIMPLE_CACHE_H_
