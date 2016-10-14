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

#include "syzygy/agent/asan/registry_cache.h"

#include <map>
#include <memory>

#include "base/base_paths.h"
#include "base/file_version_info_win.h"
#include "base/path_service.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/stringprintf.h"
#include "syzygy/pe/metadata.h"

namespace agent {
namespace asan {

const size_t RegistryCache::kDefaultMaxDaysInRegistry = 360;
const size_t RegistryCache::kDefaultMaxEntriesPerVersion = 100;
const size_t RegistryCache::kDefaultMaxModules = 50;
const size_t RegistryCache::kDefaultMaxVersions = 5;
const HKEY RegistryCache::kRegistryRootKey = HKEY_CURRENT_USER;
const wchar_t RegistryCache::kRegistryBaseKey[] =
    L"Software\\Google\\Syzygy\\RegistryCache\\";

RegistryCache::RegistryCache(const wchar_t* registry_name)
    : max_days_in_registry_(kDefaultMaxDaysInRegistry),
      max_entries_per_version_(kDefaultMaxEntriesPerVersion),
      max_modules_(kDefaultMaxModules),
      max_versions_(kDefaultMaxVersions),
      registry_cache_key_(kRegistryBaseKey),
      is_init_(false) {
  registry_cache_key_.append(registry_name);
}

RegistryCache::RegistryCache(const wchar_t* registry_name,
                             size_t max_days_in_registry,
                             size_t max_entries_per_version,
                             size_t max_modules,
                             size_t max_versions)
    : max_days_in_registry_(max_days_in_registry),
      max_entries_per_version_(max_entries_per_version),
      max_modules_(max_modules),
      max_versions_(max_versions),
      registry_cache_key_(kRegistryBaseKey),
      is_init_(false) {
  registry_cache_key_.append(registry_name);
}

// static
bool RegistryCache::RegistryAvailable() {
  base::win::RegKey test_key(kRegistryRootKey, L"SYSTEM", KEY_ALL_ACCESS);
  if (!test_key.Valid())
    return false;
  test_key.Close();
  return true;
}

bool RegistryCache::Init() {
  DCHECK(RegistryAvailable());

  // Always start by cleaning up the values, to limit the size of entries in
  // the registry.
  CleanUp();
  // We can fail if we are not able to initialize the module information.
  is_init_ = InitModuleInfo();
  if (!is_init_)
    return false;
  LoadEntries();
  return true;
}

void RegistryCache::AddOrUpdateStackId(StackId stack_id) {
  DCHECK(is_init_);

  base::win::RegKey module_key(kRegistryRootKey, module_key_name_.c_str(),
      KEY_ALL_ACCESS);
  for (RegValueIter iter(kRegistryRootKey, module_key_name_.c_str());
    iter.Valid(); ++iter) {
    DCHECK_EQ(sizeof(StackId), iter.ValueSize());
    const StackId* ptr_value = reinterpret_cast<const StackId*>(iter.Value());
    // We don't break out of the loop, just in case there are redundant values
    // (shouldn't normally occur).
    if (*ptr_value == stack_id)
      module_key.DeleteValue(iter.Name());
  }
  std::wstring name =
      base::Int64ToString16(base::Time::Now().ToInternalValue());
  module_key.WriteValue(name.c_str(), &stack_id, sizeof(stack_id), REG_BINARY);
  entries_.insert(stack_id);
}

bool RegistryCache::DoesIdExist(
    common::StackCapture::StackId allocation_stack_id) const {
  DCHECK(is_init_);

  return entries_.find(allocation_stack_id) != entries_.end();
}

bool RegistryCache::RemoveStackId(
    common::StackCapture::StackId allocation_stack_id) {
  DCHECK(is_init_);

  return entries_.erase(allocation_stack_id) != 0;
}

// static
void RegistryCache::DeleteRegistryTree(const wchar_t* registry_name) {
  base::win::RegKey base_key(
      kRegistryRootKey, kRegistryBaseKey, KEY_ALL_ACCESS);
  base_key.DeleteKey(registry_name);
}

bool RegistryCache::InitModuleInfo() {
  base::FilePath file_path;
  if (PathService::Get(base::FILE_MODULE, &file_path)) {
    module_name_ = file_path.BaseName().value();
  } else {
    LOG(ERROR) << "Cannot get the module name.";
    return false;
  }

  if (module_name_.empty()) {
    LOG(ERROR) << "Module name is empty.";
    return false;
  }

  // Get the module version. We start by grabbing the product version from the
  // file version information.
  module_version_.clear();
  std::unique_ptr<FileVersionInfo> version_info(
      FileVersionInfo::CreateFileVersionInfo(file_path));
  if (version_info)
    module_version_ = version_info->product_version();
  if (module_version_.empty()) {
    // If that fails, we try grabbing the version from the PE signature.
#ifndef _WIN64
    pe::PEFile pe_file;
    pe::PEFile::Signature signature;
#else
    pe::PEFile64 pe_file;
    pe::PEFile64::Signature signature;
#endif
    if (pe_file.Init(file_path)) {
      pe_file.GetSignature(&signature);
      module_version_ = base::StringPrintf(
          L"%08X%x", signature.module_time_date_stamp, signature.module_size);
    } else {
      // If all fails, we bail.
      LOG(ERROR) << "Cannot get the module version.";
      return false;
    }
  }
  module_key_name_ = registry_cache_key_;
  module_key_name_.append(1, L'\\').append(module_name_);
  module_key_name_.append(1, L'\\').append(module_version_);

  return true;
}

void RegistryCache::CleanUp() {
  // Cleanup each top-level key (ie. module level).
  std::wstring key_name;
  base::win::RegKey base_key(kRegistryRootKey, registry_cache_key_.c_str(),
                             KEY_ALL_ACCESS);
  base::Time newest_value;
  std::multimap<base::Time, std::wstring> values;
  for (RegKeyIter iter(kRegistryRootKey, registry_cache_key_.c_str());
       iter.Valid(); ++iter) {
    key_name = registry_cache_key_;
    key_name.append(1, L'\\').append(iter.Name());
    CleanUpModule(key_name, &newest_value);
    // Delete key if empty, otherwise memorize it for possible deletion later.
    RegKeyIter iter2(kRegistryRootKey, key_name.c_str());
    if (iter2.SubkeyCount() <= 0) {
      base_key.DeleteKey(iter.Name());
    } else {
      values.insert(std::make_pair(newest_value, iter.Name()));
    }
  }

  // Delete oldest entries until we satisfy the maximum number of versions in
  // the module.
  while (values.size() > max_modules_) {
    base_key.DeleteKey(values.begin()->second.c_str());
    values.erase(values.begin());
  }
}

void RegistryCache::CleanUpModule(const std::wstring& base_key_name,
                                  base::Time* newest) {
  std::wstring key_name;
  base::win::RegKey key, base_key;
  base::Time newest_value;
  std::multimap<base::Time, std::wstring> values;

  base_key.Open(kRegistryRootKey, base_key_name.c_str(), KEY_ALL_ACCESS);
  // Go through each key (ie. version level) and cleanup the values.
  RegKeyIter iter(kRegistryRootKey, base_key_name.c_str());
  for (; iter.Valid(); ++iter) {
    key_name = base_key_name;
    key_name.append(1, L'\\').append(iter.Name());
    key.Open(kRegistryRootKey, key_name.c_str(), KEY_ALL_ACCESS);
    CleanUpVersion(&key, &newest_value);
    // Delete key if empty, otherwise memorize it for possible deletion later.
    if (key.GetValueCount() == 0) {
      base_key.DeleteKey(iter.Name());
    } else {
      values.insert(std::make_pair(newest_value, iter.Name()));
    }
    key.Close();
  }

  // Delete oldest entries until we satisfy the maximum number of versions in
  // the module.
  while (values.size() > max_versions_) {
    base_key.DeleteKey(values.begin()->second.c_str());
    values.erase(values.begin());
  }

  // Set |newest| to the timestamp of the newest version of the current module.
  if (newest != nullptr) {
    if (!values.empty()) {
      *newest = values.rbegin()->first;
    } else {
      *newest = base::Time::UnixEpoch();
    }
  }
}

void RegistryCache::CleanUpVersion(base::win::RegKey* base_key,
                                   base::Time* newest) {
  DCHECK_NE(static_cast<base::win::RegKey*>(nullptr), base_key);

  std::multimap<base::Time, std::wstring> values;

  // Iterate over the values, get the time (corresponds to the name) and store
  // in a map for potential deletion.
  for (RegValueIter iter(base_key->Handle(), L""); iter.Valid(); ++iter) {
    int64_t TimeInternalValue;
    // If the time is not valid or if the value size is wrong, set its time to
    // a really old one to force its deletion.
    if (base::StringToInt64(iter.Name(), &TimeInternalValue) &&
        iter.ValueSize() == sizeof(StackId)) {
      values.insert(std::make_pair(
          base::Time::FromInternalValue(TimeInternalValue), iter.Name()));
    } else {
      values.insert(std::make_pair(base::Time::UnixEpoch(), iter.Name()));
    }
  }

  size_t nb_remaining_entries = max_entries_per_version_;
  // Iterate over the map and, for each entry, verify if it needs to be purged.
  // An entry is kept if its age is smaller than |kMaxDaysInRegistry| and if we
  // have not reached |kMaxEntriesPerVersion| entries. Since the entries are
  // sorted by age, we ensure that the kept entries are always the most recent.
  for (auto iter(values.rbegin()); iter != values.rend(); ++iter) {
    if (nb_remaining_entries > 0) {
      base::TimeDelta delta(base::Time::Now() - (iter->first));
      if (delta.InDays() < max_days_in_registry_) {
        nb_remaining_entries--;
        continue;
      }
      // Once we find an entry that's too old, delete all the following as well.
      nb_remaining_entries = 0;
    }
    base_key->DeleteValue(iter->second.c_str());
  }

  // Set |newest| to the timestamp of the newest entry of the current version.
  if (newest != nullptr) {
    if (!values.empty()) {
      *newest = values.rbegin()->first;
    } else {
      *newest = base::Time::UnixEpoch();
    }
  }
}

void RegistryCache::LoadEntries() {
  // Load the entries from the registry into the container.
  for (RegValueIter iter(kRegistryRootKey, module_key_name_.c_str());
       iter.Valid(); ++iter) {
    DCHECK_EQ(sizeof(StackId), iter.ValueSize());
    const StackId* ptr_value = reinterpret_cast<const StackId*>(iter.Value());
    entries_.insert(*ptr_value);
  }
}

}  // namespace asan
}  // namespace agent
