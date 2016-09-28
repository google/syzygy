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
// This class allows us to save, in the Windows registry, the relative IDs of
// allocation stack traces for the current module & version. Module refers to
// the filename of the module containing the code (usually an executable or a
// DLL). The version is determined by various methods (see implementation of
// InitModuleInfo). Note that there is no standard naming convention for the
// version as it's used as is.
//
// Values are stored in a base key that depends on the name provided to the
// constructor. Each module gets its own registry key under the base key and
// that key's name is the same as the module base name. Inside each module key
// is a second level of keys, corresponding to the versions (same name as the
// version). An example of the key hierarchy is presented in the following
// diagram:
//
// Base key +---> chrome.exe  +---> 39.0.2171.95
//          |                 +---> 39.0.2171.99
//          |
//          +---> program.dll +---> Version 1
//          |
//          +---> program.exe +---> 1
//                            +---> 2
//                            +---> 3
//
// Finally, inside each version key are the entries. Each entry corresponds to
// an allocation stack trace. The name of the entry corresponds to its timestamp
// (return value of ToInternalValue) and its value corresponds to the stack ID.
//
// At every initialization, the entries of all modules/versions are purged
// (regardless of the current module/version). This is done by removing all
// entries older than |kMaxDaysInRegistry| as well as limiting the total number
// of entries inside each version to |kMaxEntriesPerVersion| and by deleting
// empty module and version keys.

#ifndef SYZYGY_AGENT_ASAN_REGISTRY_CACHE_H_
#define SYZYGY_AGENT_ASAN_REGISTRY_CACHE_H_

#include <unordered_set>

#include "base/macros.h"
#include "base/files/file_path.h"
#include "base/strings/string_number_conversions.h"
#include "base/time/time.h"
#include "base/win/registry.h"
#include "syzygy/agent/asan/heap_checker.h"
#include "syzygy/agent/common/stack_capture.h"

namespace agent {
namespace asan {

class RegistryCache {
 public:
  // Default value for |max_days_in_registry_|.
  static const size_t kDefaultMaxDaysInRegistry;

  // Default value for |max_entries_per_version_|.
  static const size_t kDefaultMaxEntriesPerVersion;

  // Default value for |max_modules_|.
  static const size_t kDefaultMaxModules;

  // Default value for |max_versions_|.
  static const size_t kDefaultMaxVersions;

  // Root of the path in the registry (values that make sense are HCU and HLM).
  static const HKEY kRegistryRootKey;

  // The base path that will contain the module keys (under |kRoot|). This gets
  // completed with the registry name that gets passed to the constructor to
  // form |registry_key_|.
  static const wchar_t kRegistryBaseKey[];
  // Constructors.
  // @param registry_name The base name that is used for storing in the
  //     registry.
  // @param max_days_in_registry Value of max_days_in_registry_.
  // @param max_entries_per_version Value of max_entries_per_version_.
  // @param max_modules Value of max_modules_.
  // @param max_versions Value of max_versions_.
  explicit RegistryCache(const wchar_t* registry_name);
  RegistryCache(const wchar_t* registry_name,
                size_t max_days_in_registry,
                size_t max_entries_per_version,
                size_t max_modules,
                size_t max_versions);

  // Returns true if the registry is available, false otherwise. On Chrome
  // renderer processes the sandbox prevents access to the registry.
  static bool RegistryAvailable();

  // Initializes the registry cache and prunes old values in the registry. This
  // must be called once, before any other method. Note that this function is
  // not thread-safe.
  // @returns false if an error occured.
  bool Init();

  // Adds a new |allocation_stack_id|, if it was not existent. Otherwise,
  // updates it by removing corresponding registry value and inserting a new
  // one. note that the ID must be a relative one. Will not do anything if the
  // module has not been initialized properly.
  // @pre is_init_ is true.
  // @param allocation_stack_id The relative stack ID to add.
  void AddOrUpdateStackId(common::StackCapture::StackId allocation_stack_id);

  // Checks if |allocation_stack_id| has been loaded from the registry. Will
  // always return false if the module has not been initialized properly.
  // @pre is_init_ is true.
  // @param allocation_stack_id The relative stack ID to lookup.
  // @returns true if the ID has been found, false otherwise or if not
  //     initialized.
  bool DoesIdExist(common::StackCapture::StackId allocation_stack_id) const;

  // Removes|allocation_stack_id| from the registry. Will always return false
  // if the module has not been initialized properly.
  // @pre is_init_ is true.
  // @param allocation_stack_id The relative stack ID to remove.
  // @returns true if the ID has been found, false otherwise or if not
  //     initialized.
  bool RemoveStackId(common::StackCapture::StackId allocation_stack_id);

  // Deletes the registry key corresponding to |registry_name|, including
  // everything below it. Use carefully!
  // @param registry_name  The base name whose key will be deleted from the
  //     registry.
  static void DeleteRegistryTree(const wchar_t* registry_name);

 protected:
  // For convenience (also used in unittests).
  typedef base::win::RegistryValueIterator RegValueIter;
  typedef base::win::RegistryKeyIterator RegKeyIter;
  typedef common::StackCapture::StackId StackId;

  // Maximum age allowed for an entry (in days). Any entry older than this value
  // will be purged during cleaning.
  size_t max_days_in_registry_;

  // Maximum number of entries allowed per module version. The cleaning process
  // will ensure that the number of entries in a module version does not exceed
  // this threshold by purging the oldest ones.
  size_t max_entries_per_version_;

  // Maximum number of modules allowed. The cleaning process will ensure that
  // the number of modules does not exceed this threshold by purging the oldest
  // ones.
  size_t max_modules_;

  // Maximum number of versions allowed per module. The cleaning process will
  // ensure that the number of versions for a module does not exceed this
  // threshold by purging the oldest ones.
  size_t max_versions_;

  // The base path that will contain the module keys (under |kRoot|).
  std::wstring registry_cache_key_;

  // Contains the name of the module.
  base::FilePath::StringType module_name_;
  // Contains the module version.
  std::wstring module_version_;
  // Contains the path of the module key in the registry.
  std::wstring module_key_name_;

 private:
  // Initializes the module name and version. This can fail if we are not able
  // to succesfully identify both.
  // @returns false if an error occured.
  bool InitModuleInfo();

  // Function that starts the cleanup of old entries in the registry by going
  // through each top-level key (corresponding to a module name) and calling
  // CleanUpModule on each entry. It will also delete module keys that become
  // empty after the operation. Finally, it limits the number of modules to
  // |kMaxModules| by deleting the oldest ones, if necessary.
  void CleanUp();

  // Function that cleans up a module key by going through each of its version
  // keys and calling CleanUpVersion on each entry. It will also delete version
  // keys that become empty after the operation. Finally, it limits the number
  // of versions to |kMaxVersions| by deleting the oldest ones, if necessary.
  // @param base_key The path of the registry key to clean up.
  // @param newest If not NULL, will be set to the timestamp of the newest
  //     entry. If no entries are valid/existent, will be set to UnixEpoch.
  void CleanUpModule(const std::wstring& base_key, base::Time* newest);

  // Purges old values and limits the total number of entries in a version key
  // to |kMaxEntriesPerVersion|.
  // @param src The registry key to clean up.
  // @param newest If not NULL, will be set to the timestamp of the newest
  //     entry. If no entries are valid/existent, will be set to UnixEpoch.
  void CleanUpVersion(base::win::RegKey* src, base::Time* newest);

  // Loads the entries from the registry for the current module.
  void LoadEntries();

  // True if Init() has been called successfully.
  bool is_init_;

  // The relative stack IDs that are loaded from the registry.
  std::unordered_set<common::StackCapture::StackId> entries_;

  DISALLOW_COPY_AND_ASSIGN(RegistryCache);
};

}  // namespace asan
}  // namespace agent

#endif  // SYZYGY_AGENT_ASAN_REGISTRY_CACHE_H_
