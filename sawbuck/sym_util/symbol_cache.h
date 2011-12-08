// Copyright 2011 Google Inc.
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
// A quick and dirty wrapper for symbol lookups using dbghelp.
#ifndef SAWBUCK_SYM_UTIL_SYMBOL_CACHE_H_
#define SAWBUCK_SYM_UTIL_SYMBOL_CACHE_H_

#include <windows.h>
#include <string>
#include <map>
#include <set>
#include <vector>
#include "base/callback.h"
#include "sawbuck/sym_util/types.h"

namespace sym_util {

// A simple wrapper around the Symbol APIs.
class SymbolCache {
 public:
  SymbolCache();
  ~SymbolCache();

  typedef base::Callback<void(const wchar_t*)> StatusCallback;
  void set_status_callback(StatusCallback* status_callback) {
    status_callback_ = status_callback;
  }

  bool GetSymbolForAddress(Address address, Symbol *symbol);

  // Initialize to the set of modules provided.
  bool Initialize(size_t num_modules, ModuleInformation* modules);
  void Cleanup();

  // Sets a new symbol path, flushes the current cache.
  void SetSymbolPath(const wchar_t* symbol_path);

 private:
  // We handle symbol callbacks to provide more information about images,
  // such as checksums and timestamps.
  static BOOL CALLBACK SymbolCallback(HANDLE process,
                                      ULONG action,
                                      ULONG64 data,
                                      ULONG64 context);

  bool GetModuleInformation(Address load_address, ModuleInformation* info);

  // The process handle we provide SymInitialize.
  HANDLE process_handle_;

  // Our symbol path.
  std::wstring symbol_path_;

  // True iff we've successfully SymInitialized and not
  // called SymCleanup.
  bool initialized_;

  // Callback we invoke on on status updates.
  StatusCallback* status_callback_;

  // We keep a cache of previously resolved symbols.
  // TODO(siggi): does this make sense?
  typedef std::map<Address, Symbol> SymbolMap;
  SymbolMap cache_;

  typedef std::vector<ModuleInformation> ModuleList;
  ModuleList modules_;

  // To ensure we only retry loading each module once.
  typedef std::set<Address> RetriedModuleSet;
  RetriedModuleSet retried_;
};

}  // namespace sym_util

#endif  // SAWBUCK_SYM_UTIL_SYMBOL_CACHE_H_
