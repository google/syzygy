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

#ifndef SYZYGY_KASKO_API_INTERNAL_CRASH_KEY_REGISTRATION_H_
#define SYZYGY_KASKO_API_INTERNAL_CRASH_KEY_REGISTRATION_H_

#include <windows.h>

#include <vector>

namespace kasko {
namespace api {

struct CrashKey;

namespace internal {

// Registers the address of an array of crash keys for the current process. The
// registered crash key values may later be retrieved using
// ReadCrashKeysFromProcess. This method must only be called once per process.
// @param crash_keys An array of crash keys.
// @param crash_key_count The number of entries in crash_keys.
void RegisterCrashKeys(const CrashKey* crash_keys, size_t count);

// Reads the registered crash keys (if any) from a process. This method may
// return keys with empty keys and/or values.
// @param process The process from which to read the crash keys. Must have
//     PROCESS_QUERY_INFORMATION and PROCESS_VM_READ access.
// @param crash_keys Receives the crash keys that are read.
// @return true if successful.
bool ReadCrashKeysFromProcess(HANDLE process,
                              std::vector<CrashKey>* crash_keys);

}  // namespace internal
}  // namespace api
}  // namespace kasko

#endif  // SYZYGY_KASKO_API_INTERNAL_CRASH_KEY_REGISTRATION_H_
