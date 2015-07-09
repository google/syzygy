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
// Process-related convenience utilities for agents.

#ifndef SYZYGY_COMMON_PROCESS_UTILS_H_
#define SYZYGY_COMMON_PROCESS_UTILS_H_

#include <windows.h>
#include <vector>

namespace common {

typedef std::vector<HMODULE> ModuleVector;

// Retrieves a list of all modules in the current process.
// @param modules returns a vector containing all modules in the process.
// @return true if successful. Otherwise, modules is guaranteed to be empty.
// @note that other threads in the process can be loading or unloading
//     libraries concurrently with calling this function and using its results.
//     Using the results from this function is therefore inherently racy, unless
//     running under the loader's lock, such as e.g. in a DllMain notification
//     or e.g. a TLS callback function.
bool GetCurrentProcessModules(ModuleVector* modules);

// Retrieves a list of all modules in the specified process.
// @param process the process to query.
// @param modules returns a vector containing all modules in the process.
// @return true if successful. Otherwise, modules is guaranteed to be empty.
// @note that the process can be loading or unloading libraries concurrently
//     with this function and the use of its results. Using the results from
//     this function is therefore inherently racy.
bool GetProcessModules(HANDLE process, ModuleVector* modules);

}  // namespace common

#endif  // SYZYGY_COMMON_PROCESS_UTILS_H_
