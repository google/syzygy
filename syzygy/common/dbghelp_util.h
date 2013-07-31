// Copyright 2013 Google Inc. All Rights Reserved.
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
// Utilities for dealing with the dbghelp library.

#ifndef SYZYGY_COMMON_DBGHELP_UTIL_H_
#define SYZYGY_COMMON_DBGHELP_UTIL_H_

#include <windows.h>

namespace common {

// A wrapper for SymInitialize. It looks like it has an internal race condition
// that can ocassionaly fail, so we wrap it and retry a finite number of times.
// Ugly, but necessary. Logs verbosely on failure.
// @param process Handle of the running process, or of the process being
//     debugged. Must not be NULL.
// @param user_search_path Semi-colon separated list of paths that will be
//     used to search for symbol files. May be NULL.
// @param invade_process If this is true then the modules of the process will be
//     enumerated and have each of their symbols loaded.
// @returns true on success, false otherwise.
// @note Use of this function incurs a dependency on dbghelp.dll.
bool SymInitialize(HANDLE process,
                   const char* user_search_path,
                   bool invade_process);

}  // namespace common

#endif  // SYZYGY_COMMON_DBGHELP_UTIL_H_
