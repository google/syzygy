// Copyright 2012 Google Inc. All Rights Reserved.
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
// Definitions and utility functions to initialize logging.

#ifndef SYZYGY_COMMON_LOGGING_H_
#define SYZYGY_COMMON_LOGGING_H_

#include <guiddef.h>

#include "base/strings/string_piece.h"

namespace common {

// The name of the Syzygy ETW log provider.
extern const GUID kSyzygyEtwLogProvider;

// Initializes logging for a DLL that can be loaded and unloaded from
// the client processes.
// @param client_name an identifying name for the logging client, may be used
//     to construct a file name to log to.
void InitLoggingForDll(const wchar_t* client_name);

}  // namespace common

#endif  // SYZYGY_COMMON_LOGGING_H_
