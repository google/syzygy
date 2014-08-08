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

#include "syzygy/common/logging.h"

#include "base/logging.h"
#include "base/logging_win.h"

namespace common {

// {8FD3F6B0-0591-40a3-85CD-305C7751E5EF}
const GUID kSyzygyEtwLogProvider = { 0x8fd3f6b0, 0x591, 0x40a3,
    { 0x85, 0xcd, 0x30, 0x5c, 0x77, 0x51, 0xe5, 0xef } };

void InitLoggingForDll(const wchar_t* client_name) {
  logging::LoggingSettings settings;
  settings.logging_dest = logging::LOG_NONE;
  logging::InitLogging(settings);
  logging::LogEventProvider::Initialize(common::kSyzygyEtwLogProvider);
}

}  // namespace common
