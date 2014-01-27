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

#include "syzygy/common/dbghelp_util.h"

#include <dbghelp.h>

#include "base/logging.h"
#include "syzygy/common/com_utils.h"

namespace common {

// A wrapper for SymInitialize. It looks like it has an internal race condition
// that can ocassionaly fail, so we wrap it and retry a finite number of times.
// Ugly, but necessary.
bool SymInitialize(HANDLE process,
                   const char* user_search_path,
                   bool invade_process) {
  for (int retry_count = 0; retry_count < 3; ++retry_count) {
    BOOL result = ::SymInitialize(process, user_search_path, invade_process);
    if (result == TRUE)
      return true;

    DWORD error = ::GetLastError();
    // This corresponds to STATUS_INFO_LENGTH_MISMATCH, which is defined in
    // ntstatus.h. This doesn't like being included alongside windows.h.
    if (error == 0xC0000004)
      continue;

    LOG(ERROR) << "SymInitialize failed: " << common::LogWe(error);
    return false;
  }

  LOG(ERROR) << "SymInitialize failed repeatedly.";
  return false;
}

}  // namespace common
