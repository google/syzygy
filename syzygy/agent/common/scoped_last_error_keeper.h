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

#ifndef SYZYGY_AGENT_COMMON_SCOPED_LAST_ERROR_KEEPER_H_
#define SYZYGY_AGENT_COMMON_SCOPED_LAST_ERROR_KEEPER_H_

namespace agent {
namespace common {

// Helper structure to capture and restore the current thread's last win32
// error-code value.
struct ScopedLastErrorKeeper {
  ScopedLastErrorKeeper() : last_error(::GetLastError()) {
  }

  ~ScopedLastErrorKeeper() {
    ::SetLastError(last_error);
  }

  DWORD last_error;
};

}  // namespace common
}  // namespace agent

#endif  // SYZYGY_AGENT_COMMON_SCOPED_LAST_ERROR_KEEPER_H_
