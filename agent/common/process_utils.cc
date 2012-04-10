// Copyright 2012 Google Inc.
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

#include "syzygy/agent/common/process_utils.h"

#include <psapi.h>

#include "base/logging.h"

namespace agent {
namespace common {

void GetProcessModules(ModuleVector* modules) {
  DCHECK(modules != NULL);

  modules->resize(128);
  while (true) {
    DWORD bytes = sizeof(modules->at(0)) * modules->size();
    DWORD needed_bytes = 0;
    BOOL success = ::EnumProcessModules(::GetCurrentProcess(),
                                        &modules->at(0),
                                        bytes,
                                        &needed_bytes);
    if (success && bytes >= needed_bytes) {
      // Success - break out of the loop.
      // Resize our module vector to the returned size.
      modules->resize(needed_bytes / sizeof(modules->at(0)));
      return;
    }

    // Resize our module vector with the needed size and little slop.
    modules->resize(needed_bytes / sizeof(modules->at(0)) + 4);
  }
}

}  // namespace common
}  // namespace agent
