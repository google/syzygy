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

#include "syzygy/common/process_utils.h"

#include <psapi.h>

#include "base/logging.h"
#include "base/win/pe_image.h"
#include "syzygy/common/com_utils.h"
#include "syzygy/common/path_util.h"

namespace common {

bool GetCurrentProcessModules(ModuleVector* modules) {
  return GetProcessModules(::GetCurrentProcess(), modules);
}

bool GetProcessModules(HANDLE process, ModuleVector* modules) {
  DCHECK(modules != NULL);

  modules->resize(128);
  while (true) {
    DWORD bytes_required = 0;
    // EnumProcessModules expects a DWORD as size, so it should fit.
    DCHECK_LE(modules->size() * sizeof(modules->at(0)),
              std::numeric_limits<DWORD>::max());
    // EnumProcessModules returns 'success' even if the buffer size is too
    // small.
    if (!::EnumProcessModules(
            process,
            modules->data(),
            static_cast<DWORD>(modules->size() * sizeof(modules->at(0))),
            &bytes_required)) {
      DPLOG(ERROR) << "::EnumProcessModules";
      modules->clear();
      return false;
    }
    DCHECK_EQ(0u, bytes_required % sizeof(modules->at(0)));
    size_t num_modules = bytes_required / sizeof(modules->at(0));
    if (num_modules <= modules->size()) {
      // Buffer size was too big, presumably because a module was unloaded.
      modules->resize(num_modules);
      return true;
    } else if (num_modules == 0) {
      DLOG(ERROR) << "Can't determine the module list size.";
      modules->clear();
      return false;
    } else {
      // Buffer size was too small. Try again with a larger buffer.
      modules->resize(num_modules + 4, NULL);
    }
  }
}

}  // namespace common
