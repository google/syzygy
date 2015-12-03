// Copyright 2014 Google Inc. All Rights Reserved.
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

#ifndef SYZYGY_KASKO_MINIDUMP_H_
#define SYZYGY_KASKO_MINIDUMP_H_

#include <vector>

#include "base/process/process_handle.h"
#include "base/threading/platform_thread.h"
#include "syzygy/kasko/minidump_request.h"
#include "syzygy/kasko/api/minidump_type.h"

namespace base {
class FilePath;
}  // namespace base

namespace kasko {

// Returns the access required to create a minidump of this type.
// @param type The type of the minidump to generate.
// @returns The access flags needed for the dump type.
DWORD GetRequiredAccessForMinidumpType(MinidumpRequest::Type type);
DWORD GetRequiredAccessForMinidumpType(api::MinidumpType type);

// Generates a minidump.
// @param destination The path where the dump should be generated.
// @param target_process The handle of the process whose dump should be
//     captured. Must have PROCESS_QUERY_INFORMATION and PROCESS_VM_READ access.
//     for full dumps, PROCESS_DUP_HANDLE is also required.
// @param thread_id The thread that threw the exception. Ignored if
//     request.exception_pointers is null.
// @param request The minidump parameters.
// @returns true if the operation is successful.
bool GenerateMinidump(const base::FilePath& destination,
                      base::ProcessHandle target_process,
                      base::PlatformThreadId thread_id,
                      const MinidumpRequest& request);

}  // namespace kasko

#endif  // SYZYGY_KASKO_MINIDUMP_H_
