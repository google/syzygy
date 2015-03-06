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

namespace base {
class FilePath;
}  // namespace base

namespace kasko {

// Represents a custom stream to be included in the generated minidump.
struct CustomStream {
  uint32_t type;
  const void* data;
  size_t length;
};

// Generates a minidump.
// @param destination The path where the dump should be generated.
// @param target_process The ID of the process whose dump should be captured.
// @param lient_exception_pointers The optional address of an EXCEPTION_POINTERS
//     structure in the target process memory space.
// @param thread_id The thread that threw the exception, or 0 in the absence of
//     an exception.
// @param custom_streams A vector of extra streams to include in the minidump.
// @returns true if the operation is successful.
bool GenerateMinidump(const base::FilePath& destination,
                      base::ProcessId target_process,
                      base::PlatformThreadId thread_id,
                      unsigned long client_exception_pointers,
                      const std::vector<CustomStream>& custom_streams);

}  // namespace kasko

#endif  // SYZYGY_KASKO_MINIDUMP_H_
