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

#ifndef SYZYGY_KASKO_TESTING_MINIDUMP_UNITTEST_HELPERS_H_
#define SYZYGY_KASKO_TESTING_MINIDUMP_UNITTEST_HELPERS_H_

#include <Windows.h>  // NOLINT
#include <Dbgeng.h>

#include "base/callback_forward.h"

namespace base {
class FilePath;
}  // namespace base

namespace kasko {
namespace testing {

// Receives COM interfaces that may be used to query a minidump file.
typedef base::Callback<void(IDebugClient4*, IDebugControl*, IDebugSymbols*)>
    MinidumpVisitor;

// Loads a minidump file and provides access via a callback.
// @param file_path The path to a minidump file.
// @param visitor A callback that will be invoked to query the loaded minidump
//     file.
// @returns S_OK if successful. Otherwise, an error code encountered during the
//     operation.
HRESULT VisitMinidump(const base::FilePath& file_path,
                      const MinidumpVisitor& visitor);

}  // namespace testing
}  // namespace kasko

#endif  // SYZYGY_KASKO_TESTING_MINIDUMP_UNITTEST_HELPERS_H_
