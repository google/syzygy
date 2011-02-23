// Copyright 2011 Google Inc.
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
#ifndef SYZYGY_PE_UNITTEST_UTIL_H_
#define SYZYGY_PE_UNITTEST_UTIL_H_

#include <windows.h>
#include "base/file_path.h"

namespace testing {

// Name of the test DLL.
extern const wchar_t kDllName[];

// Retrieves computes the absolute path to image_name, where image_name
// is relative to the current executable's parent directory.
FilePath GetExeRelativePath(const wchar_t* image_name);

// These perform a series of assertations on the test DLL's integrity.
void CheckTestDll(const FilePath& path);

}  // namespace testing

#endif  // SYZYGY_PE_UNITTEST_UTIL_H_
