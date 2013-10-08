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
//
// This file contains unittest utilities for setting up the environment prior
// to invoking parts of the MSVS toolchain. It is intended to be used as
// follows:
//
// TEST(Foo, Bar) {
//   base::CommandLine cmd_line(testing::kToolchainWrapperPath);
//   ...
//   base::LaunchProcess(cmd_line, 'link.exe', ...);
// }

#ifndef SYZYGY_TESTING_TOOLCHAIN_H_
#define SYZYGY_TESTING_TOOLCHAIN_H_

#include "base/files/file_path.h"

namespace testing {

// Absolute path of the toolchain-wrapping batch file.
extern const wchar_t kToolchainWrapperPath[];

}  // namespace testing

#endif  // SYZYGY_TESTING_TOOLCHAIN_H_
