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
//   ASSERT_NO_FATAL_FAILURE(testing::SetToolchainPaths());
//   base::CommandLine cmd_line(testing::kLinkerPath);
//   ...
//   base::LaunchProcess(cmd_line, ...);
// }

#ifndef SYZYGY_TESTING_TOOLCHAIN_H_
#define SYZYGY_TESTING_TOOLCHAIN_H_

#include "base/files/file_path.h"

namespace testing {

// Semi-colon separated list of paths that need to be in PATH for the
// toolchain to run.
extern const char kToolchainPaths[];

// Paths to the actual tools themselves.
extern const wchar_t kCompilerPath[];
extern const wchar_t kLinkerPath[];

// Prepares the environment for toolchain use (cl.exe and link.exe) by
// setting the appropriate paths. This is meant to be called from within an
// EXPECT_/ASSERT_NO_FATAL_FAILURES wrapper.
void SetToolchainPaths();

}  // namespace testing

#endif  // SYZYGY_TESTING_TOOLCHAIN_H_
