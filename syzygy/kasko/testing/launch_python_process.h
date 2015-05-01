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

#ifndef SYZYGY_KASKO_TESTING_LAUNCH_PYTHON_PROCESS_H_
#define SYZYGY_KASKO_TESTING_LAUNCH_PYTHON_PROCESS_H_

#include "base/process/process.h"

namespace base {
class CommandLine;
class FilePath;
class Process;
}  // namespace base

namespace kasko {
namespace testing {

// Launches a Python script.
// @param src_relative_path The script to launch, relative to the src tree root.
// @param args The script's arguments.
// @returns the process if it has launched successfully, an invalid process
//     otherwise.
base::Process LaunchPythonProcess(
    const base::FilePath& src_relative_path,
    const base::CommandLine& args);

}  // namespace testing
}  // namespace kasko

#endif  // SYZYGY_KASKO_TESTING_LAUNCH_PYTHON_PROCESS_H_
