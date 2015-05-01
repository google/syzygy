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

#include "syzygy/kasko/testing/launch_python_process.h"

#include "base/bind.h"
#include "base/callback_helpers.h"
#include "base/command_line.h"
#include "base/files/file_path.h"
#include "base/process/kill.h"
#include "base/win/scoped_handle.h"
#include "gtest/gtest.h"

namespace kasko {
namespace testing {

TEST(LaunchPythonProcessTest, BasicTest) {
  base::CommandLine args(base::CommandLine::NO_PROGRAM);
  base::Process process;
  process = LaunchPythonProcess(
      base::FilePath(L"syzygy/kasko/testing/exit_with.py"), args);
  ASSERT_TRUE(process.IsValid());
  int exit_code = 0;
  ASSERT_TRUE(process.WaitForExit(&exit_code));
  ASSERT_EQ(0, exit_code);

  // Pass an argument.
  args.AppendArg("2");
  process = LaunchPythonProcess(
      base::FilePath(L"syzygy/kasko/testing/exit_with.py"), args);
  ASSERT_TRUE(process.IsValid());
  ASSERT_TRUE(process.WaitForExit(&exit_code));
  ASSERT_EQ(2, exit_code);

  // Switches are treated differently than arguments by CommandLine, and proved
  // to be tricky in the implementation. Hence this test case with both a switch
  // and an argument.
  args.AppendSwitch("-p 3");
  process = LaunchPythonProcess(
      base::FilePath(L"syzygy/kasko/testing/exit_with.py"), args);
  ASSERT_TRUE(process.IsValid());
  ASSERT_TRUE(process.WaitForExit(&exit_code));
  ASSERT_EQ(5, exit_code);

  // Set stdin to NULL, as the test launcher does in a parallel test mode.
  base::ScopedClosureRunner reset_stdin(
      base::Bind(base::IgnoreResult(&::SetStdHandle), STD_INPUT_HANDLE,
                 ::GetStdHandle(STD_INPUT_HANDLE)));
  ::SetStdHandle(STD_INPUT_HANDLE, INVALID_HANDLE_VALUE);
  process = LaunchPythonProcess(
      base::FilePath(L"syzygy/kasko/testing/exit_with.py"), args);
  ASSERT_TRUE(process.IsValid());
  ASSERT_TRUE(process.WaitForExit(&exit_code));
  ASSERT_EQ(5, exit_code);
}

}  // namespace testing
}  // namespace kasko
