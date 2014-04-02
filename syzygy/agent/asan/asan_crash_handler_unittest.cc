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

#include "syzygy/agent/asan/asan_crash_handler.h"

#include <windows.h>

#include "base/bind.h"
#include "base/command_line.h"
#include "base/process_util.h"
#include "base/string_piece.h"
#include "base/files/file_path.h"
#include "base/synchronization/lock.h"
#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"

namespace agent {
namespace asan {

namespace {

const wchar_t kAsanCrashHandlerHarness[] = L"asan_crash_handler_harness.exe";

class TestAsanCrashHandler : public AsanCrashHandler {
 public:
  using AsanCrashHandler::on_exception_callback_;
  using AsanCrashHandler::disabled_thread_ids_;
};

class AsanCrashHandlerTest : public testing::Test {
  virtual void TearDown() OVERRIDE {
    TestAsanCrashHandler::on_exception_callback_.Reset();
  }
};

void RunHarnessTest(const base::StringPiece& test_name) {
  base::FilePath harness =
      testing::GetOutputRelativePath(kAsanCrashHandlerHarness);

  CommandLine cmd_line(harness);
  cmd_line.AppendSwitchASCII("test", test_name.as_string());

  base::LaunchOptions options;
  base::ProcessHandle handle = 0;
  ASSERT_TRUE(base::LaunchProcess(cmd_line, options, &handle));

  int exit_code = 0;
  ASSERT_TRUE(base::WaitForExitCode(handle, &exit_code));

  ASSERT_EQ(0u, exit_code);
}

void OnException(bool* called, struct _EXCEPTION_POINTERS** exception) {
  ASSERT_TRUE(called != NULL);
  *called = true;
}

}  // namespace

TEST_F(AsanCrashHandlerTest, EnableAndDisableFilter) {
  EXPECT_EQ(0u, TestAsanCrashHandler::disabled_thread_ids_.size());
  AsanCrashHandler::DisableForCurrentThread();
  EXPECT_EQ(1u, TestAsanCrashHandler::disabled_thread_ids_.size());
  AsanCrashHandler::EnableForCurrentThread();
  EXPECT_EQ(0u, TestAsanCrashHandler::disabled_thread_ids_.size());
}

TEST_F(AsanCrashHandlerTest, SetOnExceptionCallback) {
  EXPECT_TRUE(TestAsanCrashHandler::on_exception_callback_.is_null());

  bool called = false;
  AsanCrashHandler::SetOnExceptionCallback(
      base::Bind(&OnException, base::Unretained(&called)));
  EXPECT_FALSE(TestAsanCrashHandler::on_exception_callback_.is_null());

  TestAsanCrashHandler::on_exception_callback_.Run(NULL);
  EXPECT_TRUE(called);
}

TEST_F(AsanCrashHandlerTest, FilterEnabled) {
  EXPECT_NO_FATAL_FAILURE(RunHarnessTest("FilterEnabled"));
}

TEST_F(AsanCrashHandlerTest, FilterDisabled) {
  EXPECT_NO_FATAL_FAILURE(RunHarnessTest("FilterDisabled"));
}

}  // namespace asan
}  // namespace agent
