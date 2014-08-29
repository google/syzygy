// Copyright 2012 Google Inc. All Rights Reserved.
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

#include "syzygy/agent/asan/asan_runtime.h"

#include "base/bind.h"
#include "base/command_line.h"
#include "base/environment.h"
#include "base/memory/scoped_ptr.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/utf_string_conversions.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/agent/asan/asan_logger.h"
#include "syzygy/agent/asan/unittest_util.h"

namespace agent {
namespace asan {

namespace {

using agent::asan::AsanErrorInfo;

// A derived class to expose protected members for unit-testing.
class TestAsanRuntime : public AsanRuntime {
 public:
  using AsanRuntime::PropagateParams;
};

class AsanRuntimeTest : public testing::TestWithAsanLogger {
 public:
  typedef testing::TestWithAsanLogger Super;

  AsanRuntimeTest()
      : current_command_line_(CommandLine::NO_PROGRAM),
        stack_cache_(&logger_) {
  }

  void SetUp() OVERRIDE {
    Super::SetUp();

    env_.reset(base::Environment::Create());
    ASSERT_TRUE(env_.get() != NULL);
    env_->UnSetVar(AsanRuntime::kSyzygyAsanOptionsEnvVar);

    // Setup the "global" state.
    StackCapture::Init();
    StackCaptureCache::Init();
  }

  void TearDown() OVERRIDE {
    // Clear the environment so other tests aren't affected.
    env_->UnSetVar(AsanRuntime::kSyzygyAsanOptionsEnvVar);

    Super::TearDown();
  }

  AsanLogger logger_;
  StackCaptureCache stack_cache_;

  // The test runtime instance.
  TestAsanRuntime asan_runtime_;

  // The value of the command-line that we want to test.
  CommandLine current_command_line_;

  // The process environment.
  scoped_ptr<base::Environment> env_;
};

bool callback_called = false;

// A simple callback that change the value of a boolean to indicate that it has
// been called.
void TestCallback(AsanErrorInfo* error_info) {
  callback_called = true;
}

}  // namespace

TEST_F(AsanRuntimeTest, SetUpAndTearDown) {
  ASSERT_NO_FATAL_FAILURE(
      asan_runtime_.SetUp(current_command_line_.GetCommandLineString()));
  ASSERT_NO_FATAL_FAILURE(asan_runtime_.TearDown());
}

TEST_F(AsanRuntimeTest, OnError) {
  ASSERT_NO_FATAL_FAILURE(
      asan_runtime_.SetUp(current_command_line_.GetCommandLineString()));

  // Disable the heap checking as this really slows down the unittests.
  asan_runtime_.params().check_heap_on_failure = false;
  asan_runtime_.SetErrorCallBack(base::Bind(&TestCallback));
  callback_called = false;
  AsanErrorInfo bad_access_info = {};
  RtlCaptureContext(&bad_access_info.context);
  asan_runtime_.OnError(&bad_access_info);
  ASSERT_TRUE(callback_called);
  ASSERT_NO_FATAL_FAILURE(asan_runtime_.TearDown());
}

TEST_F(AsanRuntimeTest, SetCompressionReportingPeriod) {
  ASSERT_EQ(StackCaptureCache::GetDefaultCompressionReportingPeriod(),
            StackCaptureCache::compression_reporting_period());

  size_t new_period =
      StackCaptureCache::GetDefaultCompressionReportingPeriod() + 1024;
  std::string new_period_str = base::UintToString(new_period);
  current_command_line_.AppendSwitchASCII(
      common::kParamReportingPeriod, new_period_str);

  ASSERT_NO_FATAL_FAILURE(
      asan_runtime_.SetUp(current_command_line_.GetCommandLineString()));
  // Ensure that the compression reporting period has been modified.
  EXPECT_EQ(new_period, StackCaptureCache::compression_reporting_period());
  ASSERT_NO_FATAL_FAILURE(asan_runtime_.TearDown());
}

TEST_F(AsanRuntimeTest, SetBottomFramesToSkip) {
  size_t frames_to_skip = StackCapture::bottom_frames_to_skip() + 1;
  std::string new_frames_to_skip_str = base::UintToString(frames_to_skip);
  current_command_line_.AppendSwitchASCII(
      common::kParamBottomFramesToSkip, new_frames_to_skip_str);

  ASSERT_NO_FATAL_FAILURE(
      asan_runtime_.SetUp(current_command_line_.GetCommandLineString()));
  EXPECT_EQ(frames_to_skip, StackCapture::bottom_frames_to_skip());
  ASSERT_NO_FATAL_FAILURE(asan_runtime_.TearDown());
}

TEST_F(AsanRuntimeTest, SetDisableBreakpad) {
  current_command_line_.AppendSwitch(common::kParamDisableBreakpadReporting);

  ASSERT_NO_FATAL_FAILURE(
      asan_runtime_.SetUp(current_command_line_.GetCommandLineString()));
  EXPECT_TRUE(asan_runtime_.params().disable_breakpad_reporting);
  ASSERT_NO_FATAL_FAILURE(asan_runtime_.TearDown());
}

TEST_F(AsanRuntimeTest, SetExitOnFailure) {
  current_command_line_.AppendSwitch(common::kParamExitOnFailure);

  ASSERT_NO_FATAL_FAILURE(
      asan_runtime_.SetUp(current_command_line_.GetCommandLineString()));
  EXPECT_TRUE(asan_runtime_.params().exit_on_failure);
  ASSERT_NO_FATAL_FAILURE(asan_runtime_.TearDown());
}

TEST_F(AsanRuntimeTest, ExitOnFailure) {
  current_command_line_.AppendSwitch(common::kParamExitOnFailure);

  ASSERT_NO_FATAL_FAILURE(
      asan_runtime_.SetUp(current_command_line_.GetCommandLineString()));

  EXPECT_TRUE(asan_runtime_.params().exit_on_failure);
  AsanErrorInfo bad_access_info = {};
  RtlCaptureContext(&bad_access_info.context);

  // We need to delete the files and directory created by this unittest because
  // the EXPECT_EXIT macro will clone the process and this new process will exit
  // after the call to OnError, without calling the destructor of this class
  // (who takes care of deleting the temporary files/directories).
  DeleteTempFileAndDirectory();
  // Disable the heap checking as this really slows down the unittests.
  asan_runtime_.params().check_heap_on_failure = false;
  EXPECT_EXIT(asan_runtime_.OnError(&bad_access_info),
              ::testing::ExitedWithCode(EXIT_FAILURE), "");

  ASSERT_NO_FATAL_FAILURE(asan_runtime_.TearDown());
}

TEST_F(AsanRuntimeTest, IgnoredStackIds) {
  std::string ignored_stack_ids = "0x1;0X7E577E57;0xCAFEBABE;0xffffffff";
  current_command_line_.AppendSwitchASCII(
      common::kParamIgnoredStackIds, ignored_stack_ids);

  ASSERT_NO_FATAL_FAILURE(
      asan_runtime_.SetUp(current_command_line_.GetCommandLineString()));

  EXPECT_THAT(asan_runtime_.params().ignored_stack_ids_set,
              testing::ElementsAre(0x1, 0x7E577E57, 0xCAFEBABE, 0xFFFFFFFF));
  ASSERT_NO_FATAL_FAILURE(asan_runtime_.TearDown());
}

}  // namespace asan
}  // namespace agent
