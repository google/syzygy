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
#include "base/string_number_conversions.h"
#include "base/utf_string_conversions.h"
#include "base/memory/scoped_ptr.h"
#include "gtest/gtest.h"
#include "syzygy/agent/asan/asan_heap.h"
#include "syzygy/agent/asan/unittest_util.h"

namespace agent {
namespace asan {

namespace {

using agent::asan::AsanErrorInfo;
using agent::asan::HeapProxy;

// A derived class to expose protected members for unit-testing.
class TestAsanRuntime : public AsanRuntime {
 public:
  using AsanRuntime::AsanFlags;
  using AsanRuntime::kBottomFramesToSkip;
  using AsanRuntime::kCompressionReportingPeriod;
  using AsanRuntime::kExitOnFailure;
  using AsanRuntime::kIgnoredStackIds;
  using AsanRuntime::kQuarantineSize;
  using AsanRuntime::kSyzyAsanEnvVar;
  using AsanRuntime::PropagateFlagsValues;
  using AsanRuntime::flags;
  using AsanRuntime::set_flags;
};

class AsanRuntimeTest : public testing::TestWithAsanLogger {
 public:
  AsanRuntimeTest() : current_command_line_(CommandLine::NO_PROGRAM) {
  }

  void SetUp() OVERRIDE {
    testing::TestWithAsanLogger::SetUp();
    scoped_ptr<base::Environment> env(base::Environment::Create());
    ASSERT_TRUE(env.get() != NULL);
    env->UnSetVar(TestAsanRuntime::kSyzyAsanEnvVar);

    // Setup the "global" state.
    HeapProxy::Init();
    StackCapture::Init();
    StackCaptureCache::Init();
  }

  // The test runtime instance.
  TestAsanRuntime asan_runtime_;

  // The value of the command-line that we want to test.
  CommandLine current_command_line_;
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
  asan_runtime_.SetErrorCallBack(base::Bind(&TestCallback));
  callback_called = false;
  AsanErrorInfo bad_access_info = {};
  RtlCaptureContext(&bad_access_info.context);
  asan_runtime_.OnError(&bad_access_info);
  ASSERT_TRUE(callback_called);
  ASSERT_NO_FATAL_FAILURE(asan_runtime_.TearDown());
}

TEST_F(AsanRuntimeTest, SetDefaultQuarantineMaxSize) {
  // Initialize the flags with the original command line.
  ASSERT_NO_FATAL_FAILURE(
      asan_runtime_.SetUp(current_command_line_.GetCommandLineString()));

  // Double the max size of the quarantine.
  unsigned int quarantine_max_size =
      HeapProxy::default_quarantine_max_size() * 2;
  // Increments the quarantine max size if it was set to 0.
  if (quarantine_max_size == 0)
    quarantine_max_size++;
  DCHECK_GT(quarantine_max_size, 0U);
  std::string quarantine_max_size_str = base::UintToString(quarantine_max_size);
  current_command_line_.AppendSwitchASCII(TestAsanRuntime::kQuarantineSize,
                                          quarantine_max_size_str);

  // Tear down the runtime and restart it with a different command line.
  ASSERT_NO_FATAL_FAILURE(asan_runtime_.TearDown());
  ASSERT_NO_FATAL_FAILURE(
      asan_runtime_.SetUp(current_command_line_.GetCommandLineString()));

  // Ensure that the quarantine max size has been modified.
  EXPECT_EQ(quarantine_max_size, HeapProxy::default_quarantine_max_size());

  // Ensure that the heap proxies use the new quarantine max size.
  HeapProxy heap_proxy(asan_runtime_.stack_cache(), asan_runtime_.logger());
  ASSERT_TRUE(heap_proxy.Create(0, 0, 0));
  EXPECT_EQ(quarantine_max_size, heap_proxy.quarantine_max_size());
  ASSERT_TRUE(heap_proxy.Destroy());
}

TEST_F(AsanRuntimeTest, SetCompressionReportingPeriod) {
  ASSERT_EQ(StackCaptureCache::GetDefaultCompressionReportingPeriod(),
            StackCaptureCache::compression_reporting_period());

  size_t new_period =
      StackCaptureCache::GetDefaultCompressionReportingPeriod() + 1024;
  std::string new_period_str = base::UintToString(new_period);
  current_command_line_.AppendSwitchASCII(
      TestAsanRuntime::kCompressionReportingPeriod, new_period_str);

  ASSERT_NO_FATAL_FAILURE(
      asan_runtime_.SetUp(current_command_line_.GetCommandLineString()));

  // Ensure that the compression reporting period has been modified.
  EXPECT_EQ(new_period, StackCaptureCache::compression_reporting_period());
}

TEST_F(AsanRuntimeTest, SetBottomFramesToSkip) {
  size_t frames_to_skip = StackCapture::bottom_frames_to_skip() + 1;
  std::string new_frames_to_skip_str = base::UintToString(frames_to_skip);
  current_command_line_.AppendSwitchASCII(
      TestAsanRuntime::kBottomFramesToSkip, new_frames_to_skip_str);

  ASSERT_NO_FATAL_FAILURE(
      asan_runtime_.SetUp(current_command_line_.GetCommandLineString()));

  EXPECT_EQ(frames_to_skip, StackCapture::bottom_frames_to_skip());
}

TEST_F(AsanRuntimeTest, SetExitOnFailure) {
  current_command_line_.AppendSwitch(TestAsanRuntime::kExitOnFailure);

  ASSERT_NO_FATAL_FAILURE(
      asan_runtime_.SetUp(current_command_line_.GetCommandLineString()));
  EXPECT_TRUE(asan_runtime_.flags()->exit_on_failure);
}

TEST_F(AsanRuntimeTest, ExitOnFailure) {
  current_command_line_.AppendSwitch(TestAsanRuntime::kExitOnFailure);

  ASSERT_NO_FATAL_FAILURE(
      asan_runtime_.SetUp(current_command_line_.GetCommandLineString()));

  EXPECT_TRUE(asan_runtime_.flags()->exit_on_failure);
  AsanErrorInfo bad_access_info = {};
  RtlCaptureContext(&bad_access_info.context);

  // We need to delete the files and directory created by this unittest because
  // the EXPECT_EXIT macro will clone the process and this new process will exit
  // after the call to OnError, without calling the destructor of this class
  // (who takes care of deleting the temporary files/directories).
  DeleteTempFileAndDirectory();
  EXPECT_EXIT(asan_runtime_.OnError(&bad_access_info),
              ::testing::ExitedWithCode(EXIT_FAILURE), "");
}

TEST_F(AsanRuntimeTest, IgnoredStackIds) {
  std::string ignored_stack_ids = "0x1;0X7E577E57;0xCAFEBABE;0xffffffff";
  current_command_line_.AppendSwitchASCII(
      TestAsanRuntime::kIgnoredStackIds, ignored_stack_ids);

  ASSERT_NO_FATAL_FAILURE(
      asan_runtime_.SetUp(current_command_line_.GetCommandLineString()));

  EXPECT_TRUE(asan_runtime_.flags()->ignored_stack_ids.find(0x1) !=
              asan_runtime_.flags()->ignored_stack_ids.end());
  EXPECT_TRUE(asan_runtime_.flags()->ignored_stack_ids.find(0x7E577E57) !=
              asan_runtime_.flags()->ignored_stack_ids.end());
  EXPECT_TRUE(asan_runtime_.flags()->ignored_stack_ids.find(0xCAFEBABE) !=
              asan_runtime_.flags()->ignored_stack_ids.end());
  EXPECT_TRUE(asan_runtime_.flags()->ignored_stack_ids.find(0xFFFFFFFF) !=
              asan_runtime_.flags()->ignored_stack_ids.end());
}

TEST_F(AsanRuntimeTest, SetFlags) {
  ASSERT_NO_FATAL_FAILURE(
      asan_runtime_.SetUp(current_command_line_.GetCommandLineString()));

  TestAsanRuntime::AsanFlags flags;
  flags.quarantine_size = HeapProxy::default_quarantine_max_size() - 1;
  ASSERT_LT(0U, flags.quarantine_size);
  flags.reporting_period =
      StackCaptureCache::GetDefaultCompressionReportingPeriod() - 1;
  ASSERT_LT(0U, flags.reporting_period);
  flags.bottom_frames_to_skip =
      StackCapture::bottom_frames_to_skip() + 1;
  ASSERT_LT(0U, flags.bottom_frames_to_skip);
  flags.max_num_frames =
      asan_runtime_.stack_cache()->max_num_frames() - 1;
  ASSERT_LT(0U, flags.max_num_frames);
  asan_runtime_.set_flags(&flags);
  asan_runtime_.PropagateFlagsValues();

  ASSERT_EQ(flags.quarantine_size, HeapProxy::default_quarantine_max_size());
  ASSERT_EQ(flags.reporting_period,
            StackCaptureCache::compression_reporting_period());
  ASSERT_EQ(flags.bottom_frames_to_skip, StackCapture::bottom_frames_to_skip());
  ASSERT_EQ(flags.max_num_frames,
            asan_runtime_.stack_cache()->max_num_frames());
}

}  // namespace asan
}  // namespace agent
