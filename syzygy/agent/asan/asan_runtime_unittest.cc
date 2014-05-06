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
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/agent/asan/asan_heap.h"
#include "syzygy/agent/asan/asan_logger.h"
#include "syzygy/agent/asan/unittest_util.h"

namespace agent {
namespace asan {

namespace {

using agent::asan::AsanErrorInfo;
using agent::asan::HeapProxy;

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
    HeapProxy::Init(&stack_cache_);
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
  current_command_line_.AppendSwitchASCII(common::kParamQuarantineSize,
                                          quarantine_max_size_str);

  // Tear down the runtime and restart it with a different command line.
  ASSERT_NO_FATAL_FAILURE(asan_runtime_.TearDown());
  ASSERT_NO_FATAL_FAILURE(
      asan_runtime_.SetUp(current_command_line_.GetCommandLineString()));

  // Ensure that the quarantine max size has been modified.
  EXPECT_EQ(quarantine_max_size, HeapProxy::default_quarantine_max_size());

  // Ensure that the heap proxies use the new quarantine max size.
  HeapProxy heap_proxy;
  ASSERT_TRUE(heap_proxy.Create(0, 0, 0));
  EXPECT_EQ(quarantine_max_size, heap_proxy.quarantine_max_size());
  ASSERT_TRUE(heap_proxy.Destroy());

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

TEST_F(AsanRuntimeTest, SetTrailerPaddingSize) {
  size_t trailer_padding_size = HeapProxy::trailer_padding_size() + 1;
  std::string new_trailer_padding_size_str =
      base::UintToString(trailer_padding_size);
  current_command_line_.AppendSwitchASCII(
      common::kParamTrailerPaddingSize, new_trailer_padding_size_str);

  ASSERT_NO_FATAL_FAILURE(
      asan_runtime_.SetUp(current_command_line_.GetCommandLineString()));
  EXPECT_EQ(trailer_padding_size, HeapProxy::trailer_padding_size());
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

TEST_F(AsanRuntimeTest, PropagateParams) {
  ASSERT_NO_FATAL_FAILURE(
      asan_runtime_.SetUp(current_command_line_.GetCommandLineString()));

  common::InflatedAsanParameters& params = asan_runtime_.params();
  params.quarantine_size =
      HeapProxy::default_quarantine_max_size() - 1;
  ASSERT_LT(0U, params.quarantine_size);
  params.reporting_period =
      StackCaptureCache::GetDefaultCompressionReportingPeriod() - 1;
  ASSERT_LT(0U, params.reporting_period);
  params.bottom_frames_to_skip =
      StackCapture::bottom_frames_to_skip() + 1;
  ASSERT_LT(0U, params.bottom_frames_to_skip);
  params.max_num_frames =
      asan_runtime_.stack_cache()->max_num_frames() - 1;
  ASSERT_LT(0U, params.max_num_frames);
  asan_runtime_.PropagateParams();

  ASSERT_EQ(params.quarantine_size, HeapProxy::default_quarantine_max_size());
  ASSERT_EQ(params.reporting_period,
            StackCaptureCache::compression_reporting_period());
  ASSERT_EQ(params.bottom_frames_to_skip,
            StackCapture::bottom_frames_to_skip());
  ASSERT_EQ(params.max_num_frames,
            asan_runtime_.stack_cache()->max_num_frames());

  ASSERT_NO_FATAL_FAILURE(asan_runtime_.TearDown());
}

TEST_F(AsanRuntimeTest, AddAndRemoveHeaps) {
  ASSERT_NO_FATAL_FAILURE(
      asan_runtime_.SetUp(current_command_line_.GetCommandLineString()));

  HeapProxy heap_1;
  HeapProxy heap_2;
  asan_runtime_.AddHeap(&heap_1);
  asan_runtime_.AddHeap(&heap_2);

  AsanRuntime::HeapVector heaps;
  asan_runtime_.GetHeaps(&heaps);
  EXPECT_EQ(2, heaps.size());

  asan_runtime_.RemoveHeap(&heap_1);
  asan_runtime_.GetHeaps(&heaps);
  EXPECT_EQ(1, heaps.size());

  asan_runtime_.RemoveHeap(&heap_2);
  asan_runtime_.GetHeaps(&heaps);
  EXPECT_EQ(0U, heaps.size());

  ASSERT_NO_FATAL_FAILURE(asan_runtime_.TearDown());
}

}  // namespace asan
}  // namespace agent
