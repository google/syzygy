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

#include "syzygy/agent/asan/runtime.h"

#include <map>
#include <memory>

#include "base/bind.h"
#include "base/bits.h"
#include "base/command_line.h"
#include "base/environment.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/utf_string_conversions.h"
#include "gtest/gtest.h"
#include "syzygy/agent/asan/unittest_util.h"

namespace agent {
namespace asan {

namespace {

using agent::asan::AsanErrorInfo;

// Derived classes to expose protected members for unit-testing.
class TestBlockHeapManager : public heap_managers::BlockHeapManager {
 public:
  using heap_managers::BlockHeapManager::enable_page_protections_;
};

class TestAsanRuntime : public AsanRuntime {
 public:
  using AsanRuntime::GenerateRandomFeatureSet;
  using AsanRuntime::PropagateFeatureSet;
  using AsanRuntime::PropagateParams;
  using AsanRuntime::heap_manager_;
};

class AsanRuntimeTest : public testing::TestWithAsanLogger {
 public:
  typedef testing::TestWithAsanLogger Super;

  AsanRuntimeTest() : current_command_line_(base::CommandLine::NO_PROGRAM) {}

  void SetUp() override {
    Super::SetUp();

    env_.reset(base::Environment::Create());
    ASSERT_TRUE(env_.get() != NULL);
    env_->UnSetVar(::common::kSyzyAsanOptionsEnvVar);

    // Setup the "global" state.
    common::StackCapture::Init();
    StackCaptureCache::Init();
  }

  void TearDown() override {
    // Clear the environment so other tests aren't affected.
    env_->UnSetVar(::common::kSyzyAsanOptionsEnvVar);

    Super::TearDown();
  }

  // The test runtime instance.
  TestAsanRuntime asan_runtime_;

  // The value of the command-line that we want to test.
  base::CommandLine current_command_line_;

  // The process environment.
  std::unique_ptr<base::Environment> env_;
};

bool callback_called = false;
AsanErrorInfo callback_error_info = {};

// A simple callback that change the value of a boolean to indicate that it has
// been called.
void TestCallback(AsanErrorInfo* error_info) {
  callback_called = true;
  callback_error_info = *error_info;
}

}  // namespace

TEST_F(AsanRuntimeTest, SetUpAndTearDown) {
  ASSERT_NO_FATAL_FAILURE(
      asan_runtime_.SetUp(current_command_line_.GetCommandLineString()));
  // Make sure the singleton pointer matches the runtime we created.
  ASSERT_EQ(reinterpret_cast<AsanRuntime*>(&asan_runtime_),
            AsanRuntime::runtime());
  ASSERT_NO_FATAL_FAILURE(asan_runtime_.TearDown());
}

TEST_F(AsanRuntimeTest, ThreadIdCache) {
  ASSERT_NO_FATAL_FAILURE(
      asan_runtime_.SetUp(current_command_line_.GetCommandLineString()));

  EXPECT_FALSE(asan_runtime_.ThreadIdIsValid(1234));
  EXPECT_FALSE(asan_runtime_.ThreadIdIsValid(5678));
  asan_runtime_.AddThreadId(1234);
  EXPECT_TRUE(asan_runtime_.ThreadIdIsValid(1234));
  EXPECT_FALSE(asan_runtime_.ThreadIdIsValid(5678));
  asan_runtime_.AddThreadId(5678);
  EXPECT_TRUE(asan_runtime_.ThreadIdIsValid(1234));
  EXPECT_TRUE(asan_runtime_.ThreadIdIsValid(5678));

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
  ::common::AsanParameters params = asan_runtime_.params();
  EXPECT_EQ(0u, ::memcmp(&params, &(callback_error_info.asan_parameters),
                         sizeof(::common::AsanParameters)));
}

TEST_F(AsanRuntimeTest, SetCompressionReportingPeriod) {
  ASSERT_EQ(StackCaptureCache::GetDefaultCompressionReportingPeriod(),
            StackCaptureCache::compression_reporting_period());

  size_t new_period =
      StackCaptureCache::GetDefaultCompressionReportingPeriod() + 1024;
  std::string new_period_str = base::SizeTToString(new_period);
  current_command_line_.AppendSwitchASCII(
      ::common::kParamReportingPeriod, new_period_str);

  ASSERT_NO_FATAL_FAILURE(
      asan_runtime_.SetUp(current_command_line_.GetCommandLineString()));
  // Ensure that the compression reporting period has been modified.
  EXPECT_EQ(new_period, StackCaptureCache::compression_reporting_period());
  ASSERT_NO_FATAL_FAILURE(asan_runtime_.TearDown());
}

TEST_F(AsanRuntimeTest, SetBottomFramesToSkip) {
  size_t frames_to_skip = common::StackCapture::bottom_frames_to_skip() + 1;
  std::string new_frames_to_skip_str = base::SizeTToString(frames_to_skip);
  current_command_line_.AppendSwitchASCII(
      ::common::kParamBottomFramesToSkip, new_frames_to_skip_str);

  ASSERT_NO_FATAL_FAILURE(
      asan_runtime_.SetUp(current_command_line_.GetCommandLineString()));
  EXPECT_EQ(frames_to_skip, common::StackCapture::bottom_frames_to_skip());
  ASSERT_NO_FATAL_FAILURE(asan_runtime_.TearDown());
}

TEST_F(AsanRuntimeTest, SetDisableBreakpad) {
  current_command_line_.AppendSwitch(::common::kParamDisableBreakpadReporting);

  ASSERT_NO_FATAL_FAILURE(
      asan_runtime_.SetUp(current_command_line_.GetCommandLineString()));
  EXPECT_TRUE(asan_runtime_.params().disable_breakpad_reporting);
  ASSERT_NO_FATAL_FAILURE(asan_runtime_.TearDown());
}

TEST_F(AsanRuntimeTest, SetExitOnFailure) {
  current_command_line_.AppendSwitch(::common::kParamExitOnFailure);

  ASSERT_NO_FATAL_FAILURE(
      asan_runtime_.SetUp(current_command_line_.GetCommandLineString()));
  EXPECT_TRUE(asan_runtime_.params().exit_on_failure);
  ASSERT_NO_FATAL_FAILURE(asan_runtime_.TearDown());
}

TEST_F(AsanRuntimeTest, ExitOnFailure) {
  // This test always fails under a debugger, due to strangeness in how
  // gtest death tests work.
  if (base::debug::BeingDebugged()) {
    LOG(WARNING) << "Skipping this test under debugger.";
    return;
  }

  current_command_line_.AppendSwitch(::common::kParamExitOnFailure);

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
      ::common::kParamIgnoredStackIds, ignored_stack_ids);

  ASSERT_NO_FATAL_FAILURE(
      asan_runtime_.SetUp(current_command_line_.GetCommandLineString()));

  EXPECT_THAT(asan_runtime_.params().ignored_stack_ids_set,
              testing::ElementsAre(0x1, 0x7E577E57, 0xCAFEBABE, 0xFFFFFFFF));
  ASSERT_NO_FATAL_FAILURE(asan_runtime_.TearDown());
}

TEST_F(AsanRuntimeTest, HeapIdIsValid) {
  ASSERT_NO_FATAL_FAILURE(
      asan_runtime_.SetUp(current_command_line_.GetCommandLineString()));

  EXPECT_FALSE(asan_runtime_.HeapIdIsValid(0xDEADBEEF));
  EXPECT_TRUE(asan_runtime_.HeapIdIsValid(asan_runtime_.GetProcessHeap()));

  ASSERT_NO_FATAL_FAILURE(asan_runtime_.TearDown());
}

TEST_F(AsanRuntimeTest, GetHeapType) {
  ASSERT_NO_FATAL_FAILURE(
      asan_runtime_.SetUp(current_command_line_.GetCommandLineString()));

  HeapManagerInterface::HeapId heap_id = asan_runtime_.GetProcessHeap();
  EXPECT_EQ(kWinHeap, asan_runtime_.GetHeapType(heap_id));

  ASSERT_NO_FATAL_FAILURE(asan_runtime_.TearDown());
}

TEST_F(AsanRuntimeTest, GenerateRandomFeatureSet) {
  const size_t kIterations = 10000;
  std::map<size_t, size_t> feature_group_frequency;

  for (size_t i = 0; i < kIterations; ++i) {
    AsanFeatureSet feature_group = asan_runtime_.GenerateRandomFeatureSet();
    ASSERT_LT(feature_group, ASAN_FEATURE_MAX);
    if (feature_group_frequency.find(feature_group) !=
        feature_group_frequency.end()) {
      feature_group_frequency[feature_group]++;
    } else {
      feature_group_frequency[feature_group] = 0;
    }
  }

  // Count the deprecated features.
  size_t number_of_deprecated_features = 0;
  for (size_t i = 0; i < sizeof(kAsanDeprecatedFeatures) * 8; ++i) {
    if ((kAsanDeprecatedFeatures & (1 << i)) != 0)
      number_of_deprecated_features++;
  }

  // This could theoretically fail, but that would imply an extremely bad
  // implementation of the underlying random number generator. We expect a
  // standard deviation of 1 / 8 * sqrt(10000 * 7) = 33. A 10% margin is
  // 1000 / 33 = 30 standard deviations. For |z| > 30, the p-value is < 0.00001
  // and can be considered as insignificant.
  const size_t kExpectedCount =
      kIterations / (ASAN_FEATURE_MAX >> number_of_deprecated_features);
  const size_t kErrorMargin = kExpectedCount / 10;
  for (const auto& iter : feature_group_frequency) {
    EXPECT_LT(kExpectedCount - kErrorMargin, iter.second);
    EXPECT_GT(kExpectedCount + kErrorMargin, iter.second);
  }
}

TEST_F(AsanRuntimeTest, PropagateFeatureSet) {
  ASSERT_NO_FATAL_FAILURE(
      asan_runtime_.SetUp(current_command_line_.GetCommandLineString()));

  for (uint32_t feature_set = 0; feature_set < ASAN_FEATURE_MAX;
       ++feature_set) {
    // Skip feature sets that enable deprecated features.
    if (feature_set & kAsanDeprecatedFeatures)
      continue;

    asan_runtime_.PropagateFeatureSet(feature_set);
    ::common::AsanParameters expected_params = {};
    ::common::SetDefaultAsanParameters(&expected_params);
    expected_params.enable_large_block_heap =
        ((feature_set & ASAN_FEATURE_ENABLE_LARGE_BLOCK_HEAP) != 0U);
    EXPECT_EQ(0U, ::memcmp(&expected_params, &asan_runtime_.params(),
                           sizeof(::common::AsanParameters)));
    TestBlockHeapManager* test_block_heap_manager =
        static_cast<TestBlockHeapManager*>(asan_runtime_.heap_manager_.get());
    EXPECT_EQ(test_block_heap_manager->enable_page_protections_,
              ((feature_set & ASAN_FEATURE_ENABLE_PAGE_PROTECTIONS) != 0U));
  }

  ASSERT_NO_FATAL_FAILURE(asan_runtime_.TearDown());
}

TEST_F(AsanRuntimeTest, OnErrorSaveEnabledFeatureList) {
  asan_runtime_.params().feature_randomization = true;
  ASSERT_NO_FATAL_FAILURE(
      asan_runtime_.SetUp(current_command_line_.GetCommandLineString()));

  // Disable the heap checking as this really slows down the unittests.
  asan_runtime_.params().check_heap_on_failure = false;
  asan_runtime_.SetErrorCallBack(base::Bind(&TestCallback));
  callback_called = false;
  callback_error_info.feature_set = ASAN_FEATURE_MAX;
  AsanErrorInfo bad_access_info = {};
  RtlCaptureContext(&bad_access_info.context);
  AsanFeatureSet expected_feature_set = static_cast<AsanFeatureSet>(
      ASAN_FEATURE_ENABLE_LARGE_BLOCK_HEAP);
  asan_runtime_.PropagateFeatureSet(expected_feature_set);
  asan_runtime_.OnError(&bad_access_info);
  EXPECT_TRUE(callback_called);
  EXPECT_EQ(expected_feature_set, callback_error_info.feature_set);
  ASSERT_NO_FATAL_FAILURE(asan_runtime_.TearDown());
}

}  // namespace asan
}  // namespace agent
