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

#include "syzygy/reorder/reorder_app.h"

#include <string>

#include "base/stringprintf.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/block_graph/basic_block_decomposer.h"
#include "syzygy/block_graph/typed_block.h"
#include "syzygy/block_graph/unittest_util.h"
#include "syzygy/common/unittest_util.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/decomposer.h"
#include "syzygy/pe/pe_utils.h"
#include "syzygy/pe/unittest_util.h"
#include "syzygy/reorder/reorderer.h"

namespace reorder {

using block_graph::BlockGraph;
using common::Application;
using core::RelativeAddress;
using ::testing::ScopedLogLevelSaver;

namespace {

class TestReorderApp : public ReorderApp {
 public:
  using ReorderApp::kInvalidMode;
  using ReorderApp::kLinearOrderMode;
  using ReorderApp::kRandomOrderMode;
  using ReorderApp::kDeadCodeFinderMode;
  using ReorderApp::mode_;
  using ReorderApp::instrumented_image_path_;
  using ReorderApp::input_image_path_;
  using ReorderApp::output_file_path_;
  using ReorderApp::bb_entry_count_file_path_;
  using ReorderApp::trace_file_paths_;
  using ReorderApp::seed_;
  using ReorderApp::pretty_print_;
  using ReorderApp::flags_;
  using ReorderApp::kInstrumentedImage;
  using ReorderApp::kOutputFile;
  using ReorderApp::kInputImage;
  using ReorderApp::kBasicBlockEntryCounts;
  using ReorderApp::kSeed;
  using ReorderApp::kListDeadCode;
  using ReorderApp::kPrettyPrint;
  using ReorderApp::kReordererFlags;
  using ReorderApp::kInstrumentedDll;
  using ReorderApp::kInputDll;
};

typedef common::Application<TestReorderApp> TestApp;

class ReorderAppTest : public testing::PELibUnitTest {
 public:
  typedef testing::PELibUnitTest Super;

  ReorderAppTest()
      : cmd_line_(base::FilePath(L"reorder.exe")),
        test_impl_(test_app_.implementation()),
        seed_(1234567),
        pretty_print_(false) {
  }

  void SetUp() {
    Super::SetUp();

    // Several of the tests generate progress and (deliberate) error messages
    // that would otherwise clutter the unit-test output.
    logging::SetMinLogLevel(logging::LOG_FATAL);

    // Setup the IO streams.
    CreateTemporaryDir(&temp_dir_);
    stdin_path_ = temp_dir_.Append(L"NUL");
    stdout_path_ = temp_dir_.Append(L"stdout.txt");
    stderr_path_ = temp_dir_.Append(L"stderr.txt");
    InitStreams(stdin_path_, stdout_path_, stderr_path_);

    // Initialize the (potential) input and output path values.
    abs_input_image_path_ = testing::GetExeTestDataRelativePath(
        testing::kTestDllName);
    input_image_path_ = testing::GetRelativePath(abs_input_image_path_);

    abs_instrumented_image_path_ = testing::GetExeTestDataRelativePath(
        testing::kCallTraceInstrumentedTestDllName);
    instrumented_image_path_ = testing::GetRelativePath(
        abs_instrumented_image_path_);

    abs_output_file_path_ = testing::GetExeTestDataRelativePath(L"order.json");
    output_file_path_ = testing::GetRelativePath(abs_output_file_path_);

    abs_bb_entry_count_file_path_ = testing::GetExeTestDataRelativePath(
        L"basic_block_entry_traces\\entry_counts.json");
    bb_entry_count_file_path_ = testing::GetRelativePath(
        abs_bb_entry_count_file_path_);

    abs_trace_file_path_ = testing::GetExeTestDataRelativePath(
        testing::kCallTraceTraceFiles[0]);
    trace_file_path_ = testing::GetRelativePath(abs_trace_file_path_);

    // Point the application at the test's command-line and IO streams.
    test_app_.set_command_line(&cmd_line_);
    test_app_.set_in(in());
    test_app_.set_out(out());
    test_app_.set_err(err());
  }

 protected:
  // Stashes the current log-level before each test instance and restores it
  // after each test completes.
  ScopedLogLevelSaver log_level_saver;

  // @name The application under test.
  // @{
  TestApp test_app_;
  TestApp::Implementation& test_impl_;
  base::FilePath temp_dir_;
  base::FilePath stdin_path_;
  base::FilePath stdout_path_;
  base::FilePath stderr_path_;
  // @}

  // @name Command-line and parameters.
  // @{
  CommandLine cmd_line_;
  base::FilePath instrumented_image_path_;
  base::FilePath input_image_path_;
  base::FilePath output_file_path_;
  base::FilePath bb_entry_count_file_path_;
  base::FilePath trace_file_path_;
  uint32 seed_;
  bool pretty_print_;
  // @}

  // @name Expected final values of input parameters.
  // @{
  base::FilePath abs_input_image_path_;
  base::FilePath abs_instrumented_image_path_;
  base::FilePath abs_output_file_path_;
  base::FilePath abs_bb_entry_count_file_path_;
  base::FilePath abs_trace_file_path_;
  // @}
};

}  // namespace

TEST_F(ReorderAppTest, GetHelp) {
  cmd_line_.AppendSwitch("help");
  ASSERT_FALSE(test_impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(ReorderAppTest, EmptyCommandLineFails) {
  ASSERT_FALSE(test_impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(ReorderAppTest, ParseWithNeitherInstrumentedNorOrderFails) {
  cmd_line_.AppendSwitchPath("input-image", input_image_path_);

  ASSERT_FALSE(test_impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(ReorderAppTest, ParseWithSeedAndListDeadCodeFails) {
  cmd_line_.AppendSwitchPath(
      TestReorderApp::kInstrumentedImage, instrumented_image_path_);
  cmd_line_.AppendSwitchPath(TestReorderApp::kOutputFile, output_file_path_);
  cmd_line_.AppendSwitchPath(TestReorderApp::kInputImage, input_image_path_);
  cmd_line_.AppendSwitchASCII(
      TestReorderApp::kSeed, base::StringPrintf("%d", seed_));
  cmd_line_.AppendSwitch(TestReorderApp::kListDeadCode);

  ASSERT_FALSE(test_impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(ReorderAppTest, ParseWithEmptySeedFails) {
  cmd_line_.AppendSwitchPath(
      TestReorderApp::kInstrumentedImage, instrumented_image_path_);
  cmd_line_.AppendSwitchPath(TestReorderApp::kOutputFile, output_file_path_);
  cmd_line_.AppendSwitch(TestReorderApp::kSeed);

  ASSERT_FALSE(test_impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(ReorderAppTest, ParseWithInvalidSeedFails) {
  cmd_line_.AppendSwitchPath(
      TestReorderApp::kInstrumentedImage, instrumented_image_path_);
  cmd_line_.AppendSwitchPath(TestReorderApp::kOutputFile, output_file_path_);
  cmd_line_.AppendSwitchASCII(TestReorderApp::kSeed, "hello");

  ASSERT_FALSE(test_impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(ReorderAppTest, ParseWithInvalidFlagsFails) {
  cmd_line_.AppendSwitchPath(
      TestReorderApp::kInstrumentedImage, instrumented_image_path_);
  cmd_line_.AppendSwitchPath(TestReorderApp::kOutputFile, output_file_path_);
  cmd_line_.AppendSwitchASCII(
      TestReorderApp::kReordererFlags, "no-data,no-code,hello");

  ASSERT_FALSE(test_impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(ReorderAppTest, ParseLinearOrderWithNoTraceFiles) {
  cmd_line_.AppendSwitchPath(
      TestReorderApp::kInstrumentedImage, instrumented_image_path_);
  cmd_line_.AppendSwitchPath(TestReorderApp::kOutputFile, output_file_path_);
  ASSERT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(ReorderAppTest, ParseMinimalLinearOrderCommandLine) {
  cmd_line_.AppendSwitchPath(
      TestReorderApp::kInstrumentedImage, instrumented_image_path_);
  cmd_line_.AppendSwitchPath(TestReorderApp::kOutputFile, output_file_path_);
  cmd_line_.AppendArgPath(trace_file_path_);

  ASSERT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));

  EXPECT_EQ(TestReorderApp::kLinearOrderMode, test_impl_.mode_);
  EXPECT_TRUE(test_impl_.input_image_path_.empty());
  EXPECT_EQ(abs_instrumented_image_path_, test_impl_.instrumented_image_path_);
  EXPECT_EQ(abs_output_file_path_, test_impl_.output_file_path_);
  EXPECT_EQ(abs_trace_file_path_, test_impl_.trace_file_paths_.front());
  EXPECT_EQ(0U, test_impl_.seed_);
  EXPECT_FALSE(test_impl_.pretty_print_);
  EXPECT_EQ(Reorderer::kFlagReorderCode | Reorderer::kFlagReorderData,
            test_impl_.flags_);

  EXPECT_TRUE(test_impl_.SetUp());
}

TEST_F(ReorderAppTest, ParseFullLinearOrderCommandLine) {
  cmd_line_.AppendSwitchPath(
      TestReorderApp::kInstrumentedImage, instrumented_image_path_);
  cmd_line_.AppendSwitchPath(TestReorderApp::kOutputFile, output_file_path_);
  cmd_line_.AppendSwitchPath(TestReorderApp::kInputImage, input_image_path_);
  cmd_line_.AppendSwitchPath(
      TestReorderApp::kBasicBlockEntryCounts, bb_entry_count_file_path_);
  cmd_line_.AppendSwitchASCII(
      TestReorderApp::kReordererFlags, "no-data,no-code");
  cmd_line_.AppendSwitch(TestReorderApp::kPrettyPrint);
  cmd_line_.AppendArgPath(trace_file_path_);

  ASSERT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));

  EXPECT_EQ(TestReorderApp::kLinearOrderMode, test_impl_.mode_);
  EXPECT_EQ(abs_input_image_path_, test_impl_.input_image_path_);
  EXPECT_EQ(abs_instrumented_image_path_, test_impl_.instrumented_image_path_);
  EXPECT_EQ(abs_output_file_path_, test_impl_.output_file_path_);
  EXPECT_EQ(abs_bb_entry_count_file_path_,
            test_impl_.bb_entry_count_file_path_);
  EXPECT_EQ(abs_trace_file_path_, test_impl_.trace_file_paths_.front());
  EXPECT_EQ(0U, test_impl_.seed_);
  EXPECT_TRUE(test_impl_.pretty_print_);
  EXPECT_EQ(0, test_impl_.flags_ & Reorderer::kFlagReorderCode);
  EXPECT_EQ(0, test_impl_.flags_ & Reorderer::kFlagReorderData);

  EXPECT_TRUE(test_impl_.SetUp());
}

TEST_F(ReorderAppTest, ParseMinimalDeprecatedLinearOrderCommandLine) {
  cmd_line_.AppendSwitchPath(
      TestReorderApp::kInstrumentedDll, instrumented_image_path_);
  cmd_line_.AppendSwitchPath(TestReorderApp::kOutputFile, output_file_path_);
  cmd_line_.AppendArgPath(trace_file_path_);

  ASSERT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));

  EXPECT_EQ(TestReorderApp::kLinearOrderMode, test_impl_.mode_);
  EXPECT_TRUE(test_impl_.input_image_path_.empty());
  EXPECT_EQ(abs_instrumented_image_path_, test_impl_.instrumented_image_path_);
  EXPECT_EQ(abs_output_file_path_, test_impl_.output_file_path_);
  EXPECT_EQ(abs_trace_file_path_, test_impl_.trace_file_paths_.front());
  EXPECT_EQ(0U, test_impl_.seed_);
  EXPECT_FALSE(test_impl_.pretty_print_);

  EXPECT_TRUE(test_impl_.SetUp());
}

TEST_F(ReorderAppTest, ParseFullDeprecatedLinearOrderCommandLine) {
  cmd_line_.AppendSwitchPath(
      TestReorderApp::kInstrumentedDll, instrumented_image_path_);
  cmd_line_.AppendSwitchPath(TestReorderApp::kOutputFile, output_file_path_);
  cmd_line_.AppendSwitchPath(TestReorderApp::kInputDll, input_image_path_);
  cmd_line_.AppendSwitch(TestReorderApp::kPrettyPrint);
  cmd_line_.AppendArgPath(trace_file_path_);

  ASSERT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));

  EXPECT_EQ(TestReorderApp::kLinearOrderMode, test_impl_.mode_);
  EXPECT_EQ(abs_input_image_path_, test_impl_.input_image_path_);
  EXPECT_EQ(abs_instrumented_image_path_, test_impl_.instrumented_image_path_);
  EXPECT_EQ(abs_output_file_path_, test_impl_.output_file_path_);
  EXPECT_EQ(0U, test_impl_.seed_);
  EXPECT_TRUE(test_impl_.pretty_print_);

  EXPECT_TRUE(test_impl_.SetUp());
}

TEST_F(ReorderAppTest, ParseRandomOrderCommandLine) {
  cmd_line_.AppendSwitchPath(
      TestReorderApp::kInstrumentedDll, instrumented_image_path_);
  cmd_line_.AppendSwitchPath(TestReorderApp::kOutputFile, output_file_path_);
  cmd_line_.AppendSwitchASCII(
      TestReorderApp::kSeed, base::StringPrintf("%d", seed_));

  ASSERT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));

  EXPECT_EQ(TestReorderApp::kRandomOrderMode, test_impl_.mode_);
  EXPECT_TRUE(test_impl_.input_image_path_.empty());
  EXPECT_EQ(abs_instrumented_image_path_, test_impl_.instrumented_image_path_);
  EXPECT_EQ(abs_output_file_path_, test_impl_.output_file_path_);
  EXPECT_EQ(seed_, test_impl_.seed_);
  EXPECT_TRUE(test_impl_.trace_file_paths_.empty());
  EXPECT_FALSE(test_impl_.pretty_print_);

  EXPECT_TRUE(test_impl_.SetUp());
}

TEST_F(ReorderAppTest, ParseRandomOrderWithTraceFilesFails) {
  cmd_line_.AppendSwitchPath(
      TestReorderApp::kInstrumentedImage, instrumented_image_path_);
  cmd_line_.AppendSwitchPath(TestReorderApp::kOutputFile, output_file_path_);
  cmd_line_.AppendSwitchASCII(
      TestReorderApp::kSeed, base::StringPrintf("%d", seed_));
  cmd_line_.AppendArgPath(trace_file_path_);

  ASSERT_FALSE(test_impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(ReorderAppTest, ParseDeadCodeFinderCommandLine) {
  cmd_line_.AppendSwitchPath(
      TestReorderApp::kInstrumentedDll, instrumented_image_path_);
  cmd_line_.AppendSwitchPath(TestReorderApp::kOutputFile, output_file_path_);
  cmd_line_.AppendSwitch(TestReorderApp::kListDeadCode);
  cmd_line_.AppendSwitch(TestReorderApp::kPrettyPrint);
  cmd_line_.AppendArgPath(trace_file_path_);

  ASSERT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));

  EXPECT_EQ(TestReorderApp::kDeadCodeFinderMode, test_impl_.mode_);
  EXPECT_TRUE(test_impl_.input_image_path_.empty());
  EXPECT_EQ(abs_instrumented_image_path_, test_impl_.instrumented_image_path_);
  EXPECT_EQ(abs_output_file_path_, test_impl_.output_file_path_);
  EXPECT_EQ(abs_trace_file_path_, test_impl_.trace_file_paths_.front());
  EXPECT_EQ(0U, test_impl_.seed_);
  EXPECT_TRUE(test_impl_.pretty_print_);

  EXPECT_TRUE(test_impl_.SetUp());
}

TEST_F(ReorderAppTest, LinearOrderEndToEnd) {
  cmd_line_.AppendSwitchPath(
      TestReorderApp::kInstrumentedImage, instrumented_image_path_);
  cmd_line_.AppendSwitchPath(TestReorderApp::kOutputFile, output_file_path_);
  cmd_line_.AppendSwitchPath(TestReorderApp::kInputImage, input_image_path_);
  cmd_line_.AppendSwitchPath(
      TestReorderApp::kBasicBlockEntryCounts, bb_entry_count_file_path_);
  cmd_line_.AppendSwitch(TestReorderApp::kPrettyPrint);
  cmd_line_.AppendArgPath(trace_file_path_);

  ASSERT_EQ(0, test_app_.Run());
}

TEST_F(ReorderAppTest, LinearOrderWithBasicBlockTrace) {
  cmd_line_.AppendSwitchPath(
      TestReorderApp::kInstrumentedImage, instrumented_image_path_);
  cmd_line_.AppendSwitchPath(TestReorderApp::kOutputFile, output_file_path_);
  cmd_line_.AppendSwitchPath(TestReorderApp::kInputImage, input_image_path_);
  cmd_line_.AppendSwitchPath(
      TestReorderApp::kBasicBlockEntryCounts, bb_entry_count_file_path_);
  cmd_line_.AppendSwitch(TestReorderApp::kPrettyPrint);
  cmd_line_.AppendArgPath(trace_file_path_);

  // Adding a Basic Block traces should be valid, and ignored.
  base::FilePath abs_bbtrace_file_path =
      testing::GetExeTestDataRelativePath(testing::kBBEntryTraceFiles[0]);
  base::FilePath bbtrace_file_path =
    testing::GetRelativePath(abs_bbtrace_file_path);
  cmd_line_.AppendArgPath(abs_bbtrace_file_path);

  ASSERT_EQ(0, test_app_.Run());
}

}  // namespace reorder
