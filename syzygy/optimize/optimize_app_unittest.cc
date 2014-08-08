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

#include "syzygy/optimize/optimize_app.h"

#include "base/strings/stringprintf.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/common/unittest_util.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/pe_utils.h"
#include "syzygy/pe/unittest_util.h"

namespace optimize {

using common::Application;
using ::testing::ScopedLogLevelSaver;

namespace {

class TestOptimizeApp : public OptimizeApp {
 public:
  using OptimizeApp::input_image_path_;
  using OptimizeApp::input_pdb_path_;
  using OptimizeApp::output_image_path_;
  using OptimizeApp::output_pdb_path_;
  using OptimizeApp::branch_file_path_;
  using OptimizeApp::unreachable_graph_path_;
  using OptimizeApp::basic_block_reorder_;
  using OptimizeApp::block_alignment_;
  using OptimizeApp::fuzz_;
  using OptimizeApp::inlining_;
  using OptimizeApp::allow_inline_assembly_;
  using OptimizeApp::peephole_;
  using OptimizeApp::overwrite_;
};

typedef common::Application<TestOptimizeApp> TestApp;

class OptimizeAppTest : public testing::PELibUnitTest {
 public:
  typedef testing::PELibUnitTest Super;

  OptimizeAppTest()
      : cmd_line_(base::FilePath(L"optimize.exe")),
        test_impl_(test_app_.implementation()) {
  }

  void SetUp() {
    Super::SetUp();

    // Several of the tests generate progress and (deliberate) error messages
    // that would otherwise clutter the unittest output.
    logging::SetMinLogLevel(logging::LOG_FATAL);

    // Setup the IO streams.
    CreateTemporaryDir(&temp_dir_);
    stdin_path_ = temp_dir_.Append(L"NUL");
    stdout_path_ = temp_dir_.Append(L"stdout.txt");
    stderr_path_ = temp_dir_.Append(L"stderr.txt");
    InitStreams(stdin_path_, stdout_path_, stderr_path_);

    // Initialize the (potential) input and output path values.
    abs_input_image_path_ = testing::GetExeRelativePath(testing::kTestDllName);
    input_image_path_ = testing::GetRelativePath(abs_input_image_path_);
    abs_input_pdb_path_ = testing::GetExeRelativePath(testing::kTestDllPdbName);
    input_pdb_path_ = testing::GetRelativePath(abs_input_pdb_path_);
    output_image_path_ = temp_dir_.Append(input_image_path_.BaseName());
    output_pdb_path_ = temp_dir_.Append(input_pdb_path_.BaseName());
    branch_file_path_ = temp_dir_.Append(L"branch.json");
    unreachable_graph_path_ = temp_dir_.Append(L"unreachable.callgrind");

    // Point the application at the test's command-line and IO streams.
    test_app_.set_command_line(&cmd_line_);
    test_app_.set_in(in());
    test_app_.set_out(out());
    test_app_.set_err(err());
  }

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
  base::FilePath input_image_path_;
  base::FilePath input_pdb_path_;
  base::FilePath output_image_path_;
  base::FilePath output_pdb_path_;
  base::FilePath branch_file_path_;
  base::FilePath unreachable_graph_path_;
  // @}

  // @name Expected final values of input parameters.
  // @{
  base::FilePath abs_input_image_path_;
  base::FilePath abs_input_pdb_path_;
  // @}
};

}  // namespace

TEST_F(OptimizeAppTest, GetHelp) {
  cmd_line_.AppendSwitch("help");
  ASSERT_FALSE(test_impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(OptimizeAppTest, EmptyCommandLineFails) {
  ASSERT_FALSE(test_impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(OptimizeAppTest, ParseWithNoInputFails) {
  cmd_line_.AppendSwitchPath("output-image", output_image_path_);

  ASSERT_FALSE(test_impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(OptimizeAppTest, ParseWithNoOutputFails) {
  cmd_line_.AppendSwitchPath("input-image", output_image_path_);

  ASSERT_FALSE(test_impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(OptimizeAppTest, ParseMinimalCommandLineWithInputAndOutput) {
  cmd_line_.AppendSwitchPath("input-image", input_image_path_);
  cmd_line_.AppendSwitchPath("output-image", output_image_path_);

  EXPECT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  EXPECT_TRUE(test_impl_.SetUp());
}

TEST_F(OptimizeAppTest, ParseMinimalCommandLineWithBranchFile) {
  cmd_line_.AppendSwitchPath("branch-file", branch_file_path_);
  cmd_line_.AppendSwitchPath("input-image", input_image_path_);
  cmd_line_.AppendSwitchPath("output-image", output_image_path_);
  EXPECT_FALSE(test_impl_.overwrite_);
  EXPECT_FALSE(test_impl_.inlining_);
  EXPECT_FALSE(test_impl_.allow_inline_assembly_);
  EXPECT_FALSE(test_impl_.block_alignment_);
  EXPECT_FALSE(test_impl_.basic_block_reorder_);
  EXPECT_FALSE(test_impl_.peephole_);
  EXPECT_FALSE(test_impl_.fuzz_);

  EXPECT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  EXPECT_TRUE(test_impl_.SetUp());
}

TEST_F(OptimizeAppTest, ParseFullCommandLineWithBranchFile) {
  cmd_line_.AppendSwitchPath("input-image", input_image_path_);
  cmd_line_.AppendSwitchPath("output-image", output_image_path_);
  cmd_line_.AppendSwitchPath("output-pdb", output_pdb_path_);
  cmd_line_.AppendSwitchPath("branch-file", branch_file_path_);
  cmd_line_.AppendSwitch("overwrite");

  EXPECT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  EXPECT_FALSE(test_impl_.input_image_path_.empty());
  EXPECT_TRUE(test_impl_.input_pdb_path_.empty());
  EXPECT_EQ(output_image_path_, test_impl_.output_image_path_);
  EXPECT_EQ(output_pdb_path_, test_impl_.output_pdb_path_);
  EXPECT_EQ(branch_file_path_, test_impl_.branch_file_path_);
  EXPECT_TRUE(test_impl_.overwrite_);

  EXPECT_TRUE(test_impl_.SetUp());
}

TEST_F(OptimizeAppTest, ParseFullCommandLineWithInputAndOutputPdb) {
  cmd_line_.AppendSwitchPath("input-image", input_image_path_);
  cmd_line_.AppendSwitchPath("input-pdb", input_pdb_path_);
  cmd_line_.AppendSwitchPath("output-image", output_image_path_);
  cmd_line_.AppendSwitchPath("output-pdb", output_pdb_path_);
  cmd_line_.AppendSwitch("overwrite");
  cmd_line_.AppendSwitch("inlining");
  cmd_line_.AppendSwitch("allow-inline-assembly");
  cmd_line_.AppendSwitch("block-alignment");
  cmd_line_.AppendSwitch("basic-block-reorder");
  cmd_line_.AppendSwitch("peephole");
  cmd_line_.AppendSwitch("fuzz");

  EXPECT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  EXPECT_EQ(abs_input_image_path_, test_impl_.input_image_path_);
  EXPECT_EQ(abs_input_pdb_path_, test_impl_.input_pdb_path_);
  EXPECT_EQ(output_image_path_, test_impl_.output_image_path_);
  EXPECT_EQ(output_pdb_path_, test_impl_.output_pdb_path_);
  EXPECT_TRUE(test_impl_.overwrite_);
  EXPECT_TRUE(test_impl_.inlining_);
  EXPECT_TRUE(test_impl_.allow_inline_assembly_);
  EXPECT_TRUE(test_impl_.block_alignment_);
  EXPECT_TRUE(test_impl_.basic_block_reorder_);
  EXPECT_TRUE(test_impl_.peephole_);
  EXPECT_TRUE(test_impl_.fuzz_);

  EXPECT_TRUE(test_impl_.SetUp());
}

TEST_F(OptimizeAppTest, ParseAllCommandLineWithInputAndOutputPdb) {
  cmd_line_.AppendSwitchPath("input-image", input_image_path_);
  cmd_line_.AppendSwitchPath("input-pdb", input_pdb_path_);
  cmd_line_.AppendSwitchPath("output-image", output_image_path_);
  cmd_line_.AppendSwitchPath("output-pdb", output_pdb_path_);
  cmd_line_.AppendSwitch("overwrite");
  cmd_line_.AppendSwitch("all");

  EXPECT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  EXPECT_EQ(abs_input_image_path_, test_impl_.input_image_path_);
  EXPECT_EQ(abs_input_pdb_path_, test_impl_.input_pdb_path_);
  EXPECT_EQ(output_image_path_, test_impl_.output_image_path_);
  EXPECT_EQ(output_pdb_path_, test_impl_.output_pdb_path_);
  EXPECT_TRUE(test_impl_.overwrite_);
  EXPECT_TRUE(test_impl_.inlining_);
  EXPECT_TRUE(test_impl_.block_alignment_);
  EXPECT_TRUE(test_impl_.basic_block_reorder_);
  EXPECT_TRUE(test_impl_.block_alignment_);
  EXPECT_TRUE(test_impl_.peephole_);
  EXPECT_FALSE(test_impl_.fuzz_);

  EXPECT_TRUE(test_impl_.SetUp());
}

TEST_F(OptimizeAppTest, ParseCommandLineWithUnreachableGraph) {
  cmd_line_.AppendSwitchPath("input-image", input_image_path_);
  cmd_line_.AppendSwitchPath("output-image", output_image_path_);
  cmd_line_.AppendSwitch("unreachable-block");
  cmd_line_.AppendSwitchPath("dump-unreachable-graph", unreachable_graph_path_);
  cmd_line_.AppendSwitch("overwrite");

  EXPECT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  EXPECT_FALSE(test_impl_.input_image_path_.empty());
  EXPECT_EQ(output_image_path_, test_impl_.output_image_path_);
  EXPECT_EQ(unreachable_graph_path_, test_impl_.unreachable_graph_path_);
  EXPECT_TRUE(test_impl_.overwrite_);

  EXPECT_TRUE(test_impl_.SetUp());
}

TEST_F(OptimizeAppTest, RelinkDecompose) {
  cmd_line_.AppendSwitchPath("input-image", input_image_path_);
  cmd_line_.AppendSwitchPath("output-image", output_image_path_);
  cmd_line_.AppendSwitch("overwrite");

  ASSERT_EQ(0, test_app_.Run());
  ASSERT_NO_FATAL_FAILURE(CheckTestDll(output_image_path_));
}

}  // namespace optimize
