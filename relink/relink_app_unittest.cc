// Copyright 2012 Google Inc.
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

#include "syzygy/relink/relink_app.h"

#include "base/stringprintf.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/block_graph/unittest_util.h"
#include "syzygy/common/unittest_util.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/pe_utils.h"
#include "syzygy/pe/unittest_util.h"

namespace relink {

using block_graph::BlockGraph;
using common::Application;
using core::RelativeAddress;
using ::testing::ScopedLogLevelSaver;

namespace {

class TestRelinkApp : public RelinkApp {
 public:
  using RelinkApp::input_dll_path_;
  using RelinkApp::input_pdb_path_;
  using RelinkApp::output_dll_path_;
  using RelinkApp::output_pdb_path_;
  using RelinkApp::order_file_path_;
  using RelinkApp::seed_;
  using RelinkApp::padding_;
  using RelinkApp::augment_pdb_;
  using RelinkApp::compress_pdb_;
  using RelinkApp::strip_strings_;
  using RelinkApp::output_metadata_;
  using RelinkApp::overwrite_;
};

typedef common::Application<TestRelinkApp> TestApp;

class RelinkAppTest : public testing::PELibUnitTest {
 public:
  typedef testing::PELibUnitTest Super;

  RelinkAppTest()
      : cmd_line_(FilePath(L"relink.exe")),
        test_impl_(test_app_.implementation()),
        seed_(1234567),
        padding_(32),
        augment_pdb_(false),
        compress_pdb_(false),
        strip_strings_(false),
        output_metadata_(false),
        overwrite_(false) {
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
    abs_input_dll_path_ = testing::GetExeRelativePath(kDllName);
    input_dll_path_ = testing::GetRelativePath(abs_input_dll_path_);
    abs_input_pdb_path_ = testing::GetExeRelativePath(kDllPdbName);
    input_pdb_path_ = testing::GetRelativePath(abs_input_pdb_path_);
    output_dll_path_ = temp_dir_.Append(input_dll_path_.BaseName());
    output_pdb_path_ = temp_dir_.Append(input_pdb_path_.BaseName());
    order_file_path_ = temp_dir_.Append(L"order.json");

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
  FilePath temp_dir_;
  FilePath stdin_path_;
  FilePath stdout_path_;
  FilePath stderr_path_;
  // @}

  // @name Command-line and parameters.
  // @{
  CommandLine cmd_line_;
  FilePath input_dll_path_;
  FilePath input_pdb_path_;
  FilePath output_dll_path_;
  FilePath output_pdb_path_;
  FilePath order_file_path_;
  uint32 seed_;
  size_t padding_;
  bool augment_pdb_;
  bool compress_pdb_;
  bool strip_strings_;
  bool output_metadata_;
  bool overwrite_;
  // @}

  // @name Expected final values of input parameters.
  // @{
  FilePath abs_input_dll_path_;
  FilePath abs_input_pdb_path_;
  // @}
};

}  // namespace

TEST_F(RelinkAppTest, GetHelp) {
  cmd_line_.AppendSwitch("help");
  ASSERT_FALSE(test_impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(RelinkAppTest, EmptyCommandLineFails) {
  ASSERT_FALSE(test_impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(RelinkAppTest, ParseWithNeitherInputNorOrderFails) {
  cmd_line_.AppendSwitchPath("output-dll", output_dll_path_);

  ASSERT_FALSE(test_impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(RelinkAppTest, ParseWithSeedAndOrderFails) {
  cmd_line_.AppendSwitchPath("output-dll", output_dll_path_);
  cmd_line_.AppendSwitchASCII("seed", base::StringPrintf("%d", seed_));
  cmd_line_.AppendSwitchPath("order_file", order_file_path_);

  ASSERT_FALSE(test_impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(RelinkAppTest, ParseWithEmptySeedFails) {
  cmd_line_.AppendSwitchPath("output-dll", output_dll_path_);
  cmd_line_.AppendSwitch("seed");

  ASSERT_FALSE(test_impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(RelinkAppTest, ParseWithInvalidSeedFails) {
  cmd_line_.AppendSwitchPath("output-dll", output_dll_path_);
  cmd_line_.AppendSwitchASCII("seed", "hello");

  ASSERT_FALSE(test_impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(RelinkAppTest, ParseWithEmptyPaddingFails) {
  cmd_line_.AppendSwitchPath("output-dll", output_dll_path_);
  cmd_line_.AppendSwitch("padding");

  ASSERT_FALSE(test_impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(RelinkAppTest, ParseWithInvalidPaddingFails) {
  cmd_line_.AppendSwitchPath("output-dll", output_dll_path_);
  cmd_line_.AppendSwitchASCII("padding", "hello");

  ASSERT_FALSE(test_impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(RelinkAppTest, ParseMinimalCommandLineWithInputDll) {
  cmd_line_.AppendSwitchPath("input-dll", input_dll_path_);
  cmd_line_.AppendSwitchPath("output-dll", output_dll_path_);

  EXPECT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  EXPECT_TRUE(test_impl_.SetUp());
}

TEST_F(RelinkAppTest, ParseMinimalCommandLineWithOrderFile) {
  // The order file doesn't actually exist, so setup should fail to infer the
  // input dll.
  cmd_line_.AppendSwitchPath("order-file", order_file_path_);
  cmd_line_.AppendSwitchPath("output-dll", output_dll_path_);

  EXPECT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  EXPECT_FALSE(test_impl_.SetUp());
}

TEST_F(RelinkAppTest, ParseFullCommandLineWithOrderFile) {
  // Note that we specify the no-metadata flag, so we expect false below
  // for the output_metadata_ member. Also note that neither seed nor padding
  // are given, and should default to 0.
  cmd_line_.AppendSwitchPath("output-dll", output_dll_path_);
  cmd_line_.AppendSwitchPath("output-pdb", output_pdb_path_);
  cmd_line_.AppendSwitchPath("order-file", order_file_path_);
  cmd_line_.AppendSwitch("augment-pdb");
  cmd_line_.AppendSwitch("compress-pdb");
  cmd_line_.AppendSwitch("strip-strings");
  cmd_line_.AppendSwitch("no-metadata");
  cmd_line_.AppendSwitch("overwrite");

  EXPECT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  EXPECT_TRUE(test_impl_.input_dll_path_.empty());
  EXPECT_TRUE(test_impl_.input_pdb_path_.empty());
  EXPECT_EQ(output_dll_path_, test_impl_.output_dll_path_);
  EXPECT_EQ(output_pdb_path_, test_impl_.output_pdb_path_);
  EXPECT_EQ(order_file_path_, test_impl_.order_file_path_);
  EXPECT_EQ(0, test_impl_.seed_);
  EXPECT_EQ(0, test_impl_.padding_);
  EXPECT_TRUE(test_impl_.augment_pdb_);
  EXPECT_TRUE(test_impl_.compress_pdb_);
  EXPECT_TRUE(test_impl_.strip_strings_);
  EXPECT_FALSE(test_impl_.output_metadata_);
  EXPECT_TRUE(test_impl_.overwrite_);

  // The order file doesn't actually exist, so setup should fail to infer the
  // input dll.
  EXPECT_FALSE(test_impl_.SetUp());
}

TEST_F(RelinkAppTest, ParseFullCommandLineWithInputSeedAndMetadata) {
  // Note that we omit the no-metadata flag, so we expect true below for the
  // output_metadata_ member.
  cmd_line_.AppendSwitchPath("input-dll", input_dll_path_);
  cmd_line_.AppendSwitchPath("input-pdb", input_pdb_path_);
  cmd_line_.AppendSwitchPath("output-dll", output_dll_path_);
  cmd_line_.AppendSwitchPath("output-pdb", output_pdb_path_);
  cmd_line_.AppendSwitchASCII("seed", base::StringPrintf("%d", seed_));
  cmd_line_.AppendSwitchASCII("padding", base::StringPrintf("%d", padding_));
  cmd_line_.AppendSwitch("augment-pdb");
  cmd_line_.AppendSwitch("compress-pdb");
  cmd_line_.AppendSwitch("strip-strings");
  cmd_line_.AppendSwitch("overwrite");

  EXPECT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  EXPECT_EQ(abs_input_dll_path_, test_impl_.input_dll_path_);
  EXPECT_EQ(abs_input_pdb_path_, test_impl_.input_pdb_path_);
  EXPECT_EQ(output_dll_path_, test_impl_.output_dll_path_);
  EXPECT_EQ(output_pdb_path_, test_impl_.output_pdb_path_);
  EXPECT_TRUE(test_impl_.order_file_path_.empty());
  EXPECT_EQ(seed_, test_impl_.seed_);
  EXPECT_EQ(padding_, test_impl_.padding_);
  EXPECT_TRUE(test_impl_.augment_pdb_);
  EXPECT_TRUE(test_impl_.compress_pdb_);
  EXPECT_TRUE(test_impl_.strip_strings_);
  EXPECT_TRUE(test_impl_.output_metadata_);
  EXPECT_TRUE(test_impl_.overwrite_);

  // SetUp() has nothing else to infer so it should succeed.
  EXPECT_TRUE(test_impl_.SetUp());
}

TEST_F(RelinkAppTest, RandomRelink) {
  cmd_line_.AppendSwitchPath("input-dll", input_dll_path_);
  cmd_line_.AppendSwitchPath("input-pdb", input_pdb_path_);
  cmd_line_.AppendSwitchPath("output-dll", output_dll_path_);
  cmd_line_.AppendSwitchPath("output-pdb", output_pdb_path_);
  cmd_line_.AppendSwitchASCII("seed", base::StringPrintf("%d", seed_));
  cmd_line_.AppendSwitchASCII("padding", base::StringPrintf("%d", padding_));
  cmd_line_.AppendSwitch("overwrite");

  ASSERT_EQ(0, test_app_.Run());
  ASSERT_NO_FATAL_FAILURE(CheckTestDll(output_dll_path_));
}

TEST_F(RelinkAppTest, RandomRelinkBasicBlocks) {
  cmd_line_.AppendSwitchPath("input-dll", input_dll_path_);
  cmd_line_.AppendSwitchPath("input-pdb", input_pdb_path_);
  cmd_line_.AppendSwitchPath("output-dll", output_dll_path_);
  cmd_line_.AppendSwitchPath("output-pdb", output_pdb_path_);
  cmd_line_.AppendSwitchASCII("seed", base::StringPrintf("%d", seed_));
  cmd_line_.AppendSwitchASCII("padding", base::StringPrintf("%d", padding_));
  cmd_line_.AppendSwitch("overwrite");
  cmd_line_.AppendSwitch("basic-blocks");
  cmd_line_.AppendSwitch("exclude-bb-padding");

  ASSERT_EQ(0, test_app_.Run());
  ASSERT_NO_FATAL_FAILURE(CheckTestDll(output_dll_path_));
}

}  // namespace pe
