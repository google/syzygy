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

#include "syzygy/zap_timestamp/zap_timestamp_app.h"

#include "gtest/gtest.h"
#include "syzygy/pe/unittest_util.h"

namespace zap_timestamp {

namespace {

class TestZapTimestampApp : public ZapTimestampApp {
 public:
  using ZapTimestampApp::zap_;
};

typedef application::Application<TestZapTimestampApp> TestApp;

class ZapTimestampAppTest : public testing::PELibUnitTest {
 public:
  typedef testing::PELibUnitTest Super;

  ZapTimestampAppTest()
      : cmd_line_(base::FilePath(L"zap_timestamp.exe")),
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

    // Point the application at the test's command-line and IO streams.
    test_app_.set_command_line(&cmd_line_);
    test_app_.set_in(in());
    test_app_.set_out(out());
    test_app_.set_err(err());
  }

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
  base::CommandLine cmd_line_;
};

}  // namespace

TEST_F(ZapTimestampAppTest, ParseEmptyCommandLine) {
  EXPECT_FALSE(test_impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(ZapTimestampAppTest, ParseHelp) {
  cmd_line_.AppendSwitch("help");
  EXPECT_FALSE(test_impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(ZapTimestampAppTest, ParseMinimalCommandLine) {
  base::FilePath input_image(L"foo.dll");
  cmd_line_.AppendSwitchPath("input-image", input_image);
  EXPECT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));

  EXPECT_EQ(input_image, test_impl_.zap_.input_image());
  EXPECT_TRUE(test_impl_.zap_.input_pdb().empty());
  EXPECT_TRUE(test_impl_.zap_.output_image().empty());
  EXPECT_TRUE(test_impl_.zap_.output_pdb().empty());
  EXPECT_TRUE(test_impl_.zap_.write_image());
  EXPECT_TRUE(test_impl_.zap_.write_pdb());
  EXPECT_FALSE(test_impl_.zap_.overwrite());
}

TEST_F(ZapTimestampAppTest, ParseMaximalCommandLine) {
  base::FilePath input_image(L"foo.dll");
  base::FilePath input_pdb(L"foo.dll");
  base::FilePath output_image(L"foo.dll");
  base::FilePath output_pdb(L"foo.dll");

  cmd_line_.AppendSwitchPath("input-image", input_image);
  cmd_line_.AppendSwitchPath("input-pdb", input_pdb);
  cmd_line_.AppendSwitchPath("output-image", output_image);
  cmd_line_.AppendSwitchPath("output-pdb", output_pdb);
  cmd_line_.AppendSwitch("no-write-image");
  cmd_line_.AppendSwitch("no-write-pdb");
  cmd_line_.AppendSwitch("overwrite");
  cmd_line_.AppendSwitchASCII("timestamp-value", "42");
  EXPECT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));

  EXPECT_EQ(input_image, test_impl_.zap_.input_image());
  EXPECT_EQ(input_pdb, test_impl_.zap_.input_pdb());
  EXPECT_EQ(output_image, test_impl_.zap_.output_image());
  EXPECT_EQ(output_pdb, test_impl_.zap_.output_pdb());
  EXPECT_FALSE(test_impl_.zap_.write_image());
  EXPECT_FALSE(test_impl_.zap_.write_pdb());
  EXPECT_TRUE(test_impl_.zap_.overwrite());
  EXPECT_EQ(42, test_impl_.zap_.timestamp_value());
}

}  // namespace zap_timestamp
