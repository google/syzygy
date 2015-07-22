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

#include "syzygy/poirot/poirot_app.h"

#include "gtest/gtest.h"
#include "syzygy/common/unittest_util.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/poirot/unittest_util.h"

namespace poirot {

namespace {

class TestPoirotApp : public PoirotApp {
 public:
  using PoirotApp::input_minidump_;
  using PoirotApp::output_file_;
};

typedef application::Application<TestPoirotApp> TestApp;

class PoirotAppTest : public testing::ApplicationTestBase {
 public:
  typedef testing::ApplicationTestBase Super;

  PoirotAppTest()
      : cmd_line_(base::FilePath(L"poirot.exe")),
        test_impl_(test_app_.implementation()) {}

  void SetUp() override {
    Super::SetUp();

    logging::SetMinLogLevel(logging::LOG_ERROR);

    // Setup the IO streams.
    CreateTemporaryDir(&temp_dir_);
    stdin_path_ = temp_dir_.Append(L"NUL");
    stdout_path_ = temp_dir_.Append(L"stdout.txt");
    stderr_path_ = temp_dir_.Append(L"stderr.txt");
    InitStreams(stdin_path_, stdout_path_, stderr_path_);

    ASSERT_NO_FATAL_FAILURE(ConfigureTestApp(&test_app_));
  }

  // Points the application at the fixture's command-line and IO streams.
  template <typename TestAppType>
  void ConfigureTestApp(TestAppType* test_app) {
    test_app->set_command_line(&cmd_line_);
    test_app->set_in(in());
    test_app->set_out(out());
    test_app->set_err(err());
  }

  // Stashes the current log-level before each test instance and restores it
  // after each test completes.
  testing::ScopedLogLevelSaver log_level_saver;

  // @name The application under test.
  // @{
  TestApp test_app_;
  TestApp::Implementation& test_impl_;
  base::FilePath temp_dir_;
  base::FilePath stdin_path_;
  base::FilePath stdout_path_;
  base::FilePath stderr_path_;
  // @}

  base::CommandLine cmd_line_;
};

}  // namespace

TEST_F(PoirotAppTest, GetHelp) {
  cmd_line_.AppendSwitch("help");
  EXPECT_FALSE(test_impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(PoirotAppTest, ParseEmptyCommandLineFails) {
  EXPECT_FALSE(test_impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(PoirotAppTest, ParseMinimalCommandLineSucceeds) {
  cmd_line_.AppendSwitchPath("input-minidump",
      testing::GetSrcRelativePath(testing::kMinidumpUAF));
  EXPECT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  EXPECT_SAME_FILE(test_impl_.input_minidump_,
                   testing::GetSrcRelativePath(testing::kMinidumpUAF));
}

TEST_F(PoirotAppTest, ParseFullCommandLineSucceeds) {
  cmd_line_.AppendSwitchPath("input-minidump",
      testing::GetSrcRelativePath(testing::kMinidumpUAF));
  cmd_line_.AppendSwitchPath("output-file", temp_dir_.Append(L"foo.log"));
  EXPECT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  EXPECT_SAME_FILE(testing::GetSrcRelativePath(testing::kMinidumpUAF),
                   test_impl_.input_minidump_);
  EXPECT_SAME_FILE(temp_dir_.Append(L"foo.log"), test_impl_.output_file_);
}

TEST_F(PoirotAppTest, ProcessValidFileSucceeds) {
  cmd_line_.AppendSwitchPath("input-minidump",
      testing::GetSrcRelativePath(testing::kMinidumpUAF));
  EXPECT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  EXPECT_EQ(0, test_impl_.Run());
}

TEST_F(PoirotAppTest, ProcessFileWithNoKaskoStreamFails) {
  cmd_line_.AppendSwitchPath("input-minidump",
      testing::GetSrcRelativePath(testing::kMinidumpNoKaskoStream));
  EXPECT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  EXPECT_NE(0, test_impl_.Run());
}

TEST_F(PoirotAppTest, ProcessNonExistingFileFails) {
  cmd_line_.AppendSwitchPath("input-minidump",
      testing::GetSrcRelativePath(testing::kMinidumpInvalidPath));
  EXPECT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  EXPECT_NE(0, test_impl_.Run());
}

TEST_F(PoirotAppTest, WriteJsonOutput) {
  base::FilePath temp_file;
  EXPECT_TRUE(base::CreateTemporaryFileInDir(temp_dir_, &temp_file));
  cmd_line_.AppendSwitchPath("input-minidump",
      testing::GetSrcRelativePath(testing::kMinidumpUAF));
  cmd_line_.AppendSwitchPath("output-file", temp_file);
  std::string file_content;
  EXPECT_TRUE(base::ReadFileToString(temp_file, &file_content));
  EXPECT_TRUE(file_content.empty());
  EXPECT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  EXPECT_EQ(0, test_impl_.Run());
  EXPECT_TRUE(base::ReadFileToString(temp_file, &file_content));
  EXPECT_FALSE(file_content.empty());
}

}  // namespace poirot
