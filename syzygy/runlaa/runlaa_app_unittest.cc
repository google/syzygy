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

#include "syzygy/runlaa/runlaa_app.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/pe/unittest_util.h"

namespace runlaa {

namespace {

class TestRunLaaApp : public RunLaaApp {
 public:
  using RunLaaApp::expect_mode_;
  using RunLaaApp::is_laa_;
  using RunLaaApp::image_;
  using RunLaaApp::in_place_;
  using RunLaaApp::keep_temp_;
  using RunLaaApp::side_by_side_;
  using RunLaaApp::child_argv_;
};

typedef application::Application<TestRunLaaApp> TestApp;

class RunLaaAppTest : public testing::PELibUnitTest {
 public:
  typedef testing::PELibUnitTest Super;

  RunLaaAppTest()
      : cmd_line_(base::FilePath(L"runlaa.exe")),
        test_impl_(test_app_.implementation()) {}

  void SetUp() {
    Super::SetUp();

    logging::SetMinLogLevel(logging::LOG_ERROR);

    // Setup the IO streams.
    CreateTemporaryDir(&temp_dir_);
    stdin_path_ = temp_dir_.Append(L"NUL");
    stdout_path_ = temp_dir_.Append(L"stdout.txt");
    stderr_path_ = temp_dir_.Append(L"stderr.txt");
    InitStreams(stdin_path_, stdout_path_, stderr_path_);

    exe_path_ = testing::GetExeRelativePath(L"runlaa.exe");
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

  base::FilePath exe_path_;
  base::CommandLine cmd_line_;
};

}  // namespace

TEST_F(RunLaaAppTest, GetHelp) {
  cmd_line_.AppendSwitch("help");
  ASSERT_FALSE(test_impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(RunLaaAppTest, ParseEmptyCommandLineFails) {
  ASSERT_FALSE(test_impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(RunLaaAppTest, ParseMinimalCommandLineSucceeds) {
  cmd_line_.AppendSwitchPath("image", exe_path_);
  cmd_line_.AppendSwitchASCII("mode", "laa");
  ASSERT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  EXPECT_TRUE(test_impl_.expect_mode_.empty());
  EXPECT_EQ(exe_path_, test_impl_.image_);
  EXPECT_TRUE(test_impl_.is_laa_);
  EXPECT_FALSE(test_impl_.in_place_);
  EXPECT_FALSE(test_impl_.keep_temp_);
  EXPECT_FALSE(test_impl_.side_by_side_);
  EXPECT_TRUE(test_impl_.child_argv_.empty());
}

TEST_F(RunLaaAppTest, ParseMaximalCommandLineSucceeds) {
  cmd_line_.AppendSwitchPath("image", exe_path_);
  cmd_line_.AppendSwitch("in-place");
  cmd_line_.AppendSwitch("keep-temp");
  cmd_line_.AppendSwitch("side-by-side");
  cmd_line_.AppendSwitchASCII("mode", "nolaa");
  cmd_line_.AppendArg("--");
  cmd_line_.AppendArg("--foo");
  ASSERT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  EXPECT_TRUE(test_impl_.expect_mode_.empty());
  EXPECT_EQ(exe_path_, test_impl_.image_);
  EXPECT_FALSE(test_impl_.is_laa_);
  EXPECT_TRUE(test_impl_.in_place_);
  EXPECT_TRUE(test_impl_.keep_temp_);
  EXPECT_TRUE(test_impl_.side_by_side_);
  EXPECT_THAT(test_impl_.child_argv_, testing::Contains(L"--foo"));
}

TEST_F(RunLaaAppTest, ParseCommandLineInvalidModeFails) {
  cmd_line_.AppendSwitchPath("image", exe_path_);
  cmd_line_.AppendSwitchASCII("mode", "foo");
  ASSERT_FALSE(test_impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(RunLaaAppTest, ParseTestingCommandLineSucceeds) {
  cmd_line_.AppendSwitchASCII("expect-mode", "nolaa");
  ASSERT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  EXPECT_STREQ("nolaa", test_impl_.expect_mode_.c_str());
}

TEST_F(RunLaaAppTest, LaaModeSucceeds) {
  cmd_line_.AppendSwitchPath("image", exe_path_);
  cmd_line_.AppendSwitchASCII("mode", "laa");
  cmd_line_.AppendSwitch("side-by-side");
  cmd_line_.AppendArg("--");
  cmd_line_.AppendArg("--expect-mode=laa");
  ASSERT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  EXPECT_EQ(0, test_impl_.Run());
}

TEST_F(RunLaaAppTest, NoLaaModeSucceeds) {
  cmd_line_.AppendSwitchPath("image", exe_path_);
  cmd_line_.AppendSwitchASCII("mode", "nolaa");
  cmd_line_.AppendSwitch("side-by-side");
  cmd_line_.AppendArg("--");
  cmd_line_.AppendArg("--expect-mode=nolaa");
  ASSERT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  EXPECT_EQ(0, test_impl_.Run());
}

TEST_F(RunLaaAppTest, LaaModeUnexpected) {
  cmd_line_.AppendSwitchPath("image", exe_path_);
  cmd_line_.AppendSwitchASCII("mode", "laa");
  cmd_line_.AppendSwitch("side-by-side");
  cmd_line_.AppendArg("--");
  cmd_line_.AppendArg("--expect-mode=nolaa");
  ASSERT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  EXPECT_EQ(1, test_impl_.Run());
}

TEST_F(RunLaaAppTest, NoLaaModeUnexpected) {
  cmd_line_.AppendSwitchPath("image", exe_path_);
  cmd_line_.AppendSwitchASCII("mode", "nolaa");
  cmd_line_.AppendSwitch("side-by-side");
  cmd_line_.AppendArg("--");
  cmd_line_.AppendArg("--expect-mode=laa");
  ASSERT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  EXPECT_EQ(1, test_impl_.Run());
}

}  // namespace runlaa
