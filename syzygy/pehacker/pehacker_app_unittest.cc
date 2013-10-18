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

#include "syzygy/pehacker/pehacker_app.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/pe/unittest_util.h"

namespace pehacker {

namespace {

class TestPEHackerApp : public PEHackerApp {
 public:
};

typedef common::Application<TestPEHackerApp> TestApp;

class PEHackerAppTest : public testing::PELibUnitTest {
 public:
  typedef testing::PELibUnitTest Super;

  PEHackerAppTest()
      : cmd_line_(base::FilePath(L"pehacker.exe")),
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

    ASSERT_NO_FATAL_FAILURE(ConfigureTestApp(&test_app_));
  }

  // Points the application at the fixture's command-line and IO streams.
  template<typename TestAppType>
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

  CommandLine cmd_line_;
};

}  // namespace

TEST_F(PEHackerAppTest, GetHelp) {
  cmd_line_.AppendSwitch("help");
  ASSERT_FALSE(test_impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(PEHackerAppTest, ParseCommandLine) {
  ASSERT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(PEHackerAppTest, Run) {
  ASSERT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  ASSERT_EQ(0, test_impl_.Run());
}

}  // namespace pehacker
