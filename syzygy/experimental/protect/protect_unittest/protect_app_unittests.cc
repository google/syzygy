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

#include "syzygy/experimental/protect/protect_lib/protect_app.h"

#include "base/strings/utf_string_conversions.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/unittest_util.h"

namespace protect {

namespace {
static wchar_t kConfigGoodExistingOutput[] =
  L"syzygy/experimental/protect/test_data/config-good-existing-output.txt";

class TestProtectApp : public ProtectApp {
public:
  using ProtectApp::overwrite_;
};

typedef application::Application<TestProtectApp> TestApp;

class ProtectAppTest : public testing::PELibUnitTest {
public:
  typedef testing::PELibUnitTest Super;

  ProtectAppTest()
    : cmd_line_(base::FilePath(L"protect.exe")),
    test_impl_(test_app_.implementation()) {
  }

  void SetUp() {
    Super::SetUp();

    logging::SetMinLogLevel(logging::LOG_ERROR);

    // Setup the IO streams.
    CreateTemporaryDir(&temp_dir_);
    stdin_path_ = temp_dir_.Append(L"NUL");
    stdout_path_ = temp_dir_.Append(L"stdout.txt");
    stderr_path_ = temp_dir_.Append(L"stderr.txt");
    InitStreams(stdin_path_, stdout_path_, stderr_path_);

    ASSERT_NO_FATAL_FAILURE(ConfigureTestApp(&test_app_));

    config_file_ = temp_dir_.Append(L"config.txt");
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

  base::CommandLine cmd_line_;
  base::FilePath config_file_;
};

}  // namespace

TEST_F(ProtectAppTest, ParseEmptyCommandLineFails) {
  ASSERT_FALSE(test_impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(ProtectAppTest, ConfigurationFailsExistingOutput) {
  base::FilePath input_module = testing::GetOutputRelativePath(
    testing::kTestDllName);
  base::FilePath output_module = temp_dir_.Append(testing::kTestDllName);

  config_file_ = testing::GetSrcRelativePath(kConfigGoodExistingOutput);
  cmd_line_.AppendSwitchPath("input-image", input_module);
  cmd_line_.AppendSwitchPath("output-image", output_module);
  cmd_line_.AppendSwitchPath("flummox-config-path", config_file_);
  ASSERT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(ProtectAppTest, ConfigurationLoadsExistingOutput) {
  base::FilePath input_module = testing::GetOutputRelativePath(
    testing::kTestDllName);
  base::FilePath output_module = temp_dir_.Append(testing::kTestDllName);

  config_file_ = testing::GetSrcRelativePath(kConfigGoodExistingOutput);
  cmd_line_.AppendSwitchPath("input-image", input_module);
  cmd_line_.AppendSwitchPath("output-image", output_module);
  cmd_line_.AppendSwitchPath("flummox-config-path", config_file_);
  cmd_line_.AppendSwitch("overwrite");
  ASSERT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
}

}  // namespace protect