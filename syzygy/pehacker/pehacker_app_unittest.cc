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

#include "base/strings/utf_string_conversions.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/unittest_util.h"

namespace pehacker {

namespace {

static wchar_t kConfigBadPathDoesNotExist[] =
    L"syzygy/pehacker/test_data/config-bad-path-does-not-exist.txt";
static wchar_t kConfigBadEmpty[] =
    L"syzygy/pehacker/test_data/config-bad-empty.txt";
static wchar_t kConfigBadNotJson[] =
    L"syzygy/pehacker/test_data/config-bad-not-json.txt";
static wchar_t kConfigBadList[] =
    L"syzygy/pehacker/test_data/config-bad-list.txt";
static wchar_t kConfigBadString[] =
    L"syzygy/pehacker/test_data/config-bad-string.txt";
static wchar_t kConfigBadCircularVariables[] =
    L"syzygy/pehacker/test_data/config-circular-variables.txt";
static wchar_t kConfigGoodMinimal[] =
    L"syzygy/pehacker/test_data/config-good-minimal.txt";
static wchar_t kConfigGoodExistingOutput[] =
    L"syzygy/pehacker/test_data/config-good-existing-output.txt";
static wchar_t kConfigGoodDefaultValue[] =
    L"syzygy/pehacker/test_data/config-good-default-value.txt";
static wchar_t kConfigGoodNestedVariables[] =
    L"syzygy/pehacker/test_data/config-good-nested-variables.txt";
static wchar_t kConfigGoodNop[] =
    L"syzygy/pehacker/test_data/config-good-nop.txt";

class TestPEHackerApp : public PEHackerApp {
 public:
  using PEHackerApp::LoadAndValidateConfigurationFile;

  using PEHackerApp::config_file_;
  using PEHackerApp::overwrite_;
  using PEHackerApp::variables_;
  using PEHackerApp::config_;
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

  CommandLine cmd_line_;
  base::FilePath config_file_;
};

}  // namespace

TEST_F(PEHackerAppTest, GetHelp) {
  cmd_line_.AppendSwitch("help");
  ASSERT_FALSE(test_impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(PEHackerAppTest, ParseEmptyCommandLineFails) {
  ASSERT_FALSE(test_impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(PEHackerAppTest, ParseMinimalCommandLineSucceeds) {
  cmd_line_.AppendSwitchPath("config-file", config_file_);
  ASSERT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  EXPECT_EQ(config_file_, test_impl_.config_file_);
  EXPECT_FALSE(test_impl_.overwrite_);
}

TEST_F(PEHackerAppTest, ParseMinimalCommandLineSucceedsEmptyVariable) {
  cmd_line_.AppendSwitchPath("config-file", config_file_);
  cmd_line_.AppendSwitch("Dvar");
  ASSERT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  EXPECT_EQ(config_file_, test_impl_.config_file_);
  EXPECT_FALSE(test_impl_.overwrite_);

  std::string s;
  EXPECT_TRUE(test_impl_.variables_.GetString("var", &s));
  EXPECT_TRUE(s.empty());
}

TEST_F(PEHackerAppTest, ParseCommandLineFailsInvalidVariableName) {
  cmd_line_.AppendSwitchPath("config-file", config_file_);
  cmd_line_.AppendSwitchASCII("Dbad~variable-name", "true");
  ASSERT_FALSE(test_impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(PEHackerAppTest, ParseCommandLineFailsList) {
  cmd_line_.AppendSwitchPath("config-file", config_file_);
  cmd_line_.AppendSwitchASCII("Dvar", "[]");
  ASSERT_FALSE(test_impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(PEHackerAppTest, ParseCommandLineFailsDict) {
  cmd_line_.AppendSwitchPath("config-file", config_file_);
  cmd_line_.AppendSwitchASCII("Dvar", "{}");
  ASSERT_FALSE(test_impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(PEHackerAppTest, ParseCommandLineFailsDouble) {
  cmd_line_.AppendSwitchPath("config-file", config_file_);
  cmd_line_.AppendSwitchASCII("Dvar", "3.14");
  ASSERT_FALSE(test_impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(PEHackerAppTest, ParseFullCommandLineSucceeds) {
  cmd_line_.AppendSwitchPath("config-file", config_file_);
  cmd_line_.AppendSwitch("overwrite");
  cmd_line_.AppendSwitchASCII("Dvar1", "val1");
  cmd_line_.AppendSwitchASCII("Dvar2", "45");
  cmd_line_.AppendSwitchASCII("Dvar3", "\"string\"");
  cmd_line_.AppendSwitchASCII("Dvar4", "false");
  cmd_line_.AppendSwitchASCII("Dvar5", "");
  ASSERT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  EXPECT_EQ(config_file_, test_impl_.config_file_);
  EXPECT_TRUE(test_impl_.overwrite_);

  std::string s;
  int i = 0;
  double d = 0;
  bool b = false;

  EXPECT_TRUE(test_impl_.variables_.GetString("var1", &s));
  EXPECT_EQ("val1", s);

  EXPECT_TRUE(test_impl_.variables_.GetInteger("var2", &i));
  EXPECT_EQ(45, i);

  EXPECT_TRUE(test_impl_.variables_.GetString("var3", &s));
  EXPECT_EQ("string", s);

  EXPECT_TRUE(test_impl_.variables_.GetBoolean("var4", &b));
  EXPECT_FALSE(b);

  EXPECT_TRUE(test_impl_.variables_.GetString("var5", &s));
  EXPECT_TRUE(s.empty());
}

TEST_F(PEHackerAppTest, ConfigurationFailsPathDoesNotExist) {
  config_file_ = testing::GetSrcRelativePath(kConfigBadPathDoesNotExist);
  cmd_line_.AppendSwitchPath("config-file", config_file_);
  ASSERT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  ASSERT_FALSE(test_impl_.LoadAndValidateConfigurationFile());
}

TEST_F(PEHackerAppTest, ConfigurationFailsEmpty) {
  config_file_ = testing::GetSrcRelativePath(kConfigBadEmpty);
  cmd_line_.AppendSwitchPath("config-file", config_file_);
  ASSERT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  ASSERT_FALSE(test_impl_.LoadAndValidateConfigurationFile());
}

TEST_F(PEHackerAppTest, ConfigurationFailsNotJson) {
  config_file_ = testing::GetSrcRelativePath(kConfigBadNotJson);
  cmd_line_.AppendSwitchPath("config-file", config_file_);
  ASSERT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  ASSERT_FALSE(test_impl_.LoadAndValidateConfigurationFile());
}

TEST_F(PEHackerAppTest, ConfigurationFailsList) {
  config_file_ = testing::GetSrcRelativePath(kConfigBadList);
  cmd_line_.AppendSwitchPath("config-file", config_file_);
  ASSERT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  ASSERT_FALSE(test_impl_.LoadAndValidateConfigurationFile());
}

TEST_F(PEHackerAppTest, ConfigurationFailsString) {
  config_file_ = testing::GetSrcRelativePath(kConfigBadString);
  cmd_line_.AppendSwitchPath("config-file", config_file_);
  ASSERT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  ASSERT_FALSE(test_impl_.LoadAndValidateConfigurationFile());
}

TEST_F(PEHackerAppTest, ConfigurationFailsCircularVariables) {
  config_file_ = testing::GetSrcRelativePath(kConfigBadCircularVariables);
  cmd_line_.AppendSwitchPath("config-file", config_file_);
  ASSERT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  ASSERT_FALSE(test_impl_.LoadAndValidateConfigurationFile());
}

TEST_F(PEHackerAppTest, ConfigurationLoadsMinimal) {
  config_file_ = testing::GetSrcRelativePath(kConfigGoodMinimal);
  cmd_line_.AppendSwitchPath("config-file", config_file_);
  ASSERT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  ASSERT_TRUE(test_impl_.LoadAndValidateConfigurationFile());

  std::string expected_root = base::WideToUTF8(
      config_file_.DirName().NormalizePathSeparators().value());
  std::string root;
  EXPECT_TRUE(test_impl_.variables_.GetString("ROOT", &root));
  EXPECT_EQ(expected_root, root);
}

TEST_F(PEHackerAppTest, ConfigurationFailsExistingOutput) {
  config_file_ = testing::GetSrcRelativePath(kConfigGoodExistingOutput);
  cmd_line_.AppendSwitchPath("config-file", config_file_);
  ASSERT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  ASSERT_FALSE(test_impl_.LoadAndValidateConfigurationFile());
}

TEST_F(PEHackerAppTest, ConfigurationLoadsExistingOutput) {
  config_file_ = testing::GetSrcRelativePath(kConfigGoodExistingOutput);
  cmd_line_.AppendSwitchPath("config-file", config_file_);
  cmd_line_.AppendSwitch("overwrite");
  ASSERT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  ASSERT_TRUE(test_impl_.LoadAndValidateConfigurationFile());
}

TEST_F(PEHackerAppTest, ConfigurationLoadsDefaultValue) {
  config_file_ = testing::GetSrcRelativePath(kConfigGoodDefaultValue);
  cmd_line_.AppendSwitchPath("config-file", config_file_);
  ASSERT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  ASSERT_TRUE(test_impl_.LoadAndValidateConfigurationFile());

  int i = 0;
  EXPECT_TRUE(test_impl_.variables_.GetInteger("var1", &i));
  EXPECT_EQ(42, i);
}

TEST_F(PEHackerAppTest, ConfigurationLoadsOverriddenDefaultValue) {
  config_file_ = testing::GetSrcRelativePath(kConfigGoodDefaultValue);
  cmd_line_.AppendSwitchPath("config-file", config_file_);
  cmd_line_.AppendSwitchASCII("Dvar1", "0");
  ASSERT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  ASSERT_TRUE(test_impl_.LoadAndValidateConfigurationFile());

  int i = 0;
  EXPECT_TRUE(test_impl_.variables_.GetInteger("var1", &i));
  EXPECT_EQ(0, i);
}

TEST_F(PEHackerAppTest, ConfigurationLoadsNestedVariables) {
  config_file_ = testing::GetSrcRelativePath(kConfigGoodNestedVariables);
  cmd_line_.AppendSwitchPath("config-file", config_file_);
  ASSERT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  ASSERT_TRUE(test_impl_.LoadAndValidateConfigurationFile());
}

TEST_F(PEHackerAppTest, RunNop) {
  base::FilePath input_module = testing::GetOutputRelativePath(
      testing::kTestDllName);
  base::FilePath output_module = temp_dir_.Append(testing::kTestDllName);

  config_file_ = testing::GetSrcRelativePath(kConfigGoodNop);
  cmd_line_.AppendSwitchPath("config-file", config_file_);
  cmd_line_.AppendSwitchPath("Dinput_module", input_module);
  cmd_line_.AppendSwitchPath("Doutput_module", output_module);
  ASSERT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));

  EXPECT_EQ(0, test_impl_.Run());
  EXPECT_TRUE(base::PathExists(output_module));
  EXPECT_NO_FATAL_FAILURE(CheckTestDll(output_module));
}

}  // namespace pehacker
