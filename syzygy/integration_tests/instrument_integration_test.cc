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

#include "base/environment.h"
#include "base/stringprintf.h"
#include "gtest/gtest.h"
#include "syzygy/common/unittest_util.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/instrument/instrument_app.h"
#include "syzygy/pe/unittest_util.h"
#include "syzygy/trace/protocol/call_trace_defs.h"

namespace integration_tests {

namespace {

using instrument::InstrumentApp;
typedef common::Application<InstrumentApp> TestApp;

class IntrumentAppIntegrationTest : public testing::PELibUnitTest {
 public:
  typedef testing::PELibUnitTest Super;

  IntrumentAppIntegrationTest()
      : cmd_line_(base::FilePath(L"instrument.exe")),
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
    base::FilePath abs_input_dll_path_ =
        testing::GetExeRelativePath(testing::kTestDllName);
    input_dll_path_ = testing::GetRelativePath(abs_input_dll_path_);
    output_dll_path_ = temp_dir_.Append(input_dll_path_.BaseName());

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

  // Runs an instrumentation pass in the given mode and validates that the
  // resulting output DLL loads.
  void EndToEndTest(const std::string& mode) {
    cmd_line_.AppendSwitchPath("input-image", input_dll_path_);
    cmd_line_.AppendSwitchPath("output-image", output_dll_path_);
    cmd_line_.AppendSwitchASCII("mode", mode);

    // Create the instrumented DLL.
    common::Application<instrument::InstrumentApp> app;
    ASSERT_NO_FATAL_FAILURE(ConfigureTestApp(&app));
    ASSERT_EQ(0, app.Run());

    // Make it non-mandatory that there be a trace service running.
    scoped_ptr<base::Environment> env(base::Environment::Create());
    std::string env_var;
    env->SetVar(
        ::kSyzygyRpcSessionMandatoryEnvVar,
        base::StringPrintf("%s,0;%s,0;%s,0;%s,0",
                           InstrumentApp::kAgentDllBasicBlockEntry,
                           InstrumentApp::kAgentDllCoverage,
                           InstrumentApp::kAgentDllProfile,
                           InstrumentApp::kAgentDllRpc));

    // Validate that the test dll loads post instrumentation.
    ASSERT_NO_FATAL_FAILURE(CheckTestDll(output_dll_path_));
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

  // @name Command-line and parameters.
  // @{
  CommandLine cmd_line_;
  base::FilePath input_dll_path_;
  base::FilePath output_dll_path_;
  // @}
};

}  // namespace

TEST_F(IntrumentAppIntegrationTest, AsanEndToEnd) {
  ASSERT_NO_FATAL_FAILURE(EndToEndTest("asan"));
}

TEST_F(IntrumentAppIntegrationTest, BBEntryEndToEnd) {
  ASSERT_NO_FATAL_FAILURE(EndToEndTest("bbentry"));
}

TEST_F(IntrumentAppIntegrationTest, CallTraceEndToEnd) {
  ASSERT_NO_FATAL_FAILURE(EndToEndTest("calltrace"));
}

TEST_F(IntrumentAppIntegrationTest, CoverageEndToEnd) {
  ASSERT_NO_FATAL_FAILURE(EndToEndTest("coverage"));
}

TEST_F(IntrumentAppIntegrationTest, ProfileEndToEnd) {
  ASSERT_NO_FATAL_FAILURE(EndToEndTest("profile"));
}

}  // integration_tests grinder
