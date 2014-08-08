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

#include "syzygy/instrument/instrument_app.h"

#include "base/environment.h"
#include "base/strings/stringprintf.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/block_graph/unittest_util.h"
#include "syzygy/common/unittest_util.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/instrument/instrumenters/entry_thunk_instrumenter.h"
#include "syzygy/pe/pe_relinker.h"
#include "syzygy/pe/pe_utils.h"
#include "syzygy/pe/unittest_util.h"
#include "syzygy/trace/protocol/call_trace_defs.h"

namespace instrument {

namespace {

class TestInstrumentApp : public InstrumentApp {
 public:
  using InstrumentApp::instrumenter_;
};

typedef common::Application<TestInstrumentApp> TestApp;

class InstrumentAppTest : public testing::PELibUnitTest {
 public:
  typedef testing::PELibUnitTest Super;

  InstrumentAppTest()
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
    abs_input_dll_path_ = testing::GetExeRelativePath(testing::kTestDllName);
    input_dll_path_ = testing::GetRelativePath(abs_input_dll_path_);
    abs_input_pdb_path_ = testing::GetExeRelativePath(testing::kTestDllPdbName);
    input_pdb_path_ = testing::GetRelativePath(abs_input_pdb_path_);
    output_dll_path_ = temp_dir_.Append(input_dll_path_.BaseName());
    output_pdb_path_ = temp_dir_.Append(input_pdb_path_.BaseName());

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

  // @name Command-line and parameters.
  // @{
  CommandLine cmd_line_;
  base::FilePath input_dll_path_;
  base::FilePath input_pdb_path_;
  base::FilePath output_dll_path_;
  base::FilePath output_pdb_path_;
  // @}

  // @name Expected final values of input parameters.
  // @{
  base::FilePath abs_input_dll_path_;
  base::FilePath abs_input_pdb_path_;
  // @}
};

}  // namespace

TEST_F(InstrumentAppTest, GetHelp) {
  cmd_line_.AppendSwitch("help");
  ASSERT_FALSE(test_impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(InstrumentAppTest, EmptyCommandLineFails) {
  ASSERT_FALSE(test_impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(InstrumentAppTest, ParseWithNoInputImageFails) {
  cmd_line_.AppendSwitchPath("output-image", output_dll_path_);

  ASSERT_FALSE(test_impl_.ParseCommandLine(&cmd_line_));
  ASSERT_EQ(1, test_impl_.Run());
}

TEST_F(InstrumentAppTest, ParseWithNoOutputImageFails) {
  cmd_line_.AppendSwitchPath("input-image", input_dll_path_);

  ASSERT_FALSE(test_impl_.ParseCommandLine(&cmd_line_));
  ASSERT_EQ(1, test_impl_.Run());
}

TEST_F(InstrumentAppTest, DeprecatedParseNoModeSpecifyDlls) {
  cmd_line_.AppendSwitchPath("input-dll", input_dll_path_);
  cmd_line_.AppendSwitchPath("output-dll", output_dll_path_);

  EXPECT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  instrumenters::EntryThunkInstrumenter* entry_thunk_instrumenter =
      reinterpret_cast<instrumenters::EntryThunkInstrumenter*>
          (test_impl_.instrumenter_.get());
  ASSERT_TRUE(entry_thunk_instrumenter != NULL);
  ASSERT_EQ(instrumenters::EntryThunkInstrumenter::CALL_TRACE,
            entry_thunk_instrumenter->instrumentation_mode());
}

TEST_F(InstrumentAppTest, DeprecatedParseCallTraceClientRpc) {
  cmd_line_.AppendSwitchASCII("call-trace-client", "RPC");
  cmd_line_.AppendSwitchPath("input-dll", input_dll_path_);
  cmd_line_.AppendSwitchPath("output-dll", output_dll_path_);

  EXPECT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  instrumenters::EntryThunkInstrumenter* entry_thunk_instrumenter =
      reinterpret_cast<instrumenters::EntryThunkInstrumenter*>
          (test_impl_.instrumenter_.get());
  ASSERT_TRUE(entry_thunk_instrumenter != NULL);
  ASSERT_EQ(instrumenters::EntryThunkInstrumenter::CALL_TRACE,
            entry_thunk_instrumenter->instrumentation_mode());
}

TEST_F(InstrumentAppTest, DeprecatedParseCallTraceClientProfiler) {
  cmd_line_.AppendSwitchASCII("call-trace-client", "profiler");
  cmd_line_.AppendSwitchPath("input-dll", input_dll_path_);
  cmd_line_.AppendSwitchPath("output-dll", output_dll_path_);

  EXPECT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  instrumenters::EntryThunkInstrumenter* entry_thunk_instrumenter =
      reinterpret_cast<instrumenters::EntryThunkInstrumenter*>
          (test_impl_.instrumenter_.get());
  ASSERT_TRUE(entry_thunk_instrumenter != NULL);
  ASSERT_EQ(instrumenters::EntryThunkInstrumenter::PROFILE,
            entry_thunk_instrumenter->instrumentation_mode());
}

TEST_F(InstrumentAppTest, Run) {
  cmd_line_.AppendSwitchPath("input-dll", input_dll_path_);
  cmd_line_.AppendSwitchPath("output-dll", output_dll_path_);

  EXPECT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  ASSERT_EQ(0, test_impl_.Run());
}

}  // namespace instrument
