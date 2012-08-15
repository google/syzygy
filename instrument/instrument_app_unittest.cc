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

#include "syzygy/instrument/instrument_app.h"

#include "base/stringprintf.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/block_graph/unittest_util.h"
#include "syzygy/common/unittest_util.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/pe_relinker.h"
#include "syzygy/pe/pe_utils.h"
#include "syzygy/pe/unittest_util.h"

namespace instrument {

namespace {

using testing::StrictMock;
using testing::Return;
using testing::_;

class MockRelinker : public pe::PERelinker {
 public:
  MOCK_METHOD0(Init, bool());
  MOCK_METHOD0(Relink, bool());
};

class TestInstrumentApp : public InstrumentApp {
 public:
  using InstrumentApp::input_dll_path_;
  using InstrumentApp::input_pdb_path_;
  using InstrumentApp::output_dll_path_;
  using InstrumentApp::output_pdb_path_;
  using InstrumentApp::client_dll_;
  using InstrumentApp::allow_overwrite_;
  using InstrumentApp::no_augment_pdb_;
  using InstrumentApp::debug_friendly_;
  using InstrumentApp::instrument_unsafe_references_;
  using InstrumentApp::module_entry_only_;
  using InstrumentApp::thunk_imports_;
  using InstrumentApp::mode_;
  using InstrumentApp::no_strip_strings_;

  pe::PERelinker& GetRelinker() OVERRIDE {
    return mock_relinker_;
  }

  StrictMock<MockRelinker> mock_relinker_;
};

typedef common::Application<TestInstrumentApp> TestApp;

class InstrumentAppTest : public testing::PELibUnitTest {
 public:
  typedef testing::PELibUnitTest Super;

  InstrumentAppTest()
      : cmd_line_(FilePath(L"instrument.exe")),
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
    abs_input_dll_path_ = testing::GetExeRelativePath(kDllName);
    input_dll_path_ = testing::GetRelativePath(abs_input_dll_path_);
    abs_input_pdb_path_ = testing::GetExeRelativePath(kDllPdbName);
    input_pdb_path_ = testing::GetRelativePath(abs_input_pdb_path_);
    output_dll_path_ = temp_dir_.Append(input_dll_path_.BaseName());
    output_pdb_path_ = temp_dir_.Append(input_pdb_path_.BaseName());

    // Point the application at the test's command-line, IO streams and mock
    // machinery.
    test_app_.set_command_line(&cmd_line_);
    test_app_.set_in(in());
    test_app_.set_out(out());
    test_app_.set_err(err());
  }

  // Stashes the current log-level before each test instance and restores it
  // after each test completes.
  testing::ScopedLogLevelSaver log_level_saver;

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
  // @}

  // @name Expected final values of input parameters.
  // @{
  FilePath abs_input_dll_path_;
  FilePath abs_input_pdb_path_;
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
}

TEST_F(InstrumentAppTest, ParseWithNoOutputImageFails) {
  cmd_line_.AppendSwitchPath("input-image", input_dll_path_);

  ASSERT_FALSE(test_impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(InstrumentAppTest, ParseMinimalAsan) {
  cmd_line_.AppendSwitchASCII("mode", "ASAN");
  cmd_line_.AppendSwitchPath("input-image", input_dll_path_);
  cmd_line_.AppendSwitchPath("output-image", output_dll_path_);

  EXPECT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));

  EXPECT_EQ(InstrumentApp::kInstrumentAsanMode, test_impl_.mode_);
  EXPECT_EQ(abs_input_dll_path_, test_impl_.input_dll_path_);
  EXPECT_EQ(output_dll_path_, test_impl_.output_dll_path_);
  EXPECT_TRUE(test_impl_.client_dll_.empty());
  EXPECT_FALSE(test_impl_.allow_overwrite_);
  EXPECT_FALSE(test_impl_.no_augment_pdb_);
  EXPECT_FALSE(test_impl_.no_strip_strings_);
  EXPECT_FALSE(test_impl_.debug_friendly_);
}

TEST_F(InstrumentAppTest, ParseFullAsan) {
  cmd_line_.AppendSwitchASCII("mode", "ASAN");
  cmd_line_.AppendSwitchPath("input-image", input_dll_path_);
  cmd_line_.AppendSwitchPath("output-image", output_dll_path_);
  cmd_line_.AppendSwitchASCII("agent", "foo.dll");
  cmd_line_.AppendSwitch("debug-friendly");
  cmd_line_.AppendSwitchPath("input-pdb", input_pdb_path_);
  cmd_line_.AppendSwitch("no-augment-pdb");
  cmd_line_.AppendSwitch("no-strip-strings");
  cmd_line_.AppendSwitchPath("output-pdb", output_pdb_path_);
  cmd_line_.AppendSwitch("overwrite");

  EXPECT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));

  EXPECT_EQ(InstrumentApp::kInstrumentAsanMode, test_impl_.mode_);
  EXPECT_EQ(abs_input_dll_path_, test_impl_.input_dll_path_);
  EXPECT_EQ(output_dll_path_, test_impl_.output_dll_path_);
  EXPECT_EQ(abs_input_pdb_path_, test_impl_.input_pdb_path_);
  EXPECT_EQ(output_pdb_path_, test_impl_.output_pdb_path_);
  EXPECT_TRUE(test_impl_.client_dll_.empty());
  EXPECT_TRUE(test_impl_.allow_overwrite_);
  EXPECT_TRUE(test_impl_.no_augment_pdb_);
  EXPECT_TRUE(test_impl_.no_strip_strings_);
  EXPECT_TRUE(test_impl_.debug_friendly_);
}

TEST_F(InstrumentAppTest, ParseMinimalCallTrace) {
  cmd_line_.AppendSwitchASCII("mode", "CALLTRACE");
  cmd_line_.AppendSwitchPath("input-image", input_dll_path_);
  cmd_line_.AppendSwitchPath("output-image", output_dll_path_);

  EXPECT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));

  EXPECT_EQ(InstrumentApp::kInstrumentCallTraceMode, test_impl_.mode_);
  EXPECT_EQ(abs_input_dll_path_, test_impl_.input_dll_path_);
  EXPECT_EQ(output_dll_path_, test_impl_.output_dll_path_);
  EXPECT_EQ(std::string(InstrumentApp::kCallTraceClientDllRpc),
            test_impl_.client_dll_);
  EXPECT_FALSE(test_impl_.allow_overwrite_);
  EXPECT_FALSE(test_impl_.no_augment_pdb_);
  EXPECT_FALSE(test_impl_.no_strip_strings_);
  EXPECT_FALSE(test_impl_.debug_friendly_);
  EXPECT_FALSE(test_impl_.thunk_imports_);
  EXPECT_TRUE(test_impl_.instrument_unsafe_references_);
  EXPECT_FALSE(test_impl_.module_entry_only_);
}

TEST_F(InstrumentAppTest, ParseFullCallTrace) {
  cmd_line_.AppendSwitchASCII("mode", "CALLTRACE");
  cmd_line_.AppendSwitchPath("input-image", input_dll_path_);
  cmd_line_.AppendSwitchPath("output-image", output_dll_path_);

  cmd_line_.AppendSwitchASCII("agent", "foo.dll");
  cmd_line_.AppendSwitch("debug-friendly");
  cmd_line_.AppendSwitchPath("input-pdb", input_pdb_path_);
  cmd_line_.AppendSwitch("no-augment-pdb");
  cmd_line_.AppendSwitch("no-strip-strings");
  cmd_line_.AppendSwitchPath("output-pdb", output_pdb_path_);
  cmd_line_.AppendSwitch("overwrite");
  cmd_line_.AppendSwitch("instrument-imports");
  cmd_line_.AppendSwitch("module-entry-only");
  cmd_line_.AppendSwitch("no-unsafe-refs");

  EXPECT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));

  EXPECT_EQ(InstrumentApp::kInstrumentCallTraceMode, test_impl_.mode_);
  EXPECT_EQ(abs_input_dll_path_, test_impl_.input_dll_path_);
  EXPECT_EQ(output_dll_path_, test_impl_.output_dll_path_);
  EXPECT_EQ(abs_input_pdb_path_, test_impl_.input_pdb_path_);
  EXPECT_EQ(output_pdb_path_, test_impl_.output_pdb_path_);
  EXPECT_EQ(std::string("foo.dll"), test_impl_.client_dll_);
  EXPECT_TRUE(test_impl_.allow_overwrite_);
  EXPECT_TRUE(test_impl_.no_augment_pdb_);
  EXPECT_TRUE(test_impl_.no_strip_strings_);
  EXPECT_TRUE(test_impl_.debug_friendly_);
  EXPECT_TRUE(test_impl_.thunk_imports_);
  EXPECT_FALSE(test_impl_.instrument_unsafe_references_);
  EXPECT_TRUE(test_impl_.module_entry_only_);
}

TEST_F(InstrumentAppTest, ParseMinimalCoverage) {
  cmd_line_.AppendSwitchASCII("mode", "COVERAGE");
  cmd_line_.AppendSwitchPath("input-image", input_dll_path_);
  cmd_line_.AppendSwitchPath("output-image", output_dll_path_);

  EXPECT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));

  EXPECT_EQ(InstrumentApp::kInstrumentCoverageMode, test_impl_.mode_);
  EXPECT_EQ(abs_input_dll_path_, test_impl_.input_dll_path_);
  EXPECT_EQ(output_dll_path_, test_impl_.output_dll_path_);
  EXPECT_EQ(std::string(InstrumentApp::kCallTraceClientDllCoverage),
            test_impl_.client_dll_);
  EXPECT_FALSE(test_impl_.allow_overwrite_);
  EXPECT_FALSE(test_impl_.no_augment_pdb_);
  EXPECT_FALSE(test_impl_.no_strip_strings_);
  EXPECT_FALSE(test_impl_.debug_friendly_);
}

TEST_F(InstrumentAppTest, ParseFullCoverage) {
  cmd_line_.AppendSwitchASCII("mode", "COVERAGE");
  cmd_line_.AppendSwitchPath("input-image", input_dll_path_);
  cmd_line_.AppendSwitchPath("output-image", output_dll_path_);
  cmd_line_.AppendSwitchASCII("agent", "foo.dll");
  cmd_line_.AppendSwitch("debug-friendly");
  cmd_line_.AppendSwitchPath("input-pdb", input_pdb_path_);
  cmd_line_.AppendSwitch("no-augment-pdb");
  cmd_line_.AppendSwitch("no-strip-strings");
  cmd_line_.AppendSwitchPath("output-pdb", output_pdb_path_);
  cmd_line_.AppendSwitch("overwrite");

  EXPECT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));

  EXPECT_EQ(InstrumentApp::kInstrumentCoverageMode, test_impl_.mode_);
  EXPECT_EQ(abs_input_dll_path_, test_impl_.input_dll_path_);
  EXPECT_EQ(output_dll_path_, test_impl_.output_dll_path_);
  EXPECT_EQ(abs_input_pdb_path_, test_impl_.input_pdb_path_);
  EXPECT_EQ(output_pdb_path_, test_impl_.output_pdb_path_);
  EXPECT_EQ(std::string("foo.dll"), test_impl_.client_dll_);
  EXPECT_TRUE(test_impl_.allow_overwrite_);
  EXPECT_TRUE(test_impl_.no_augment_pdb_);
  EXPECT_TRUE(test_impl_.no_strip_strings_);
  EXPECT_TRUE(test_impl_.debug_friendly_);
}

TEST_F(InstrumentAppTest, ParseMinimalProfiler) {
  cmd_line_.AppendSwitchASCII("mode", "PROFILER");
  cmd_line_.AppendSwitchPath("input-image", input_dll_path_);
  cmd_line_.AppendSwitchPath("output-image", output_dll_path_);

  EXPECT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  EXPECT_EQ(InstrumentApp::kInstrumentProfilerMode, test_impl_.mode_);
  EXPECT_EQ(abs_input_dll_path_, test_impl_.input_dll_path_);
  EXPECT_EQ(output_dll_path_, test_impl_.output_dll_path_);

  EXPECT_EQ(std::string(InstrumentApp::kCallTraceClientDllProfiler),
            test_impl_.client_dll_);

  EXPECT_FALSE(test_impl_.allow_overwrite_);
  EXPECT_FALSE(test_impl_.no_augment_pdb_);
  EXPECT_FALSE(test_impl_.no_strip_strings_);
  EXPECT_FALSE(test_impl_.debug_friendly_);
  EXPECT_FALSE(test_impl_.thunk_imports_);
  EXPECT_FALSE(test_impl_.instrument_unsafe_references_);
  EXPECT_FALSE(test_impl_.module_entry_only_);
}

TEST_F(InstrumentAppTest, ParseFullProfiler) {
  cmd_line_.AppendSwitchASCII("mode", "PROFILER");
  cmd_line_.AppendSwitchPath("input-image", input_dll_path_);
  cmd_line_.AppendSwitchPath("output-image", output_dll_path_);
  cmd_line_.AppendSwitchASCII("agent", "foo.dll");
  cmd_line_.AppendSwitch("debug-friendly");
  cmd_line_.AppendSwitchPath("input-pdb", input_pdb_path_);
  cmd_line_.AppendSwitch("no-augment-pdb");
  cmd_line_.AppendSwitch("no-strip-strings");
  cmd_line_.AppendSwitchPath("output-pdb", output_pdb_path_);
  cmd_line_.AppendSwitch("overwrite");
  cmd_line_.AppendSwitch("instrument-imports");

  EXPECT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));

  EXPECT_EQ(InstrumentApp::kInstrumentProfilerMode, test_impl_.mode_);
  EXPECT_EQ(abs_input_dll_path_, test_impl_.input_dll_path_);
  EXPECT_EQ(output_dll_path_, test_impl_.output_dll_path_);
  EXPECT_EQ(abs_input_pdb_path_, test_impl_.input_pdb_path_);
  EXPECT_EQ(output_pdb_path_, test_impl_.output_pdb_path_);
  EXPECT_EQ(std::string("foo.dll"), test_impl_.client_dll_);
  EXPECT_TRUE(test_impl_.allow_overwrite_);
  EXPECT_TRUE(test_impl_.no_augment_pdb_);
  EXPECT_TRUE(test_impl_.no_strip_strings_);
  EXPECT_TRUE(test_impl_.debug_friendly_);
  EXPECT_TRUE(test_impl_.thunk_imports_);
}

TEST_F(InstrumentAppTest, DeprecatedParseNoModeSpecifyDlls) {
  cmd_line_.AppendSwitchPath("input-dll", input_dll_path_);
  cmd_line_.AppendSwitchPath("output-dll", output_dll_path_);

  EXPECT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  EXPECT_EQ(InstrumentApp::kInstrumentCallTraceMode, test_impl_.mode_);
  EXPECT_EQ(abs_input_dll_path_, test_impl_.input_dll_path_);
  EXPECT_EQ(output_dll_path_, test_impl_.output_dll_path_);

  EXPECT_EQ(std::string(InstrumentApp::kCallTraceClientDllRpc),
            test_impl_.client_dll_);

  EXPECT_FALSE(test_impl_.allow_overwrite_);
  EXPECT_FALSE(test_impl_.no_augment_pdb_);
  EXPECT_FALSE(test_impl_.no_strip_strings_);
  EXPECT_FALSE(test_impl_.debug_friendly_);
  EXPECT_FALSE(test_impl_.thunk_imports_);
  EXPECT_TRUE(test_impl_.instrument_unsafe_references_);
  EXPECT_FALSE(test_impl_.module_entry_only_);
}

TEST_F(InstrumentAppTest, DeprecatedParseCallTraceClientRpc) {
  cmd_line_.AppendSwitchASCII("call-trace-client", "RPC");
  cmd_line_.AppendSwitchPath("input-dll", input_dll_path_);
  cmd_line_.AppendSwitchPath("output-dll", output_dll_path_);

  EXPECT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  EXPECT_EQ(InstrumentApp::kInstrumentCallTraceMode, test_impl_.mode_);
  EXPECT_EQ(abs_input_dll_path_, test_impl_.input_dll_path_);
  EXPECT_EQ(output_dll_path_, test_impl_.output_dll_path_);

  EXPECT_EQ(std::string(InstrumentApp::kCallTraceClientDllRpc),
            test_impl_.client_dll_);

  EXPECT_FALSE(test_impl_.allow_overwrite_);
  EXPECT_FALSE(test_impl_.no_augment_pdb_);
  EXPECT_FALSE(test_impl_.no_strip_strings_);
  EXPECT_FALSE(test_impl_.debug_friendly_);
  EXPECT_FALSE(test_impl_.thunk_imports_);
  EXPECT_TRUE(test_impl_.instrument_unsafe_references_);
  EXPECT_FALSE(test_impl_.module_entry_only_);
}

TEST_F(InstrumentAppTest, DeprecatedParseCallTraceClientProfiler) {
  cmd_line_.AppendSwitchASCII("call-trace-client", "PROFILER");
  cmd_line_.AppendSwitchPath("input-dll", input_dll_path_);
  cmd_line_.AppendSwitchPath("output-dll", output_dll_path_);

  EXPECT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  EXPECT_EQ(InstrumentApp::kInstrumentProfilerMode, test_impl_.mode_);
  EXPECT_EQ(abs_input_dll_path_, test_impl_.input_dll_path_);
  EXPECT_EQ(output_dll_path_, test_impl_.output_dll_path_);

  EXPECT_EQ(std::string(InstrumentApp::kCallTraceClientDllProfiler),
            test_impl_.client_dll_);

  EXPECT_FALSE(test_impl_.allow_overwrite_);
  EXPECT_FALSE(test_impl_.no_augment_pdb_);
  EXPECT_FALSE(test_impl_.no_strip_strings_);
  EXPECT_FALSE(test_impl_.debug_friendly_);
  EXPECT_FALSE(test_impl_.thunk_imports_);
  EXPECT_FALSE(test_impl_.instrument_unsafe_references_);
  EXPECT_FALSE(test_impl_.module_entry_only_);
}

TEST_F(InstrumentAppTest, DeprecatedParseCallTraceClientOtherDll) {
  cmd_line_.AppendSwitchASCII("call-trace-client", "foo.dll");
  cmd_line_.AppendSwitchPath("input-dll", input_dll_path_);
  cmd_line_.AppendSwitchPath("output-dll", output_dll_path_);

  EXPECT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  EXPECT_EQ(InstrumentApp::kInstrumentCallTraceMode, test_impl_.mode_);
  EXPECT_EQ(abs_input_dll_path_, test_impl_.input_dll_path_);
  EXPECT_EQ(output_dll_path_, test_impl_.output_dll_path_);

  EXPECT_EQ(std::string("foo.dll"),
            test_impl_.client_dll_);

  EXPECT_FALSE(test_impl_.allow_overwrite_);
  EXPECT_FALSE(test_impl_.no_augment_pdb_);
  EXPECT_FALSE(test_impl_.no_strip_strings_);
  EXPECT_FALSE(test_impl_.debug_friendly_);
  EXPECT_FALSE(test_impl_.thunk_imports_);
  EXPECT_TRUE(test_impl_.instrument_unsafe_references_);
  EXPECT_FALSE(test_impl_.module_entry_only_);
}

TEST_F(InstrumentAppTest, InstrumentFailsInit) {
  cmd_line_.AppendSwitchPath("input-image", input_dll_path_);
  cmd_line_.AppendSwitchPath("output-image", output_dll_path_);

  EXPECT_CALL(test_impl_.mock_relinker_, Init())
      .WillOnce(Return(false));

  EXPECT_EQ(1, test_app_.Run());
}

TEST_F(InstrumentAppTest, InstrumentFailsRelink) {
  cmd_line_.AppendSwitchPath("input-image", input_dll_path_);
  cmd_line_.AppendSwitchPath("output-image", output_dll_path_);

  EXPECT_CALL(test_impl_.mock_relinker_, Init())
      .WillOnce(Return(true));

  EXPECT_CALL(test_impl_.mock_relinker_, Relink())
      .WillOnce(Return(false));

  EXPECT_EQ(1, test_app_.Run());
}

TEST_F(InstrumentAppTest, Instrument) {
  cmd_line_.AppendSwitchPath("input-image", input_dll_path_);
  cmd_line_.AppendSwitchPath("output-image", output_dll_path_);

  EXPECT_CALL(test_impl_.mock_relinker_, Init())
      .WillOnce(Return(true));

  EXPECT_CALL(test_impl_.mock_relinker_, Relink())
      .WillOnce(Return(true));

  ASSERT_EQ(0, test_app_.Run());
}

}  // namespace pe
