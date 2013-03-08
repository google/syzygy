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
#include "base/stringprintf.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/block_graph/unittest_util.h"
#include "syzygy/common/unittest_util.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/image_filter.h"
#include "syzygy/pe/pe_relinker.h"
#include "syzygy/pe/pe_utils.h"
#include "syzygy/pe/unittest_util.h"
#include "syzygy/trace/protocol/call_trace_defs.h"

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
  using InstrumentApp::filter_path_;
  using InstrumentApp::client_dll_;
  using InstrumentApp::allow_overwrite_;
  using InstrumentApp::new_decomposer_;
  using InstrumentApp::no_augment_pdb_;
  using InstrumentApp::no_parse_debug_info_;
  using InstrumentApp::no_strip_strings_;
  using InstrumentApp::debug_friendly_;
  using InstrumentApp::instrument_unsafe_references_;
  using InstrumentApp::module_entry_only_;
  using InstrumentApp::thunk_imports_;
  using InstrumentApp::mode_;

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
    abs_input_dll_path_ = testing::GetExeRelativePath(testing::kTestDllName);
    input_dll_path_ = testing::GetRelativePath(abs_input_dll_path_);
    abs_input_pdb_path_ = testing::GetExeRelativePath(testing::kTestDllPdbName);
    input_pdb_path_ = testing::GetRelativePath(abs_input_pdb_path_);
    output_dll_path_ = temp_dir_.Append(input_dll_path_.BaseName());
    output_pdb_path_ = temp_dir_.Append(input_pdb_path_.BaseName());
    test_dll_filter_path_ = temp_dir_.Append(L"test_dll_filter.json");
    dummy_filter_path_ = temp_dir_.Append(L"dummy_filter.json");

    ASSERT_NO_FATAL_FAILURE(ConfigureTestApp(&test_app_));
  }

  void MakeFilters() {
    // Create a valid test_dll filter. Just so it's not empty we mark the NT
    // headers as non-instrumentable.
    pe::ImageFilter filter;
    ASSERT_TRUE(filter.Init(abs_input_dll_path_));
    filter.filter.Mark(pe::ImageFilter::RelativeAddressFilter::Range(
        core::RelativeAddress(0), 4096));
    ASSERT_TRUE(filter.SaveToJSON(false, test_dll_filter_path_));

    // Muck up the time date stamp and create an invalid filter.
    filter.signature.module_time_date_stamp ^= 0x0F00BA55;
    ASSERT_TRUE(filter.SaveToJSON(true, dummy_filter_path_));
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
                           InstrumentApp::kCallTraceClientDllBasicBlockEntry,
                           InstrumentApp::kCallTraceClientDllCoverage,
                           InstrumentApp::kCallTraceClientDllProfile,
                           InstrumentApp::kCallTraceClientDllRpc));

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
  FilePath test_dll_filter_path_;
  FilePath dummy_filter_path_;
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
  cmd_line_.AppendSwitchASCII("mode", "asan");
  cmd_line_.AppendSwitchPath("input-image", input_dll_path_);
  cmd_line_.AppendSwitchPath("output-image", output_dll_path_);

  EXPECT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));

  EXPECT_EQ(InstrumentApp::kInstrumentAsanMode, test_impl_.mode_);
  EXPECT_EQ(abs_input_dll_path_, test_impl_.input_dll_path_);
  EXPECT_EQ(output_dll_path_, test_impl_.output_dll_path_);
  EXPECT_TRUE(test_impl_.client_dll_.empty());
  EXPECT_FALSE(test_impl_.allow_overwrite_);
  EXPECT_FALSE(test_impl_.new_decomposer_);
  EXPECT_FALSE(test_impl_.no_augment_pdb_);
  EXPECT_FALSE(test_impl_.no_parse_debug_info_);
  EXPECT_FALSE(test_impl_.no_strip_strings_);
  EXPECT_FALSE(test_impl_.debug_friendly_);
}

TEST_F(InstrumentAppTest, ParseFullAsan) {
  cmd_line_.AppendSwitchASCII("mode", "asan");
  cmd_line_.AppendSwitchPath("input-image", input_dll_path_);
  cmd_line_.AppendSwitchPath("output-image", output_dll_path_);
  cmd_line_.AppendSwitchPath("filter", test_dll_filter_path_);
  cmd_line_.AppendSwitchASCII("agent", "foo.dll");
  cmd_line_.AppendSwitch("debug-friendly");
  cmd_line_.AppendSwitchPath("input-pdb", input_pdb_path_);
  cmd_line_.AppendSwitch("new-decomposer");
  cmd_line_.AppendSwitch("no-augment-pdb");
  cmd_line_.AppendSwitch("no-parse-debug-info");
  cmd_line_.AppendSwitch("no-strip-strings");
  cmd_line_.AppendSwitchPath("output-pdb", output_pdb_path_);
  cmd_line_.AppendSwitch("overwrite");

  EXPECT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));

  EXPECT_EQ(InstrumentApp::kInstrumentAsanMode, test_impl_.mode_);
  EXPECT_EQ(abs_input_dll_path_, test_impl_.input_dll_path_);
  EXPECT_EQ(output_dll_path_, test_impl_.output_dll_path_);
  EXPECT_EQ(abs_input_pdb_path_, test_impl_.input_pdb_path_);
  EXPECT_EQ(output_pdb_path_, test_impl_.output_pdb_path_);
  EXPECT_EQ(test_dll_filter_path_, test_impl_.filter_path_);
  EXPECT_TRUE(test_impl_.client_dll_.empty());
  EXPECT_TRUE(test_impl_.allow_overwrite_);
  EXPECT_TRUE(test_impl_.new_decomposer_);
  EXPECT_TRUE(test_impl_.no_augment_pdb_);
  EXPECT_TRUE(test_impl_.no_parse_debug_info_);
  EXPECT_TRUE(test_impl_.no_strip_strings_);
  EXPECT_TRUE(test_impl_.debug_friendly_);
}

TEST_F(InstrumentAppTest, ParseMinimalBasicBlockEntry) {
  cmd_line_.AppendSwitchASCII("mode", "bbentry");
  cmd_line_.AppendSwitchPath("input-image", input_dll_path_);
  cmd_line_.AppendSwitchPath("output-image", output_dll_path_);

  EXPECT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));

  EXPECT_EQ(InstrumentApp::kInstrumentBasicBlockEntryMode, test_impl_.mode_);
  EXPECT_EQ(abs_input_dll_path_, test_impl_.input_dll_path_);
  EXPECT_EQ(output_dll_path_, test_impl_.output_dll_path_);
  EXPECT_EQ(std::string(InstrumentApp::kCallTraceClientDllBasicBlockEntry),
            test_impl_.client_dll_);
  EXPECT_FALSE(test_impl_.allow_overwrite_);
  EXPECT_FALSE(test_impl_.new_decomposer_);
  EXPECT_FALSE(test_impl_.no_augment_pdb_);
  EXPECT_FALSE(test_impl_.no_parse_debug_info_);
  EXPECT_FALSE(test_impl_.no_strip_strings_);
  EXPECT_FALSE(test_impl_.debug_friendly_);
}

TEST_F(InstrumentAppTest, ParseFullBasicBlockEntry) {
  cmd_line_.AppendSwitchASCII("mode", "bbentry");
  cmd_line_.AppendSwitchPath("input-image", input_dll_path_);
  cmd_line_.AppendSwitchPath("output-image", output_dll_path_);
  cmd_line_.AppendSwitchPath("filter", test_dll_filter_path_);
  cmd_line_.AppendSwitchASCII("agent", "foo.dll");
  cmd_line_.AppendSwitch("debug-friendly");
  cmd_line_.AppendSwitchPath("input-pdb", input_pdb_path_);
  cmd_line_.AppendSwitch("new-decomposer");
  cmd_line_.AppendSwitch("no-augment-pdb");
  cmd_line_.AppendSwitch("no-parse-debug-info");
  cmd_line_.AppendSwitch("no-strip-strings");
  cmd_line_.AppendSwitchPath("output-pdb", output_pdb_path_);
  cmd_line_.AppendSwitch("overwrite");

  EXPECT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));

  EXPECT_EQ(InstrumentApp::kInstrumentBasicBlockEntryMode, test_impl_.mode_);
  EXPECT_EQ(abs_input_dll_path_, test_impl_.input_dll_path_);
  EXPECT_EQ(output_dll_path_, test_impl_.output_dll_path_);
  EXPECT_EQ(abs_input_pdb_path_, test_impl_.input_pdb_path_);
  EXPECT_EQ(output_pdb_path_, test_impl_.output_pdb_path_);
  EXPECT_EQ(test_dll_filter_path_, test_impl_.filter_path_);
  EXPECT_EQ(std::string("foo.dll"), test_impl_.client_dll_);
  EXPECT_TRUE(test_impl_.allow_overwrite_);
  EXPECT_TRUE(test_impl_.new_decomposer_);
  EXPECT_TRUE(test_impl_.no_augment_pdb_);
  EXPECT_TRUE(test_impl_.no_parse_debug_info_);
  EXPECT_TRUE(test_impl_.no_strip_strings_);
  EXPECT_TRUE(test_impl_.debug_friendly_);
}

TEST_F(InstrumentAppTest, ParseMinimalCallTrace) {
  cmd_line_.AppendSwitchASCII("mode", "calltrace");
  cmd_line_.AppendSwitchPath("input-image", input_dll_path_);
  cmd_line_.AppendSwitchPath("output-image", output_dll_path_);

  EXPECT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));

  EXPECT_EQ(InstrumentApp::kInstrumentCallTraceMode, test_impl_.mode_);
  EXPECT_EQ(abs_input_dll_path_, test_impl_.input_dll_path_);
  EXPECT_EQ(output_dll_path_, test_impl_.output_dll_path_);
  EXPECT_EQ(std::string(InstrumentApp::kCallTraceClientDllRpc),
            test_impl_.client_dll_);
  EXPECT_FALSE(test_impl_.allow_overwrite_);
  EXPECT_FALSE(test_impl_.new_decomposer_);
  EXPECT_FALSE(test_impl_.no_augment_pdb_);
  EXPECT_FALSE(test_impl_.no_parse_debug_info_);
  EXPECT_FALSE(test_impl_.no_strip_strings_);
  EXPECT_FALSE(test_impl_.debug_friendly_);
  EXPECT_FALSE(test_impl_.thunk_imports_);
  EXPECT_TRUE(test_impl_.instrument_unsafe_references_);
  EXPECT_FALSE(test_impl_.module_entry_only_);
}

TEST_F(InstrumentAppTest, ParseFullCallTrace) {
  cmd_line_.AppendSwitchASCII("mode", "calltrace");
  cmd_line_.AppendSwitchPath("input-image", input_dll_path_);
  cmd_line_.AppendSwitchPath("output-image", output_dll_path_);
  cmd_line_.AppendSwitchPath("filter", test_dll_filter_path_);
  cmd_line_.AppendSwitchASCII("agent", "foo.dll");
  cmd_line_.AppendSwitch("debug-friendly");
  cmd_line_.AppendSwitchPath("input-pdb", input_pdb_path_);
  cmd_line_.AppendSwitch("new-decomposer");
  cmd_line_.AppendSwitch("no-augment-pdb");
  cmd_line_.AppendSwitch("no-parse-debug-info");
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
  EXPECT_EQ(test_dll_filter_path_, test_impl_.filter_path_);
  EXPECT_EQ(std::string("foo.dll"), test_impl_.client_dll_);
  EXPECT_TRUE(test_impl_.allow_overwrite_);
  EXPECT_TRUE(test_impl_.new_decomposer_);
  EXPECT_TRUE(test_impl_.no_augment_pdb_);
  EXPECT_TRUE(test_impl_.no_parse_debug_info_);
  EXPECT_TRUE(test_impl_.no_strip_strings_);
  EXPECT_TRUE(test_impl_.debug_friendly_);
  EXPECT_TRUE(test_impl_.thunk_imports_);
  EXPECT_FALSE(test_impl_.instrument_unsafe_references_);
  EXPECT_TRUE(test_impl_.module_entry_only_);
}

TEST_F(InstrumentAppTest, ParseMinimalCoverage) {
  cmd_line_.AppendSwitchASCII("mode", "coverage");
  cmd_line_.AppendSwitchPath("input-image", input_dll_path_);
  cmd_line_.AppendSwitchPath("output-image", output_dll_path_);

  EXPECT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));

  EXPECT_EQ(InstrumentApp::kInstrumentCoverageMode, test_impl_.mode_);
  EXPECT_EQ(abs_input_dll_path_, test_impl_.input_dll_path_);
  EXPECT_EQ(output_dll_path_, test_impl_.output_dll_path_);
  EXPECT_EQ(std::string(InstrumentApp::kCallTraceClientDllCoverage),
            test_impl_.client_dll_);
  EXPECT_FALSE(test_impl_.allow_overwrite_);
  EXPECT_FALSE(test_impl_.new_decomposer_);
  EXPECT_FALSE(test_impl_.no_augment_pdb_);
  EXPECT_FALSE(test_impl_.no_parse_debug_info_);
  EXPECT_FALSE(test_impl_.no_strip_strings_);
  EXPECT_FALSE(test_impl_.debug_friendly_);
}

TEST_F(InstrumentAppTest, ParseFullCoverage) {
  cmd_line_.AppendSwitchASCII("mode", "coverage");
  cmd_line_.AppendSwitchPath("input-image", input_dll_path_);
  cmd_line_.AppendSwitchPath("output-image", output_dll_path_);
  cmd_line_.AppendSwitchPath("filter", test_dll_filter_path_);
  cmd_line_.AppendSwitchASCII("agent", "foo.dll");
  cmd_line_.AppendSwitch("debug-friendly");
  cmd_line_.AppendSwitchPath("input-pdb", input_pdb_path_);
  cmd_line_.AppendSwitch("new-decomposer");
  cmd_line_.AppendSwitch("no-augment-pdb");
  cmd_line_.AppendSwitch("no-parse-debug-info");
  cmd_line_.AppendSwitch("no-strip-strings");
  cmd_line_.AppendSwitchPath("output-pdb", output_pdb_path_);
  cmd_line_.AppendSwitch("overwrite");

  EXPECT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));

  EXPECT_EQ(InstrumentApp::kInstrumentCoverageMode, test_impl_.mode_);
  EXPECT_EQ(abs_input_dll_path_, test_impl_.input_dll_path_);
  EXPECT_EQ(output_dll_path_, test_impl_.output_dll_path_);
  EXPECT_EQ(abs_input_pdb_path_, test_impl_.input_pdb_path_);
  EXPECT_EQ(output_pdb_path_, test_impl_.output_pdb_path_);
  EXPECT_EQ(test_dll_filter_path_, test_impl_.filter_path_);
  EXPECT_EQ(std::string("foo.dll"), test_impl_.client_dll_);
  EXPECT_TRUE(test_impl_.allow_overwrite_);
  EXPECT_TRUE(test_impl_.new_decomposer_);
  EXPECT_TRUE(test_impl_.no_augment_pdb_);
  EXPECT_TRUE(test_impl_.no_parse_debug_info_);
  EXPECT_TRUE(test_impl_.no_strip_strings_);
  EXPECT_TRUE(test_impl_.debug_friendly_);
}

TEST_F(InstrumentAppTest, ParseMinimalProfile) {
  cmd_line_.AppendSwitchASCII("mode", "profile");
  cmd_line_.AppendSwitchPath("input-image", input_dll_path_);
  cmd_line_.AppendSwitchPath("output-image", output_dll_path_);

  EXPECT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  EXPECT_EQ(InstrumentApp::kInstrumentProfileMode, test_impl_.mode_);
  EXPECT_EQ(abs_input_dll_path_, test_impl_.input_dll_path_);
  EXPECT_EQ(output_dll_path_, test_impl_.output_dll_path_);

  EXPECT_EQ(std::string(InstrumentApp::kCallTraceClientDllProfile),
            test_impl_.client_dll_);

  EXPECT_FALSE(test_impl_.allow_overwrite_);
  EXPECT_FALSE(test_impl_.new_decomposer_);
  EXPECT_FALSE(test_impl_.no_augment_pdb_);
  EXPECT_FALSE(test_impl_.no_parse_debug_info_);
  EXPECT_FALSE(test_impl_.no_strip_strings_);
  EXPECT_FALSE(test_impl_.debug_friendly_);
  EXPECT_FALSE(test_impl_.thunk_imports_);
  EXPECT_FALSE(test_impl_.instrument_unsafe_references_);
  EXPECT_FALSE(test_impl_.module_entry_only_);
}

TEST_F(InstrumentAppTest, ParseFullProfile) {
  cmd_line_.AppendSwitchASCII("mode", "profile");
  cmd_line_.AppendSwitchPath("input-image", input_dll_path_);
  cmd_line_.AppendSwitchPath("output-image", output_dll_path_);
  cmd_line_.AppendSwitchPath("filter", test_dll_filter_path_);
  cmd_line_.AppendSwitchASCII("agent", "foo.dll");
  cmd_line_.AppendSwitch("debug-friendly");
  cmd_line_.AppendSwitchPath("input-pdb", input_pdb_path_);
  cmd_line_.AppendSwitch("new-decomposer");
  cmd_line_.AppendSwitch("no-augment-pdb");
  cmd_line_.AppendSwitch("no-parse-debug-info");
  cmd_line_.AppendSwitch("no-strip-strings");
  cmd_line_.AppendSwitchPath("output-pdb", output_pdb_path_);
  cmd_line_.AppendSwitch("overwrite");
  cmd_line_.AppendSwitch("instrument-imports");

  EXPECT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));

  EXPECT_EQ(InstrumentApp::kInstrumentProfileMode, test_impl_.mode_);
  EXPECT_EQ(abs_input_dll_path_, test_impl_.input_dll_path_);
  EXPECT_EQ(output_dll_path_, test_impl_.output_dll_path_);
  EXPECT_EQ(abs_input_pdb_path_, test_impl_.input_pdb_path_);
  EXPECT_EQ(output_pdb_path_, test_impl_.output_pdb_path_);
  EXPECT_EQ(test_dll_filter_path_, test_impl_.filter_path_);
  EXPECT_EQ(std::string("foo.dll"), test_impl_.client_dll_);
  EXPECT_TRUE(test_impl_.allow_overwrite_);
  EXPECT_TRUE(test_impl_.new_decomposer_);
  EXPECT_TRUE(test_impl_.no_augment_pdb_);
  EXPECT_TRUE(test_impl_.no_parse_debug_info_);
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
  EXPECT_FALSE(test_impl_.new_decomposer_);
  EXPECT_FALSE(test_impl_.no_augment_pdb_);
  EXPECT_FALSE(test_impl_.no_parse_debug_info_);
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
  EXPECT_FALSE(test_impl_.new_decomposer_);
  EXPECT_FALSE(test_impl_.no_augment_pdb_);
  EXPECT_FALSE(test_impl_.no_parse_debug_info_);
  EXPECT_FALSE(test_impl_.no_strip_strings_);
  EXPECT_FALSE(test_impl_.debug_friendly_);
  EXPECT_FALSE(test_impl_.thunk_imports_);
  EXPECT_TRUE(test_impl_.instrument_unsafe_references_);
  EXPECT_FALSE(test_impl_.module_entry_only_);
}

TEST_F(InstrumentAppTest, DeprecatedParseCallTraceClientProfiler) {
  cmd_line_.AppendSwitchASCII("call-trace-client", "profiler");
  cmd_line_.AppendSwitchPath("input-dll", input_dll_path_);
  cmd_line_.AppendSwitchPath("output-dll", output_dll_path_);

  EXPECT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  EXPECT_EQ(InstrumentApp::kInstrumentProfileMode, test_impl_.mode_);
  EXPECT_EQ(abs_input_dll_path_, test_impl_.input_dll_path_);
  EXPECT_EQ(output_dll_path_, test_impl_.output_dll_path_);

  EXPECT_EQ(std::string(InstrumentApp::kCallTraceClientDllProfile),
            test_impl_.client_dll_);

  EXPECT_FALSE(test_impl_.allow_overwrite_);
  EXPECT_FALSE(test_impl_.new_decomposer_);
  EXPECT_FALSE(test_impl_.no_augment_pdb_);
  EXPECT_FALSE(test_impl_.no_parse_debug_info_);
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
  EXPECT_FALSE(test_impl_.new_decomposer_);
  EXPECT_FALSE(test_impl_.no_augment_pdb_);
  EXPECT_FALSE(test_impl_.no_parse_debug_info_);
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

TEST_F(InstrumentAppTest, AsanEndToEnd) {
  ASSERT_NO_FATAL_FAILURE(EndToEndTest("asan"));
}

TEST_F(InstrumentAppTest, BbEntryEndToEnd) {
  ASSERT_NO_FATAL_FAILURE(EndToEndTest("bbentry"));
}

TEST_F(InstrumentAppTest, CallTraceEndToEnd) {
  ASSERT_NO_FATAL_FAILURE(EndToEndTest("calltrace"));
}

TEST_F(InstrumentAppTest, CoverageEndToEnd) {
  ASSERT_NO_FATAL_FAILURE(EndToEndTest("coverage"));
}

TEST_F(InstrumentAppTest, ProfileEndToEnd) {
  ASSERT_NO_FATAL_FAILURE(EndToEndTest("profile"));
}

TEST_F(InstrumentAppTest, FailsWithInvalidFilter) {
  // Filters are applied in any mode, but run before any transformation is
  // actually done. Thus, we don't test this in combination with every mode.
  cmd_line_.AppendSwitchASCII("mode", "asan");
  cmd_line_.AppendSwitchPath("input-image", input_dll_path_);
  cmd_line_.AppendSwitchPath("output-image", output_dll_path_);
  cmd_line_.AppendSwitchPath("filter", dummy_filter_path_);

  // We don't expect the relinker to be called at all, as before we get that far
  // the filter will be identified as being for the wrong module.

  MakeFilters();
  ASSERT_NE(0, test_app_.Run());
}

TEST_F(InstrumentAppTest, SucceedsWithValidFilter) {
  cmd_line_.AppendSwitchASCII("mode", "asan");
  cmd_line_.AppendSwitchPath("input-image", input_dll_path_);
  cmd_line_.AppendSwitchPath("output-image", output_dll_path_);
  cmd_line_.AppendSwitchPath("filter", test_dll_filter_path_);

  EXPECT_CALL(test_impl_.mock_relinker_, Init())
      .WillOnce(Return(true));

  EXPECT_CALL(test_impl_.mock_relinker_, Relink())
      .WillOnce(Return(true));

  MakeFilters();
  ASSERT_EQ(0, test_app_.Run());
}

}  // namespace pe
