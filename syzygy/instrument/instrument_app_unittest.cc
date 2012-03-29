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
#include "syzygy/instrument/instrumenter.h"
#include "syzygy/pe/pe_relinker.h"
#include "syzygy/pe/pe_utils.h"
#include "syzygy/pe/unittest_util.h"

namespace instrument {

namespace {

using testing::StrictMock;
using testing::Return;
using testing::_;

class MockInstrumenter : public Instrumenter {
 public:
  MOCK_METHOD4(Instrument, bool(const FilePath&,
                                const FilePath&,
                                const FilePath&,
                                const FilePath&));
};

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
  using InstrumentApp::use_new_workflow_;
  using InstrumentApp::allow_overwrite_;
  using InstrumentApp::instrument_interior_references_;
  using InstrumentApp::debug_friendly_;

  pe::PERelinker& GetRelinker() OVERRIDE {
    return mock_relinker_;
  }

  Instrumenter& GetInstrumenter() OVERRIDE {
    return mock_instrumenter_;
  }

  StrictMock<MockRelinker> mock_relinker_;
  StrictMock<MockInstrumenter> mock_instrumenter_;
};

typedef common::Application<TestInstrumentApp> TestApp;

class InstrumentAppTest : public testing::PELibUnitTest {
 public:
  typedef testing::PELibUnitTest Super;

  InstrumentAppTest()
      : cmd_line_(FilePath(L"instrument.exe")),
        test_impl_(test_app_.implementation()),
        use_new_workflow_(false),
        allow_overwrite_(false) {
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
    input_dll_path_ = testing::GetExeRelativePath(kDllName);
    input_pdb_path_ = testing::GetExeRelativePath(kDllPdbName);
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
  std::string client_dll_;
  bool use_new_workflow_;
  bool instrument_interior_references_;
  bool allow_overwrite_;
  bool debug_friendly_;
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

TEST_F(InstrumentAppTest, ParseWithNoInputDllFails) {
  cmd_line_.AppendSwitchPath("output-dll", output_dll_path_);

  ASSERT_FALSE(test_impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(InstrumentAppTest, ParseWithNoOutputDllFails) {
  cmd_line_.AppendSwitchPath("input-dll", output_dll_path_);

  ASSERT_FALSE(test_impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(InstrumentAppTest, ParseMinimalCommandLine) {
  cmd_line_.AppendSwitchPath("input-dll", input_dll_path_);
  cmd_line_.AppendSwitchPath("output-dll", output_dll_path_);

  EXPECT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  EXPECT_TRUE(test_impl_.SetUp());

  EXPECT_EQ(input_dll_path_, test_impl_.input_dll_path_);
  EXPECT_TRUE(test_impl_.input_pdb_path_.empty());
  EXPECT_EQ(output_dll_path_, test_impl_.output_dll_path_);
  EXPECT_TRUE(test_impl_.output_pdb_path_.empty());
  EXPECT_EQ(Instrumenter::kCallTraceClientDllEtw, test_impl_.client_dll_);
  EXPECT_TRUE(test_impl_.instrument_interior_references_);
  EXPECT_FALSE(test_impl_.use_new_workflow_);
  EXPECT_FALSE(test_impl_.allow_overwrite_);
  EXPECT_FALSE(test_impl_.debug_friendly_);
}

TEST_F(InstrumentAppTest, ParseFullCommandLineRpc) {
  cmd_line_.AppendSwitchPath("input-dll", input_dll_path_);
  cmd_line_.AppendSwitchPath("input-pdb", input_pdb_path_);
  cmd_line_.AppendSwitchPath("output-dll", output_dll_path_);
  cmd_line_.AppendSwitchPath("output-pdb", output_pdb_path_);
  cmd_line_.AppendSwitchASCII("call-trace-client", "rpc");
  cmd_line_.AppendSwitch("no-interior-refs");
  cmd_line_.AppendSwitch("new-workflow");
  cmd_line_.AppendSwitch("overwrite");
  cmd_line_.AppendSwitch("debug-friendly");


  EXPECT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  EXPECT_TRUE(test_impl_.SetUp());

  EXPECT_EQ(input_dll_path_, test_impl_.input_dll_path_);
  EXPECT_EQ(input_pdb_path_, test_impl_.input_pdb_path_);
  EXPECT_EQ(output_dll_path_, test_impl_.output_dll_path_);
  EXPECT_EQ(output_pdb_path_, test_impl_.output_pdb_path_);
  EXPECT_EQ(Instrumenter::kCallTraceClientDllRpc, test_impl_.client_dll_);
  EXPECT_FALSE(test_impl_.instrument_interior_references_);
  EXPECT_TRUE(test_impl_.use_new_workflow_);
  EXPECT_TRUE(test_impl_.allow_overwrite_);
  EXPECT_TRUE(test_impl_.debug_friendly_);
}

TEST_F(InstrumentAppTest, ParseFullCommandLineProfiler) {
  cmd_line_.AppendSwitchPath("input-dll", input_dll_path_);
  cmd_line_.AppendSwitchPath("input-pdb", input_pdb_path_);
  cmd_line_.AppendSwitchPath("output-dll", output_dll_path_);
  cmd_line_.AppendSwitchPath("output-pdb", output_pdb_path_);
  cmd_line_.AppendSwitchASCII("call-trace-client", "profiler");
  cmd_line_.AppendSwitch("no-interior-refs");
  cmd_line_.AppendSwitch("new-workflow");
  cmd_line_.AppendSwitch("overwrite");
  cmd_line_.AppendSwitch("debug-friendly");


  EXPECT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  EXPECT_TRUE(test_impl_.SetUp());

  EXPECT_EQ(input_dll_path_, test_impl_.input_dll_path_);
  EXPECT_EQ(input_pdb_path_, test_impl_.input_pdb_path_);
  EXPECT_EQ(output_dll_path_, test_impl_.output_dll_path_);
  EXPECT_EQ(output_pdb_path_, test_impl_.output_pdb_path_);
  EXPECT_EQ(Instrumenter::kCallTraceClientDllProfiler, test_impl_.client_dll_);
  EXPECT_FALSE(test_impl_.instrument_interior_references_);
  EXPECT_TRUE(test_impl_.use_new_workflow_);
  EXPECT_TRUE(test_impl_.allow_overwrite_);
  EXPECT_TRUE(test_impl_.debug_friendly_);
}


TEST_F(InstrumentAppTest, ParseFullCommandLineEtw) {
  cmd_line_.AppendSwitchPath("input-dll", input_dll_path_);
  cmd_line_.AppendSwitchPath("input-pdb", input_pdb_path_);
  cmd_line_.AppendSwitchPath("output-dll", output_dll_path_);
  cmd_line_.AppendSwitchPath("output-pdb", output_pdb_path_);
  cmd_line_.AppendSwitchASCII("call-trace-client", "etw");
  cmd_line_.AppendSwitch("no-interior-refs");
  cmd_line_.AppendSwitch("new-workflow");
  cmd_line_.AppendSwitch("overwrite");
  cmd_line_.AppendSwitch("debug-friendly");


  EXPECT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));

  EXPECT_EQ(input_dll_path_, test_impl_.input_dll_path_);
  EXPECT_EQ(input_pdb_path_, test_impl_.input_pdb_path_);
  EXPECT_EQ(output_dll_path_, test_impl_.output_dll_path_);
  EXPECT_EQ(output_pdb_path_, test_impl_.output_pdb_path_);
  EXPECT_EQ(Instrumenter::kCallTraceClientDllEtw, test_impl_.client_dll_);
  EXPECT_FALSE(test_impl_.instrument_interior_references_);
  EXPECT_TRUE(test_impl_.use_new_workflow_);
  EXPECT_TRUE(test_impl_.allow_overwrite_);
  EXPECT_TRUE(test_impl_.debug_friendly_);
}

TEST_F(InstrumentAppTest, ParseFullCommandLineOther) {
  const std::string kOtherDll("other.dll");

  cmd_line_.AppendSwitchPath("input-dll", input_dll_path_);
  cmd_line_.AppendSwitchPath("input-pdb", input_pdb_path_);
  cmd_line_.AppendSwitchPath("output-dll", output_dll_path_);
  cmd_line_.AppendSwitchPath("output-pdb", output_pdb_path_);
  cmd_line_.AppendSwitchASCII("call-trace-client", kOtherDll);
  cmd_line_.AppendSwitch("no-interior-refs");
  cmd_line_.AppendSwitch("new-workflow");
  cmd_line_.AppendSwitch("overwrite");
  cmd_line_.AppendSwitch("debug-friendly");

  EXPECT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));

  EXPECT_EQ(input_dll_path_, test_impl_.input_dll_path_);
  EXPECT_EQ(input_pdb_path_, test_impl_.input_pdb_path_);
  EXPECT_EQ(output_dll_path_, test_impl_.output_dll_path_);
  EXPECT_EQ(output_pdb_path_.value(), test_impl_.output_pdb_path_.value());
  EXPECT_EQ(kOtherDll, test_impl_.client_dll_);
  EXPECT_FALSE(test_impl_.instrument_interior_references_);
  EXPECT_TRUE(test_impl_.use_new_workflow_);
  EXPECT_TRUE(test_impl_.allow_overwrite_);
  EXPECT_TRUE(test_impl_.debug_friendly_);
}

TEST_F(InstrumentAppTest, InstrumentWithOldWorkflow) {
  cmd_line_.AppendSwitchPath("input-dll", input_dll_path_);
  cmd_line_.AppendSwitchPath("input-pdb", input_pdb_path_);
  cmd_line_.AppendSwitchPath("output-dll", output_dll_path_);
  cmd_line_.AppendSwitchPath("output-pdb", output_pdb_path_);

  EXPECT_CALL(test_impl_.mock_instrumenter_,
              Instrument(input_dll_path_,
                         input_pdb_path_,
                         output_dll_path_,
                         output_pdb_path_))
      .WillOnce(Return(true));

  ASSERT_EQ(0, test_app_.Run());
}

TEST_F(InstrumentAppTest, InstrumentWithOldWorkflowInferPdbs) {
  cmd_line_.AppendSwitchPath("input-dll", input_dll_path_);
  cmd_line_.AppendSwitchPath("output-dll", output_dll_path_);

  // We validate that it correctly infers the correct PDB files, and we return
  // false to exercise the error handling code.
  EXPECT_CALL(test_impl_.mock_instrumenter_,
              Instrument(input_dll_path_,
                         input_pdb_path_,
                         output_dll_path_,
                         output_pdb_path_))
      .WillOnce(Return(true));

  EXPECT_EQ(0, test_app_.Run());
}

TEST_F(InstrumentAppTest, InstrumentWithOldWorkflowFailsInstrument) {
  cmd_line_.AppendSwitchPath("input-dll", input_dll_path_);
  cmd_line_.AppendSwitchPath("output-dll", output_dll_path_);

  // We validate that it correctly infers the correct PDB files, and we return
  // false to exercise the error handling code.
  EXPECT_CALL(test_impl_.mock_instrumenter_,
              Instrument(input_dll_path_,
                         input_pdb_path_,
                         output_dll_path_,
                         output_pdb_path_))
      .WillOnce(Return(false));

  EXPECT_EQ(1, test_app_.Run());
}

TEST_F(InstrumentAppTest, InstrumentWithNewWorkflowFailsInit) {
  cmd_line_.AppendSwitchPath("input-dll", input_dll_path_);
  cmd_line_.AppendSwitchPath("output-dll", output_dll_path_);
  cmd_line_.AppendSwitch("new-workflow");

  EXPECT_CALL(test_impl_.mock_relinker_, Init())
      .WillOnce(Return(false));

  EXPECT_EQ(1, test_app_.Run());
}

TEST_F(InstrumentAppTest, InstrumentWithNewWorkflowFailsRelink) {
  cmd_line_.AppendSwitchPath("input-dll", input_dll_path_);
  cmd_line_.AppendSwitchPath("output-dll", output_dll_path_);
  cmd_line_.AppendSwitch("new-workflow");

  EXPECT_CALL(test_impl_.mock_relinker_, Init())
      .WillOnce(Return(true));

  EXPECT_CALL(test_impl_.mock_relinker_, Relink())
      .WillOnce(Return(false));

  EXPECT_EQ(1, test_app_.Run());
}

TEST_F(InstrumentAppTest, InstrumentWithNewWorkflow) {
  cmd_line_.AppendSwitchPath("input-dll", input_dll_path_);
  cmd_line_.AppendSwitchPath("output-dll", output_dll_path_);
  cmd_line_.AppendSwitch("new-workflow");

  EXPECT_CALL(test_impl_.mock_relinker_, Init())
      .WillOnce(Return(true));

  EXPECT_CALL(test_impl_.mock_relinker_, Relink())
      .WillOnce(Return(true));

  ASSERT_EQ(0, test_app_.Run());
}

}  // namespace pe
