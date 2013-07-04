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

#include "syzygy/instrument/instrumenters/instrumenter_with_agent.h"

#include "base/command_line.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/unittest_util.h"

namespace instrument {
namespace instrumenters {

namespace {

using testing::StrictMock;
using testing::Return;
using testing::_;

const char kTestAgentDllName[] = "test_agent_dll.dll";

class MockRelinker : public pe::PERelinker {
 public:
  MOCK_METHOD0(Init, bool());
  MOCK_METHOD0(Relink, bool());
};

class TestInstrumenterWithAgent : public InstrumenterWithAgent {
 public:
  using InstrumenterWithAgent::input_dll_path_;
  using InstrumenterWithAgent::input_pdb_path_;
  using InstrumenterWithAgent::output_dll_path_;
  using InstrumenterWithAgent::output_pdb_path_;
  using InstrumenterWithAgent::allow_overwrite_;
  using InstrumenterWithAgent::new_decomposer_;
  using InstrumenterWithAgent::no_augment_pdb_;
  using InstrumenterWithAgent::no_parse_debug_info_;
  using InstrumenterWithAgent::no_strip_strings_;

  TestInstrumenterWithAgent() {
    agent_dll_ = kTestAgentDllName;
  }

  MOCK_METHOD0(InstrumentImpl, bool());

  pe::PERelinker* GetRelinker() OVERRIDE {
    return &mock_relinker_;
  }

  virtual const char* InstrumentationMode() { return "test"; }

  StrictMock<MockRelinker> mock_relinker_;
};

class InstrumenterWithAgentTest : public testing::PELibUnitTest {
 public:
  typedef testing::PELibUnitTest Super;

  InstrumenterWithAgentTest()
      : cmd_line_(base::FilePath(L"instrument.exe")) {
  }

  virtual void SetUp() OVERRIDE {
    testing::Test::SetUp();

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
  }

  void SetUpValidCommandLine() {
    cmd_line_.AppendSwitchPath("input-dll", input_dll_path_);
    cmd_line_.AppendSwitchPath("output-dll", output_dll_path_);
  }

 protected:
  base::FilePath temp_dir_;

  // @name The redirected streams paths.
  // @{
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

  // The fake instrumenter we delegate to.
  TestInstrumenterWithAgent instrumenter_;
};

}  // namespace

TEST_F(InstrumenterWithAgentTest, EmptyCommandLineFails) {
  ASSERT_FALSE(instrumenter_.ParseCommandLine(&cmd_line_));
}

TEST_F(InstrumenterWithAgentTest, ParseWithNoInputImageFails) {
  cmd_line_.AppendSwitchPath("output-image", output_dll_path_);

  ASSERT_FALSE(instrumenter_.ParseCommandLine(&cmd_line_));
}

TEST_F(InstrumenterWithAgentTest, ParseWithNoOutputImageFails) {
  cmd_line_.AppendSwitchPath("input-image", input_dll_path_);

  ASSERT_FALSE(instrumenter_.ParseCommandLine(&cmd_line_));
}

TEST_F(InstrumenterWithAgentTest, DeprecatedParseNoModeSpecifyDlls) {
  cmd_line_.AppendSwitchPath("input-dll", input_dll_path_);
  cmd_line_.AppendSwitchPath("output-dll", output_dll_path_);

  EXPECT_TRUE(instrumenter_.ParseCommandLine(&cmd_line_));
  EXPECT_EQ(abs_input_dll_path_, instrumenter_.input_dll_path_);
  EXPECT_EQ(output_dll_path_, instrumenter_.output_dll_path_);

  EXPECT_FALSE(instrumenter_.allow_overwrite_);
  EXPECT_FALSE(instrumenter_.new_decomposer_);
  EXPECT_FALSE(instrumenter_.no_augment_pdb_);
  EXPECT_FALSE(instrumenter_.no_parse_debug_info_);
  EXPECT_FALSE(instrumenter_.no_strip_strings_);
}

TEST_F(InstrumenterWithAgentTest, agent_dll) {
  EXPECT_STREQ(kTestAgentDllName, instrumenter_.agent_dll().c_str());
}

TEST_F(InstrumenterWithAgentTest, Instrument) {
  SetUpValidCommandLine();

  EXPECT_TRUE(instrumenter_.ParseCommandLine(&cmd_line_));
  EXPECT_CALL(instrumenter_.mock_relinker_, Init()).WillOnce(Return(true));
  EXPECT_CALL(instrumenter_.mock_relinker_, Relink()).WillOnce(Return(true));
  EXPECT_CALL(instrumenter_, InstrumentImpl()).WillOnce(Return(true));

  EXPECT_TRUE(instrumenter_.Instrument());
}

TEST_F(InstrumenterWithAgentTest, InstrumentFailsInit) {
  SetUpValidCommandLine();

  EXPECT_CALL(instrumenter_.mock_relinker_, Init()).WillOnce(Return(false));

  EXPECT_FALSE(instrumenter_.Instrument());
}

TEST_F(InstrumenterWithAgentTest, InstrumentFailsRelink) {
  SetUpValidCommandLine();

  EXPECT_CALL(instrumenter_.mock_relinker_, Init()).WillOnce(Return(true));
  EXPECT_CALL(instrumenter_.mock_relinker_, Relink()).WillOnce(Return(false));
  EXPECT_CALL(instrumenter_, InstrumentImpl()).WillOnce(Return(true));

  EXPECT_FALSE(instrumenter_.Instrument());
}

}  // namespace instrumenters
}  // namespace instrument
