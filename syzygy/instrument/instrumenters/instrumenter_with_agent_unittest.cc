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

class MockPERelinker : public pe::PERelinker {
 public:
  MockPERelinker() : pe::PERelinker(&policy_) {
  }

  MOCK_METHOD0(Init, bool());
  MOCK_METHOD0(Relink, bool());

 private:
  pe::PETransformPolicy policy_;
};

class MockCoffRelinker : public pe::CoffRelinker {
 public:
  MockCoffRelinker() : pe::CoffRelinker(&policy_) {
  }

  MOCK_METHOD0(Init, bool());
  MOCK_METHOD0(Relink, bool());

 private:
  pe::CoffTransformPolicy policy_;
};

class TestInstrumenterWithAgent : public InstrumenterWithAgent {
 public:
  using InstrumenterWithAgent::input_image_path_;
  using InstrumenterWithAgent::input_pdb_path_;
  using InstrumenterWithAgent::output_image_path_;
  using InstrumenterWithAgent::output_pdb_path_;
  using InstrumenterWithAgent::allow_overwrite_;
  using InstrumenterWithAgent::old_decomposer_;
  using InstrumenterWithAgent::no_augment_pdb_;
  using InstrumenterWithAgent::no_strip_strings_;

  TestInstrumenterWithAgent() {
    agent_dll_ = kTestAgentDllName;
  }

  // For the purposes of testing, our instrumenter supports all image formats.
  virtual bool ImageFormatIsSupported(pe::ImageFormat image_format) OVERRIDE {
    return true;
  }

  MOCK_METHOD0(InstrumentImpl, bool());

  pe::PERelinker* GetPERelinker() OVERRIDE {
    return &mock_pe_relinker_;
  }

  pe::CoffRelinker* GetCoffRelinker() OVERRIDE {
    return &mock_coff_relinker_;
  }

  virtual const char* InstrumentationMode() OVERRIDE { return "test"; }

  StrictMock<MockPERelinker> mock_pe_relinker_;
  StrictMock<MockCoffRelinker> mock_coff_relinker_;
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
    abs_input_pe_image_path_ = testing::GetExeRelativePath(
        testing::kTestDllName);
    input_pe_image_path_ = testing::GetRelativePath(abs_input_pe_image_path_);
    abs_input_pdb_path_ = testing::GetExeRelativePath(testing::kTestDllPdbName);
    input_pdb_path_ = testing::GetRelativePath(abs_input_pdb_path_);
    output_pe_image_path_ = temp_dir_.Append(input_pe_image_path_.BaseName());
    output_pdb_path_ = temp_dir_.Append(input_pdb_path_.BaseName());

    abs_input_coff_image_path_ = testing::GetExeTestDataRelativePath(
        testing::kTestDllCoffObjName);
    input_coff_image_path_ = testing::GetRelativePath(
        abs_input_coff_image_path_);
    output_coff_image_path_ = temp_dir_.Append(testing::kTestDllCoffObjName);
  }

  void SetUpValidCommandLinePE() {
    cmd_line_.AppendSwitchPath("input-image", input_pe_image_path_);
    cmd_line_.AppendSwitchPath("output-image", output_pe_image_path_);
  }

  void SetUpValidCommandLineCoff() {
    cmd_line_.AppendSwitchPath("input-image", input_coff_image_path_);
    cmd_line_.AppendSwitchPath("output-image", output_coff_image_path_);
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
  base::FilePath input_pe_image_path_;
  base::FilePath input_pdb_path_;
  base::FilePath output_pe_image_path_;
  base::FilePath output_pdb_path_;
  base::FilePath input_coff_image_path_;
  base::FilePath output_coff_image_path_;
  // @}

  // @name Expected final values of input parameters.
  // @{
  base::FilePath abs_input_pe_image_path_;
  base::FilePath abs_input_pdb_path_;
  base::FilePath abs_input_coff_image_path_;
  // @}
};

}  // namespace

TEST_F(InstrumenterWithAgentTest, EmptyCommandLineFails) {
  TestInstrumenterWithAgent instrumenter;
  ASSERT_FALSE(instrumenter.ParseCommandLine(&cmd_line_));
}

TEST_F(InstrumenterWithAgentTest, ParseWithNoInputImageFails) {
  cmd_line_.AppendSwitchPath("output-image", output_pe_image_path_);

  TestInstrumenterWithAgent instrumenter;
  ASSERT_FALSE(instrumenter.ParseCommandLine(&cmd_line_));
}

TEST_F(InstrumenterWithAgentTest, ParseWithNoOutputImageFails) {
  cmd_line_.AppendSwitchPath("input-image", input_pe_image_path_);

  TestInstrumenterWithAgent instrumenter;
  ASSERT_FALSE(instrumenter.ParseCommandLine(&cmd_line_));
}

TEST_F(InstrumenterWithAgentTest, ParseInputImages) {
  cmd_line_.AppendSwitchPath("input-image", input_pe_image_path_);
  cmd_line_.AppendSwitchPath("output-image", output_pe_image_path_);

  TestInstrumenterWithAgent instrumenter;
  EXPECT_TRUE(instrumenter.ParseCommandLine(&cmd_line_));
  EXPECT_EQ(abs_input_pe_image_path_, instrumenter.input_image_path_);
  EXPECT_EQ(output_pe_image_path_, instrumenter.output_image_path_);

  EXPECT_FALSE(instrumenter.allow_overwrite_);
  EXPECT_FALSE(instrumenter.old_decomposer_);
  EXPECT_FALSE(instrumenter.no_augment_pdb_);
  EXPECT_FALSE(instrumenter.no_strip_strings_);
}

TEST_F(InstrumenterWithAgentTest, agent_dll) {
  TestInstrumenterWithAgent instrumenter;
  EXPECT_STREQ(kTestAgentDllName, instrumenter.agent_dll().c_str());
}

TEST_F(InstrumenterWithAgentTest, InstrumentPE) {
  SetUpValidCommandLinePE();

  TestInstrumenterWithAgent instrumenter;
  EXPECT_TRUE(instrumenter.ParseCommandLine(&cmd_line_));
  EXPECT_CALL(instrumenter.mock_pe_relinker_, Init()).WillOnce(Return(true));
  EXPECT_CALL(instrumenter.mock_pe_relinker_, Relink()).WillOnce(Return(true));
  EXPECT_CALL(instrumenter, InstrumentImpl()).WillOnce(Return(true));

  EXPECT_TRUE(instrumenter.Instrument());
}

TEST_F(InstrumenterWithAgentTest, InstrumentCoff) {
  SetUpValidCommandLineCoff();

  TestInstrumenterWithAgent instrumenter;
  EXPECT_TRUE(instrumenter.ParseCommandLine(&cmd_line_));
  EXPECT_CALL(instrumenter.mock_coff_relinker_, Init()).WillOnce(Return(true));
  EXPECT_CALL(instrumenter.mock_coff_relinker_, Relink()).WillOnce(
      Return(true));
  EXPECT_CALL(instrumenter, InstrumentImpl()).WillOnce(Return(true));

  EXPECT_TRUE(instrumenter.Instrument());
}

TEST_F(InstrumenterWithAgentTest, InstrumentFailsInitPE) {
  TestInstrumenterWithAgent instrumenter;
  SetUpValidCommandLinePE();
  EXPECT_TRUE(instrumenter.ParseCommandLine(&cmd_line_));

  EXPECT_CALL(instrumenter.mock_pe_relinker_, Init()).WillOnce(Return(false));

  EXPECT_FALSE(instrumenter.Instrument());
}

TEST_F(InstrumenterWithAgentTest, InstrumentFailsInitCoff) {
  TestInstrumenterWithAgent instrumenter;
  SetUpValidCommandLineCoff();
  EXPECT_TRUE(instrumenter.ParseCommandLine(&cmd_line_));

  EXPECT_CALL(instrumenter.mock_coff_relinker_, Init()).WillOnce(Return(false));

  EXPECT_FALSE(instrumenter.Instrument());
}

TEST_F(InstrumenterWithAgentTest, InstrumentFailsRelinkPE) {
  TestInstrumenterWithAgent instrumenter;
  SetUpValidCommandLinePE();
  EXPECT_TRUE(instrumenter.ParseCommandLine(&cmd_line_));

  EXPECT_CALL(instrumenter.mock_pe_relinker_, Init()).WillOnce(Return(true));
  EXPECT_CALL(instrumenter.mock_pe_relinker_, Relink()).WillOnce(
      Return(false));
  EXPECT_CALL(instrumenter, InstrumentImpl()).WillOnce(Return(true));

  EXPECT_FALSE(instrumenter.Instrument());
}

TEST_F(InstrumenterWithAgentTest, InstrumentFailsRelinkCoff) {
  TestInstrumenterWithAgent instrumenter;
  SetUpValidCommandLineCoff();
  EXPECT_TRUE(instrumenter.ParseCommandLine(&cmd_line_));

  EXPECT_CALL(instrumenter.mock_coff_relinker_, Init()).WillOnce(Return(true));
  EXPECT_CALL(instrumenter.mock_coff_relinker_, Relink()).WillOnce(
      Return(false));
  EXPECT_CALL(instrumenter, InstrumentImpl()).WillOnce(Return(true));

  EXPECT_FALSE(instrumenter.Instrument());
}

}  // namespace instrumenters
}  // namespace instrument
