// Copyright 2017 Google Inc. All Rights Reserved.
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
//

#include "syzygy/instrument/instrumenters/afl_instrumenter.h"

#include "base/command_line.h"
#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/unittest_util.h"

namespace instrument {
namespace instrumenters {

namespace {

static const wchar_t kAFLWhitelistPath[] =
    LR"(syzygy\instrument\test_data\afl-good-whitelist.json)";

static const wchar_t kAFLBlacklistPath[] =
    LR"(syzygy\instrument\test_data\afl-good-blacklist.json)";

static const wchar_t kAFLBadConfigPath[] =
    LR"(syzygy\instrument\test_data\afl-bad-config.json)";

static const wchar_t kAFLBadConfigEmptyWhitelistPath[] =
    LR"(syzygy\instrument\test_data\afl-bad-empty-whitelist.json)";

static const wchar_t kAFLBadConfigEmptyBlacklistPath[] =
    LR"(syzygy\instrument\test_data\afl-bad-empty-blacklist.json)";

class TestAFLInstrumenter : public AFLInstrumenter {
 public:
  using AFLInstrumenter::input_image_path_;
  using AFLInstrumenter::input_pdb_path_;
  using AFLInstrumenter::output_image_path_;
  using AFLInstrumenter::output_pdb_path_;
  using AFLInstrumenter::force_decomposition_;
  using AFLInstrumenter::multithread_mode_;
  using AFLInstrumenter::cookie_check_hook_;
  using AFLInstrumenter::target_set_;
  using AFLInstrumenter::whitelist_mode_;
  using InstrumenterWithRelinker::CreateRelinker;
};

class AFLInstrumenterTest : public testing::PELibUnitTest {
 public:
  AFLInstrumenterTest() : cmd_line_(base::FilePath(L"instrument.exe")) {}

  void SetUp() override {
    testing::Test::SetUp();

    // Setup the IO streams.
    CreateTemporaryDir(&temp_dir_);
    stdin_path_ = temp_dir_.Append(L"NUL");
    stdout_path_ = temp_dir_.Append(L"stdout.txt");
    stderr_path_ = temp_dir_.Append(L"stderr.txt");
    InitStreams(stdin_path_, stdout_path_, stderr_path_);

    // Initialize the (potential) input and output path values.
    abs_input_image_path_ = testing::GetExeRelativePath(testing::kTestDllName);
    input_image_path_ = testing::GetRelativePath(abs_input_image_path_);
    abs_input_pdb_path_ = testing::GetExeRelativePath(testing::kTestDllPdbName);
    input_pdb_path_ = testing::GetRelativePath(abs_input_pdb_path_);
    output_pdb_path_ = temp_dir_.Append(input_pdb_path_.BaseName());
    output_image_path_ = temp_dir_.Append(input_image_path_.BaseName());
  }

  void SetUpValidCommandLine() {
    cmd_line_.AppendSwitchPath("input-image", input_image_path_);
    cmd_line_.AppendSwitchPath("output-image", output_image_path_);
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
  base::CommandLine cmd_line_;
  base::FilePath input_image_path_;
  base::FilePath input_pdb_path_;
  base::FilePath output_image_path_;
  base::FilePath output_pdb_path_;
  // @}

  // @name Expected final values of input parameters.
  // @{
  base::FilePath abs_input_image_path_;
  base::FilePath abs_input_pdb_path_;
  // @}

  // The fake instrumenter we delegate to.
  TestAFLInstrumenter instrumenter_;
};

}  // namespace

TEST_F(AFLInstrumenterTest, ParseMinimalCli) {
  SetUpValidCommandLine();

  EXPECT_TRUE(instrumenter_.ParseCommandLine(&cmd_line_));

  EXPECT_EQ(abs_input_image_path_, instrumenter_.input_image_path_);
  EXPECT_EQ(output_image_path_, instrumenter_.output_image_path_);
  EXPECT_FALSE(instrumenter_.force_decomposition_);
  EXPECT_FALSE(instrumenter_.multithread_mode_);
  EXPECT_FALSE(instrumenter_.cookie_check_hook_);
  EXPECT_EQ(instrumenter_.target_set_.size(), 0);
}

TEST_F(AFLInstrumenterTest, ParseFullCli) {
  SetUpValidCommandLine();
  cmd_line_.AppendSwitchPath("input-pdb", input_pdb_path_);
  cmd_line_.AppendSwitch("multithread");
  cmd_line_.AppendSwitch("force-decompose");
  cmd_line_.AppendSwitch("cookie-check-hook");
  cmd_line_.AppendSwitchPath("output-pdb", output_pdb_path_);

  EXPECT_TRUE(instrumenter_.ParseCommandLine(&cmd_line_));

  EXPECT_EQ(abs_input_image_path_, instrumenter_.input_image_path_);
  EXPECT_EQ(output_image_path_, instrumenter_.output_image_path_);
  EXPECT_EQ(abs_input_pdb_path_, instrumenter_.input_pdb_path_);
  EXPECT_EQ(output_pdb_path_, instrumenter_.output_pdb_path_);
  EXPECT_EQ(instrumenter_.target_set_.size(), 0);
  EXPECT_TRUE(instrumenter_.multithread_mode_);
  EXPECT_TRUE(instrumenter_.force_decomposition_);
  EXPECT_TRUE(instrumenter_.cookie_check_hook_);
}

TEST_F(AFLInstrumenterTest, ParseWhitelist) {
  SetUpValidCommandLine();
  cmd_line_.AppendSwitchPath("config",
                             testing::GetSrcRelativePath(kAFLWhitelistPath));

  EXPECT_TRUE(instrumenter_.ParseCommandLine(&cmd_line_));

  EXPECT_TRUE(instrumenter_.whitelist_mode_);
  EXPECT_EQ(instrumenter_.target_set_.size(), 4);
  EXPECT_NE(instrumenter_.target_set_.find("fuzzme"),
            instrumenter_.target_set_.end());
  EXPECT_NE(instrumenter_.target_set_.find("pattern1"),
            instrumenter_.target_set_.end());
  EXPECT_NE(instrumenter_.target_set_.find("_pattern2"),
            instrumenter_.target_set_.end());
  EXPECT_NE(instrumenter_.target_set_.find("Unused::M"),
            instrumenter_.target_set_.end());
}

TEST_F(AFLInstrumenterTest, ParseBlacklist) {
  SetUpValidCommandLine();
  cmd_line_.AppendSwitchPath("config",
                             testing::GetSrcRelativePath(kAFLBlacklistPath));

  EXPECT_TRUE(instrumenter_.ParseCommandLine(&cmd_line_));

  EXPECT_FALSE(instrumenter_.whitelist_mode_);
  EXPECT_EQ(instrumenter_.target_set_.size(), 4);
  EXPECT_NE(instrumenter_.target_set_.find("fuzzme"),
            instrumenter_.target_set_.end());
  EXPECT_NE(instrumenter_.target_set_.find("pattern1"),
            instrumenter_.target_set_.end());
  EXPECT_NE(instrumenter_.target_set_.find("_pattern2"),
            instrumenter_.target_set_.end());
  EXPECT_NE(instrumenter_.target_set_.find("Unused::M"),
            instrumenter_.target_set_.end());
}

TEST_F(AFLInstrumenterTest, ParseWrongConfig) {
  SetUpValidCommandLine();
  cmd_line_.AppendSwitchPath("config",
                             testing::GetSrcRelativePath(kAFLBadConfigPath));

  EXPECT_FALSE(instrumenter_.ParseCommandLine(&cmd_line_));
}

TEST_F(AFLInstrumenterTest, ParseEmptyWhitelist) {
  SetUpValidCommandLine();
  cmd_line_.AppendSwitchPath(
      "config", testing::GetSrcRelativePath(kAFLBadConfigEmptyWhitelistPath));

  EXPECT_FALSE(instrumenter_.ParseCommandLine(&cmd_line_));
  EXPECT_EQ(instrumenter_.target_set_.size(), 0);
}

TEST_F(AFLInstrumenterTest, ParseEmptyBlacklist) {
  SetUpValidCommandLine();
  cmd_line_.AppendSwitchPath(
      "config", testing::GetSrcRelativePath(kAFLBadConfigEmptyBlacklistPath));

  EXPECT_FALSE(instrumenter_.ParseCommandLine(&cmd_line_));
  EXPECT_EQ(instrumenter_.target_set_.size(), 0);
}

TEST_F(AFLInstrumenterTest, InstrumentImpl) {
  SetUpValidCommandLine();

  EXPECT_TRUE(instrumenter_.ParseCommandLine(&cmd_line_));
  EXPECT_TRUE(instrumenter_.InstrumentPrepare());
  EXPECT_TRUE(instrumenter_.CreateRelinker());
  EXPECT_TRUE(instrumenter_.InstrumentImpl());
}

}  // namespace instrumenters
}  // namespace instrument
