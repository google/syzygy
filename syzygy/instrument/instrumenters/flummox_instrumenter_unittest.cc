// Copyright 2015 Google Inc. All Rights Reserved.
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

#include "syzygy/instrument/instrumenters/flummox_instrumenter.h"

#include "base/command_line.h"
#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/unittest_util.h"

namespace instrument {
namespace instrumenters {

namespace {

static wchar_t kFlummoxConfigGoodPath[] =
    L"syzygy\\instrument\\test_data\\flummox-config-good.json";

class TestFlummoxConfig : public FlummoxInstrumenter::FlummoxConfig {
};

class TestFlummoxInstrumenter : public FlummoxInstrumenter {
 public:
  using FlummoxInstrumenter::input_image_path_;
  using FlummoxInstrumenter::input_pdb_path_;
  using FlummoxInstrumenter::output_image_path_;
  using FlummoxInstrumenter::output_pdb_path_;
  using FlummoxInstrumenter::flummox_config_path_;
  using FlummoxInstrumenter::allow_overwrite_;
  using FlummoxInstrumenter::no_augment_pdb_;
  using FlummoxInstrumenter::no_strip_strings_;
  using FlummoxInstrumenter::debug_friendly_;
  using FlummoxInstrumenter::flummox_transform_;
  using FlummoxInstrumenter::InstrumentPrepare;
  using FlummoxInstrumenter::InstrumentImpl;
  using FlummoxInstrumenter::CreateRelinker;
};

class FlummoxInstrumenterTest : public testing::PELibUnitTest {
 public:
  typedef testing::PELibUnitTest Super;

  FlummoxInstrumenterTest()
      : cmd_line_(base::FilePath(L"instrument.exe")) {
  }

  void SetUp() override {
    testing::Test::SetUp();

    // Reduce clutter the unittest output.
    logging::SetMinLogLevel(logging::LOG_FATAL);

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
    abs_flummox_config_path_ =
        testing::GetSrcRelativePath(kFlummoxConfigGoodPath);
    output_image_path_ = temp_dir_.Append(input_image_path_.BaseName());
    output_pdb_path_ = temp_dir_.Append(input_pdb_path_.BaseName());
    flummox_config_path_ = testing::GetRelativePath(abs_flummox_config_path_);
  }

  void SetUpValidCommandLine() {
    cmd_line_.AppendSwitchPath("input-image", input_image_path_);
    cmd_line_.AppendSwitchPath("output-image", output_image_path_);
    cmd_line_.AppendSwitchPath("flummox-config-path", flummox_config_path_);
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
  base::FilePath flummox_config_path_;
  // @}

  // @name Expected final values of input parameters.
  // @{
  base::FilePath abs_input_image_path_;
  base::FilePath abs_input_pdb_path_;
  base::FilePath abs_flummox_config_path_;
  // @}

  // The fake instrumenter we delegate to.
  TestFlummoxInstrumenter instrumenter_;
};

}  // namespace


TEST_F(FlummoxInstrumenterTest, ParseTargetListEmpty) {
  TestFlummoxConfig config;
  config.ReadFromJSON("{ \"targets\": {} }");
  EXPECT_EQ(0U, config.target_set().size());
  EXPECT_FALSE(config.add_copy());
}

TEST_F(FlummoxInstrumenterTest, ParseTargetListNormal) {
  TestFlummoxConfig config;
  config.ReadFromJSON(R"JSON(
{
  "targets": {
    "foo": [],  // Comment
    "base::bar": [],
    //"unused": [],
    "__baz__": []
  },
  "add_copy": true
}
)JSON");
  EXPECT_EQ(3U, config.target_set().size());
  EXPECT_NE(config.target_set().end(), config.target_set().find("foo"));
  EXPECT_NE(config.target_set().end(), config.target_set().find("base::bar"));
  EXPECT_NE(config.target_set().end(), config.target_set().find("__baz__"));
  EXPECT_TRUE(config.add_copy());
}

TEST_F(FlummoxInstrumenterTest, ParseCommandLineMinimalCoverage) {
  SetUpValidCommandLine();

  EXPECT_TRUE(instrumenter_.ParseCommandLine(&cmd_line_));

  EXPECT_EQ(abs_input_image_path_, instrumenter_.input_image_path_);
  EXPECT_EQ(abs_flummox_config_path_, instrumenter_.flummox_config_path_);
  EXPECT_EQ(output_image_path_, instrumenter_.output_image_path_);

  EXPECT_FALSE(instrumenter_.allow_overwrite_);
  EXPECT_FALSE(instrumenter_.no_augment_pdb_);
  EXPECT_FALSE(instrumenter_.no_strip_strings_);
  EXPECT_FALSE(instrumenter_.debug_friendly_);
}

TEST_F(FlummoxInstrumenterTest, ParseCommandLineFullCoverage) {
  SetUpValidCommandLine();
  cmd_line_.AppendSwitch("debug-friendly");
  cmd_line_.AppendSwitchPath("input-pdb", input_pdb_path_);
  cmd_line_.AppendSwitch("no-augment-pdb");
  cmd_line_.AppendSwitch("no-strip-strings");
  cmd_line_.AppendSwitchPath("output-pdb", output_pdb_path_);
  cmd_line_.AppendSwitch("overwrite");

  EXPECT_TRUE(instrumenter_.ParseCommandLine(&cmd_line_));

  EXPECT_EQ(abs_input_image_path_, instrumenter_.input_image_path_);
  EXPECT_EQ(abs_flummox_config_path_, instrumenter_.flummox_config_path_);
  EXPECT_EQ(output_image_path_, instrumenter_.output_image_path_);
  EXPECT_EQ(abs_input_pdb_path_, instrumenter_.input_pdb_path_);
  EXPECT_EQ(output_pdb_path_, instrumenter_.output_pdb_path_);
  EXPECT_TRUE(instrumenter_.allow_overwrite_);
  EXPECT_TRUE(instrumenter_.no_augment_pdb_);
  EXPECT_TRUE(instrumenter_.no_strip_strings_);
  EXPECT_TRUE(instrumenter_.debug_friendly_);
}

TEST_F(FlummoxInstrumenterTest, InstrumentImpl) {
  SetUpValidCommandLine();

  EXPECT_TRUE(instrumenter_.ParseCommandLine(&cmd_line_));
  EXPECT_TRUE(instrumenter_.InstrumentPrepare());
  EXPECT_TRUE(instrumenter_.CreateRelinker());
  EXPECT_TRUE(instrumenter_.InstrumentImpl());
  // Ensure that the test target lists are read.
  const auto& target_visited =
      instrumenter_.flummox_transform_->target_visited();
  EXPECT_EQ(2U, target_visited.size());
  EXPECT_NE(target_visited.end(), target_visited.find("Used::M"));
  EXPECT_NE(target_visited.end(), target_visited.find("TestUnusedFuncs"));
}

}  // namespace instrumenters
}  // namespace instrument
