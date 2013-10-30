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

#include "syzygy/instrument/instrumenters/asan_instrumenter.h"

#include "base/command_line.h"
#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/image_filter.h"
#include "syzygy/pe/unittest_util.h"

namespace instrument {
namespace instrumenters {

namespace {

class TestAsanInstrumenter : public AsanInstrumenter {
 public:
  using AsanInstrumenter::agent_dll_;
  using AsanInstrumenter::input_image_path_;
  using AsanInstrumenter::input_pdb_path_;
  using AsanInstrumenter::use_interceptors_;
  using AsanInstrumenter::output_image_path_;
  using AsanInstrumenter::output_pdb_path_;
  using AsanInstrumenter::allow_overwrite_;
  using AsanInstrumenter::new_decomposer_;
  using AsanInstrumenter::no_augment_pdb_;
  using AsanInstrumenter::no_parse_debug_info_;
  using AsanInstrumenter::no_strip_strings_;
  using AsanInstrumenter::filter_path_;
  using AsanInstrumenter::debug_friendly_;
  using AsanInstrumenter::use_liveness_analysis_;
  using AsanInstrumenter::remove_redundant_checks_;
  using AsanInstrumenter::kAgentDllAsan;
  using AsanInstrumenter::InstrumentImpl;
  using InstrumenterWithAgent::CreateRelinker;

  TestAsanInstrumenter() {
    // Call the GetPERelinker function to initialize it.
    EXPECT_TRUE(GetPERelinker() != NULL);
  }
};

class AsanInstrumenterTest : public testing::PELibUnitTest {
 public:
  typedef testing::PELibUnitTest Super;

  AsanInstrumenterTest()
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
    abs_input_image_path_ = testing::GetExeRelativePath(testing::kTestDllName);
    input_image_path_ = testing::GetRelativePath(abs_input_image_path_);
    abs_input_pdb_path_ = testing::GetExeRelativePath(testing::kTestDllPdbName);
    input_pdb_path_ = testing::GetRelativePath(abs_input_pdb_path_);
    output_image_path_ = temp_dir_.Append(input_image_path_.BaseName());
    output_pdb_path_ = temp_dir_.Append(input_pdb_path_.BaseName());
    test_dll_filter_path_ = temp_dir_.Append(L"test_dll_filter.json");
    dummy_filter_path_ = temp_dir_.Append(L"dummy_filter.json");
  }

  void SetUpValidCommandLine() {
    cmd_line_.AppendSwitchPath("input-image", input_image_path_);
    cmd_line_.AppendSwitchPath("output-image", output_image_path_);
  }

 protected:
  void MakeFilters() {
    // Create a valid test_dll filter. Just so it's not empty we mark the NT
    // headers as non-instrumentable.
    pe::ImageFilter filter;
    ASSERT_TRUE(filter.Init(abs_input_image_path_));
    filter.filter.Mark(pe::ImageFilter::RelativeAddressFilter::Range(
        core::RelativeAddress(0), 4096));
    ASSERT_TRUE(filter.SaveToJSON(false, test_dll_filter_path_));

    // Muck up the time date stamp and create an invalid filter.
    filter.signature.module_time_date_stamp ^= 0x0F00BA55;
    ASSERT_TRUE(filter.SaveToJSON(true, dummy_filter_path_));
  }

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
  base::FilePath input_image_path_;
  base::FilePath input_pdb_path_;
  base::FilePath output_image_path_;
  base::FilePath output_pdb_path_;
  base::FilePath test_dll_filter_path_;
  base::FilePath dummy_filter_path_;
  // @}

  // @name Expected final values of input parameters.
  // @{
  base::FilePath abs_input_image_path_;
  base::FilePath abs_input_pdb_path_;
  // @}

  // The fake instrumenter we delegate to.
  TestAsanInstrumenter instrumenter_;
};

}  // namespace

TEST_F(AsanInstrumenterTest, ParseMinimalAsan) {
  SetUpValidCommandLine();

  EXPECT_TRUE(instrumenter_.ParseCommandLine(&cmd_line_));

  EXPECT_EQ(abs_input_image_path_, instrumenter_.input_image_path_);
  EXPECT_EQ(output_image_path_, instrumenter_.output_image_path_);
  EXPECT_EQ(std::string(TestAsanInstrumenter::kAgentDllAsan),
            instrumenter_.agent_dll_);
  EXPECT_FALSE(instrumenter_.allow_overwrite_);
  EXPECT_FALSE(instrumenter_.new_decomposer_);
  EXPECT_FALSE(instrumenter_.no_augment_pdb_);
  EXPECT_FALSE(instrumenter_.no_parse_debug_info_);
  EXPECT_FALSE(instrumenter_.no_strip_strings_);
  EXPECT_FALSE(instrumenter_.debug_friendly_);
  EXPECT_TRUE(instrumenter_.use_interceptors_);
  EXPECT_TRUE(instrumenter_.use_liveness_analysis_);
  EXPECT_TRUE(instrumenter_.remove_redundant_checks_);
}

TEST_F(AsanInstrumenterTest, ParseFullAsan) {
  SetUpValidCommandLine();
  cmd_line_.AppendSwitchPath("filter", test_dll_filter_path_);
  cmd_line_.AppendSwitchASCII("agent", "foo.dll");
  cmd_line_.AppendSwitch("debug-friendly");
  cmd_line_.AppendSwitchPath("input-pdb", input_pdb_path_);
  cmd_line_.AppendSwitch("new-decomposer");
  cmd_line_.AppendSwitch("no-augment-pdb");
  cmd_line_.AppendSwitch("no-interceptors");
  cmd_line_.AppendSwitch("no-parse-debug-info");
  cmd_line_.AppendSwitch("no-strip-strings");
  cmd_line_.AppendSwitchPath("output-pdb", output_pdb_path_);
  cmd_line_.AppendSwitch("overwrite");
  cmd_line_.AppendSwitch("no-liveness-analysis");
  cmd_line_.AppendSwitch("no-redundancy-analysis");

  EXPECT_TRUE(instrumenter_.ParseCommandLine(&cmd_line_));

  EXPECT_EQ(abs_input_image_path_, instrumenter_.input_image_path_);
  EXPECT_EQ(output_image_path_, instrumenter_.output_image_path_);
  EXPECT_EQ(abs_input_pdb_path_, instrumenter_.input_pdb_path_);
  EXPECT_EQ(output_pdb_path_, instrumenter_.output_pdb_path_);
  EXPECT_EQ(test_dll_filter_path_, instrumenter_.filter_path_);
  EXPECT_EQ(std::string("foo.dll"), instrumenter_.agent_dll_);
  EXPECT_TRUE(instrumenter_.allow_overwrite_);
  EXPECT_TRUE(instrumenter_.new_decomposer_);
  EXPECT_TRUE(instrumenter_.no_augment_pdb_);
  EXPECT_TRUE(instrumenter_.no_parse_debug_info_);
  EXPECT_TRUE(instrumenter_.no_strip_strings_);
  EXPECT_TRUE(instrumenter_.debug_friendly_);
  EXPECT_FALSE(instrumenter_.use_interceptors_);
  EXPECT_FALSE(instrumenter_.use_liveness_analysis_);
  EXPECT_FALSE(instrumenter_.remove_redundant_checks_);
}

TEST_F(AsanInstrumenterTest, InstrumentImpl) {
  SetUpValidCommandLine();

  EXPECT_TRUE(instrumenter_.ParseCommandLine(&cmd_line_));
  EXPECT_TRUE(instrumenter_.CreateRelinker());
  EXPECT_TRUE(instrumenter_.InstrumentImpl());
}

TEST_F(AsanInstrumenterTest, FailsWithInvalidFilter) {
  cmd_line_.AppendSwitchPath("input-image", input_image_path_);
  cmd_line_.AppendSwitchPath("output-image", output_image_path_);
  cmd_line_.AppendSwitchPath("filter", dummy_filter_path_);

  // We don't expect the relinker to be called at all, as before we get that far
  // the filter will be identified as being for the wrong module.

  MakeFilters();
  EXPECT_TRUE(instrumenter_.ParseCommandLine(&cmd_line_));
  EXPECT_TRUE(instrumenter_.CreateRelinker());
  EXPECT_FALSE(instrumenter_.InstrumentImpl());
}

TEST_F(AsanInstrumenterTest, SucceedsWithValidFilter) {
  cmd_line_.AppendSwitchPath("input-image", input_image_path_);
  cmd_line_.AppendSwitchPath("output-image", output_image_path_);
  cmd_line_.AppendSwitchPath("filter", test_dll_filter_path_);

  MakeFilters();
  EXPECT_TRUE(instrumenter_.ParseCommandLine(&cmd_line_));
  EXPECT_TRUE(instrumenter_.CreateRelinker());
  EXPECT_TRUE(instrumenter_.InstrumentImpl());
}

}  // namespace instrumenters
}  // namespace instrument
