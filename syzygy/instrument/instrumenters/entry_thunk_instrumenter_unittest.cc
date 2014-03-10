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

#include "syzygy/instrument/instrumenters/entry_thunk_instrumenter.h"

#include "base/command_line.h"
#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/unittest_util.h"

namespace instrument {
namespace instrumenters {

namespace {

class TestEntryThunkInstrumenter : public EntryThunkInstrumenter {
 public:
  using EntryThunkInstrumenter::agent_dll_;
  using EntryThunkInstrumenter::input_image_path_;
  using EntryThunkInstrumenter::input_pdb_path_;
  using EntryThunkInstrumenter::output_image_path_;
  using EntryThunkInstrumenter::output_pdb_path_;
  using EntryThunkInstrumenter::allow_overwrite_;
  using EntryThunkInstrumenter::no_augment_pdb_;
  using EntryThunkInstrumenter::no_strip_strings_;
  using EntryThunkInstrumenter::instrument_unsafe_references_;
  using EntryThunkInstrumenter::module_entry_only_;
  using EntryThunkInstrumenter::thunk_imports_;
  using EntryThunkInstrumenter::debug_friendly_;
  using EntryThunkInstrumenter::instrumentation_mode_;
  using EntryThunkInstrumenter::kAgentDllProfile;
  using EntryThunkInstrumenter::kAgentDllRpc;
  using EntryThunkInstrumenter::InstrumentImpl;
  using InstrumenterWithAgent::CreateRelinker;

  explicit TestEntryThunkInstrumenter(Mode instrumentation_mode)
      : EntryThunkInstrumenter(instrumentation_mode) {
    // Call the GetPERelinker function to initialize it.
    EXPECT_TRUE(GetPERelinker() != NULL);
  }
};

class EntryThunkInstrumenterTest : public testing::PELibUnitTest {
 public:
  typedef testing::PELibUnitTest Super;

  EntryThunkInstrumenterTest()
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
  CommandLine cmd_line_;
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
  scoped_ptr<TestEntryThunkInstrumenter> instrumenter_;
};

}  // namespace

TEST_F(EntryThunkInstrumenterTest, ParseMinimalCallTrace) {
  SetUpValidCommandLine();
  instrumenter_.reset(
      new TestEntryThunkInstrumenter(EntryThunkInstrumenter::CALL_TRACE));

  EXPECT_TRUE(instrumenter_->ParseCommandLine(&cmd_line_));

  EXPECT_EQ(EntryThunkInstrumenter::CALL_TRACE,
            instrumenter_->instrumentation_mode_);
  EXPECT_EQ(abs_input_image_path_, instrumenter_->input_image_path_);
  EXPECT_EQ(output_image_path_, instrumenter_->output_image_path_);
  EXPECT_EQ(std::string(TestEntryThunkInstrumenter::kAgentDllRpc),
            instrumenter_->agent_dll_);
  EXPECT_FALSE(instrumenter_->allow_overwrite_);
  EXPECT_FALSE(instrumenter_->no_augment_pdb_);
  EXPECT_FALSE(instrumenter_->no_strip_strings_);
  EXPECT_FALSE(instrumenter_->debug_friendly_);
  EXPECT_FALSE(instrumenter_->thunk_imports_);
  EXPECT_TRUE(instrumenter_->instrument_unsafe_references_);
  EXPECT_FALSE(instrumenter_->module_entry_only_);
}

TEST_F(EntryThunkInstrumenterTest, ParseFullCallTrace) {
  SetUpValidCommandLine();
  instrumenter_.reset(
      new TestEntryThunkInstrumenter(EntryThunkInstrumenter::CALL_TRACE));

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

  EXPECT_TRUE(instrumenter_->ParseCommandLine(&cmd_line_));

  EXPECT_EQ(EntryThunkInstrumenter::CALL_TRACE,
            instrumenter_->instrumentation_mode_);
  EXPECT_EQ(abs_input_image_path_, instrumenter_->input_image_path_);
  EXPECT_EQ(output_image_path_, instrumenter_->output_image_path_);
  EXPECT_EQ(abs_input_pdb_path_, instrumenter_->input_pdb_path_);
  EXPECT_EQ(output_pdb_path_, instrumenter_->output_pdb_path_);
  EXPECT_EQ(std::string("foo.dll"), instrumenter_->agent_dll_);
  EXPECT_TRUE(instrumenter_->allow_overwrite_);
  EXPECT_TRUE(instrumenter_->no_augment_pdb_);
  EXPECT_TRUE(instrumenter_->no_strip_strings_);
  EXPECT_TRUE(instrumenter_->debug_friendly_);
  EXPECT_TRUE(instrumenter_->thunk_imports_);
  EXPECT_FALSE(instrumenter_->instrument_unsafe_references_);
  EXPECT_TRUE(instrumenter_->module_entry_only_);
}

TEST_F(EntryThunkInstrumenterTest, ParseMinimalProfile) {
  SetUpValidCommandLine();
  instrumenter_.reset(
      new TestEntryThunkInstrumenter(EntryThunkInstrumenter::PROFILE));

  EXPECT_TRUE(instrumenter_->ParseCommandLine(&cmd_line_));

  EXPECT_EQ(EntryThunkInstrumenter::PROFILE,
            instrumenter_->instrumentation_mode_);
  EXPECT_EQ(abs_input_image_path_, instrumenter_->input_image_path_);
  EXPECT_EQ(output_image_path_, instrumenter_->output_image_path_);

  EXPECT_EQ(std::string(TestEntryThunkInstrumenter::kAgentDllProfile),
            instrumenter_->agent_dll_);

  EXPECT_FALSE(instrumenter_->allow_overwrite_);
  EXPECT_FALSE(instrumenter_->no_augment_pdb_);
  EXPECT_FALSE(instrumenter_->no_strip_strings_);
  EXPECT_FALSE(instrumenter_->debug_friendly_);
  EXPECT_FALSE(instrumenter_->thunk_imports_);
  EXPECT_FALSE(instrumenter_->instrument_unsafe_references_);
  EXPECT_FALSE(instrumenter_->module_entry_only_);
}

TEST_F(EntryThunkInstrumenterTest, ParseFullProfile) {
  SetUpValidCommandLine();
  instrumenter_.reset(
      new TestEntryThunkInstrumenter(EntryThunkInstrumenter::PROFILE));
  cmd_line_.AppendSwitchASCII("agent", "foo.dll");
  cmd_line_.AppendSwitch("debug-friendly");
  cmd_line_.AppendSwitchPath("input-pdb", input_pdb_path_);
  cmd_line_.AppendSwitch("no-augment-pdb");
  cmd_line_.AppendSwitch("no-strip-strings");
  cmd_line_.AppendSwitchPath("output-pdb", output_pdb_path_);
  cmd_line_.AppendSwitch("overwrite");
  cmd_line_.AppendSwitch("instrument-imports");

  EXPECT_TRUE(instrumenter_->ParseCommandLine(&cmd_line_));

  EXPECT_EQ(EntryThunkInstrumenter::PROFILE,
            instrumenter_->instrumentation_mode_);
  EXPECT_EQ(abs_input_image_path_, instrumenter_->input_image_path_);
  EXPECT_EQ(output_image_path_, instrumenter_->output_image_path_);
  EXPECT_EQ(abs_input_pdb_path_, instrumenter_->input_pdb_path_);
  EXPECT_EQ(output_pdb_path_, instrumenter_->output_pdb_path_);
  EXPECT_EQ(std::string("foo.dll"), instrumenter_->agent_dll_);
  EXPECT_TRUE(instrumenter_->allow_overwrite_);
  EXPECT_TRUE(instrumenter_->no_augment_pdb_);
  EXPECT_TRUE(instrumenter_->no_strip_strings_);
  EXPECT_TRUE(instrumenter_->debug_friendly_);
  EXPECT_TRUE(instrumenter_->thunk_imports_);
}

TEST_F(EntryThunkInstrumenterTest, InstrumentImplCallTrace) {
  SetUpValidCommandLine();
  instrumenter_.reset(
      new TestEntryThunkInstrumenter(EntryThunkInstrumenter::CALL_TRACE));

  EXPECT_TRUE(instrumenter_->ParseCommandLine(&cmd_line_));
  EXPECT_TRUE(instrumenter_->CreateRelinker());
  EXPECT_TRUE(instrumenter_->InstrumentImpl());
}

TEST_F(EntryThunkInstrumenterTest, InstrumentImplProfile) {
  SetUpValidCommandLine();
  instrumenter_.reset(
      new TestEntryThunkInstrumenter(EntryThunkInstrumenter::PROFILE));

  EXPECT_TRUE(instrumenter_->ParseCommandLine(&cmd_line_));
  EXPECT_TRUE(instrumenter_->CreateRelinker());
  EXPECT_TRUE(instrumenter_->InstrumentImpl());
}

}  // namespace instrumenters
}  // namespace instrument
