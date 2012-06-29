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

#include "syzygy/pdb/pdb_dump.h"

#include "base/file_util.h"
#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pdb/unittest_util.h"
#include "syzygy/pe/unittest_util.h"

namespace pdb {

namespace {

class TestPdbDumpApp : public PdbDumpApp {
 public:
  // @name Expose for testing.
  // @{
  using PdbDumpApp::pdb_files_;
  using PdbDumpApp::explode_streams_;
  using PdbDumpApp::dump_symbol_record_;
  using PdbDumpApp::dump_type_info_;
  // @}
};

class PdbDumpAppTest : public testing::PELibUnitTest {
 public:
  typedef testing::PELibUnitTest Super;
  typedef common::Application<TestPdbDumpApp> TestApplication;

  PdbDumpAppTest()
      : cmd_line_(FilePath(L"grinder.exe")),
        impl_(app_.implementation()) {
  }

  void SetUp() {
    Super::SetUp();

    // Setup the IO streams.
    CreateTemporaryDir(&temp_dir_);
    stdin_path_ = temp_dir_.Append(L"NUL");
    stdout_path_ = temp_dir_.Append(L"stdout.txt");
    stderr_path_ = temp_dir_.Append(L"stderr.txt");
    InitStreams(stdin_path_, stdout_path_, stderr_path_);

    pdb_file_ = temp_dir_.Append(kDllPdbName);
    ASSERT_TRUE(file_util::CopyFile(
        testing::GetExeTestDataRelativePath(kDllPdbName), pdb_file_));

    // Point the application at the test's command-line and IO streams.
    app_.set_command_line(&cmd_line_);
    app_.set_in(in());
    app_.set_out(out());
    app_.set_err(err());
  }

 protected:
  // The command line to be given to the application under test.
  CommandLine cmd_line_;

  // The application object under test.
  TestApplication app_;

  // A reference to the underlying application implementation for convenience.
  TestPdbDumpApp& impl_;

  // A temporary folder where all IO will be stored.
  FilePath temp_dir_;

  // Path to a pdb file in our temp folder.
  FilePath pdb_file_;

  // @name File paths used for the standard IO streams.
  // @{
  FilePath stdin_path_;
  FilePath stdout_path_;
  FilePath stderr_path_;
  // @}
};

}  // namespace

TEST_F(PdbDumpAppTest, Initialization) {
  ASSERT_FALSE(impl_.explode_streams_);
  ASSERT_TRUE(impl_.pdb_files_.empty());
}

TEST_F(PdbDumpAppTest, ParseCommandlineFailsWithNoFiles) {
  ASSERT_FALSE(impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(PdbDumpAppTest, ParseCommandlineSucceedsWithFile) {
  cmd_line_.AppendArgPath(pdb_file_);
  ASSERT_TRUE(impl_.ParseCommandLine(&cmd_line_));

  ASSERT_FALSE(impl_.explode_streams_);
  ASSERT_FALSE(impl_.dump_symbol_record_);
  ASSERT_FALSE(impl_.dump_type_info_);
  ASSERT_EQ(1, impl_.pdb_files_.size());
  ASSERT_EQ(pdb_file_, impl_.pdb_files_[0]);
}

TEST_F(PdbDumpAppTest, ParseCommandlineExplodeStreams) {
  cmd_line_.AppendArgPath(pdb_file_);
  cmd_line_.AppendSwitch("--explode-streams");
  ASSERT_TRUE(impl_.ParseCommandLine(&cmd_line_));

  ASSERT_TRUE(impl_.explode_streams_);
}

TEST_F(PdbDumpAppTest, ParseCommandlineDumpSymbolRecord) {
  cmd_line_.AppendArgPath(pdb_file_);
  cmd_line_.AppendSwitch("--dump-symbol-record");
  ASSERT_TRUE(impl_.ParseCommandLine(&cmd_line_));

  ASSERT_TRUE(impl_.dump_symbol_record_);
}

TEST_F(PdbDumpAppTest, ParseCommandlineDumpTypeInfo) {
  cmd_line_.AppendArgPath(pdb_file_);
  cmd_line_.AppendSwitch("--dump-type-info");
  ASSERT_TRUE(impl_.ParseCommandLine(&cmd_line_));

  ASSERT_TRUE(impl_.dump_type_info_);
}

TEST_F(PdbDumpAppTest, Run) {
  cmd_line_.AppendArgPath(pdb_file_);
  cmd_line_.AppendSwitch("--explode-streams");
  cmd_line_.AppendSwitch("--dump-symbol-record");
  cmd_line_.AppendSwitch("--dump-type-info");

  ASSERT_EQ(0, app_.Run());

  FilePath exploded_dir =
      temp_dir_.Append(std::wstring(kDllPdbName) + L"-streams");
  ASSERT_TRUE(file_util::DirectoryExists(exploded_dir));
}

}  // namespace pdb
