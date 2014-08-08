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

#include "syzygy/pdbfind/pdbfind_app.h"

#include "base/file_util.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/strings/utf_string_conversions.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/unittest_util.h"

namespace pdbfind {

namespace {

class TestPdbFindApp : public PdbFindApp {
 public:
  using PdbFindApp::input_image_path_;
};

typedef common::Application<TestPdbFindApp> TestApp;

class PdbFindAppTest : public testing::PELibUnitTest {
 public:
  typedef testing::PELibUnitTest Super;

  PdbFindAppTest()
      : app_impl_(app_.implementation()),
        cmd_line_(base::FilePath(L"pdbfind.exe")),
        old_log_level_(0) {
  }

  void SetUp() OVERRIDE {
    Super::SetUp();

    // Several of the tests generate progress and (deliberate) error messages
    // that would otherwise clutter the unittest output.
    old_log_level_ = logging::GetMinLogLevel();
    logging::SetMinLogLevel(logging::LOG_FATAL);

    // Setup the IO streams.
    CreateTemporaryDir(&temp_dir_);
    stdin_path_ = temp_dir_.Append(L"NUL");
    stdout_path_ = temp_dir_.Append(L"stdout.txt");
    stderr_path_ = temp_dir_.Append(L"stderr.txt");
    InitStreams(stdin_path_, stdout_path_, stderr_path_);

    // Point the application at the test's command-line, IO streams and mock
    // machinery.
    app_.set_command_line(&cmd_line_);
    app_.set_in(in());
    app_.set_out(out());
    app_.set_err(err());
  }

  void TearDown() OVERRIDE {
    logging::SetMinLogLevel(old_log_level_);

    Super::TearDown();
  }

  TestApp app_;
  TestApp::Implementation& app_impl_;

  base::FilePath temp_dir_;
  base::FilePath stdin_path_;
  base::FilePath stdout_path_;
  base::FilePath stderr_path_;

  CommandLine cmd_line_;
  int old_log_level_;
};

}  // namespace

TEST_F(PdbFindAppTest, GetHelp) {
  cmd_line_.AppendSwitch("help");
  ASSERT_FALSE(app_impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(PdbFindAppTest, EmptyCommandLineFails) {
  ASSERT_FALSE(app_impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(PdbFindAppTest, TooManyArgumentsFails) {
  cmd_line_.AppendArg("foo.dll");
  cmd_line_.AppendArg("bar.dll");
  ASSERT_FALSE(app_impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(PdbFindAppTest, ParseWithOneArgumentPasses) {
  cmd_line_.AppendArg("foo.dll");
  ASSERT_TRUE(app_impl_.ParseCommandLine(&cmd_line_));
  EXPECT_EQ(app_impl_.input_image_path_, base::FilePath(L"foo.dll"));
}

TEST_F(PdbFindAppTest, ModuleNotFound) {
  base::FilePath module = testing::GetExeRelativePath(L"made_up_module.dll");
  cmd_line_.AppendArgPath(module);
  ASSERT_EQ(1, app_.Run());
}

// TODO(chrisha): More tests with images that are missing the corresponding
//     PDB or are missing CodeView records.

TEST_F(PdbFindAppTest, Succeeds) {
  base::FilePath test_dll = testing::GetExeRelativePath(testing::kTestDllName);
  cmd_line_.AppendArgPath(test_dll);
  ASSERT_EQ(0, app_.Run());

  base::FilePath expected_pdb_path = testing::GetExeRelativePath(
      testing::kTestDllPdbName);

  // We have to tear down the streams to make sure their contents are flushed
  // to disk.
  TearDownStreams();
  std::string actual_stdout;
  ASSERT_TRUE(base::ReadFileToString(stdout_path_, &actual_stdout));
  base::TrimWhitespaceASCII(actual_stdout, base::TRIM_TRAILING,
                            &actual_stdout);
  base::FilePath actual_pdb_path(base::ASCIIToWide(actual_stdout));
  EXPECT_TRUE(base::PathExists(actual_pdb_path));

#ifdef _COVERAGE_BUILD
  // In the coverage build the module is actually copied to a temporary
  // directory, but the CodeView entry still points to the original PDB.
  expected_pdb_path = expected_pdb_path.BaseName();
  actual_pdb_path = actual_pdb_path.BaseName();
  EXPECT_EQ(expected_pdb_path, actual_pdb_path);
#else
  // Our typical build environment includes a secondary drive that is mounted
  // at a location on the C drive. As such there are two possible paths to the
  // same file. We actually care that the expected path and the returned path
  // refer to the same file on disk rather than having exactly the same path.
  EXPECT_SAME_FILE(expected_pdb_path, actual_pdb_path);
#endif
}

}  // namespace pdbfind
