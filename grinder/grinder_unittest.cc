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

#include "syzygy/grinder/grinder.h"

#include "gtest/gtest.h"
#include "syzygy/common/application.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/unittest_util.h"

namespace grinder {

namespace {

class TestGrinderApp : public GrinderApp {
 public:
  // Expose for testing.
  using GrinderApp::trace_files_;
  using GrinderApp::output_file_;
};

class GrinderAppTest : public testing::PELibUnitTest {
 public:
  typedef testing::PELibUnitTest Super;
  typedef common::Application<TestGrinderApp> TestApplication;

  GrinderAppTest()
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
  TestGrinderApp& impl_;

  // A temporary folder where all IO will be stored.
  FilePath temp_dir_;

  // @name File paths used for the standard IO streams.
  // @{
  FilePath stdin_path_;
  FilePath stdout_path_;
  FilePath stderr_path_;
  // @}
};

}  // namespace

TEST_F(GrinderAppTest, ParseCommandLineFailsWithNoFiles) {
  ASSERT_FALSE(impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(GrinderAppTest, ParseCommandLineTraceFiles) {
  std::vector<FilePath> temp_files;
  for (size_t i = 0; i < 10; ++i) {
    FilePath temp_file;
    ASSERT_TRUE(file_util::CreateTemporaryFileInDir(temp_dir_, &temp_file));
    cmd_line_.AppendArgPath(temp_file);
    temp_files.push_back(temp_file);
  }

  ASSERT_TRUE(impl_.ParseCommandLine(&cmd_line_));
  ASSERT_EQ(temp_files, impl_.trace_files_);
}

TEST_F(GrinderAppTest, ParseCommandLineOutputFile) {
  ASSERT_TRUE(impl_.output_file_.empty());
  cmd_line_.AppendSwitchPath("output-file", FilePath(L"output.txt"));
  cmd_line_.AppendArgPath(
      testing::GetExeTestDataRelativePath(L"profile_traces/trace-1.bin"));

  ASSERT_TRUE(impl_.ParseCommandLine(&cmd_line_));
  ASSERT_EQ(L"output.txt", impl_.output_file_.value());
}

TEST_F(GrinderAppTest, EndToEnd) {
  cmd_line_.AppendArgPath(
      testing::GetExeTestDataRelativePath(L"profile_traces/trace-1.bin"));

  FilePath output_file;
  ASSERT_TRUE(file_util::CreateTemporaryFileInDir(temp_dir_, &output_file));
  ASSERT_TRUE(file_util::Delete(output_file, false));
  cmd_line_.AppendSwitchPath("output-file", output_file);

  ASSERT_TRUE(!file_util::PathExists(output_file));

  EXPECT_EQ(0, app_.Run());

  // Verify that the output file was created.
  EXPECT_TRUE(file_util::PathExists(output_file));
}

} //  namespace grinder

int main(int argc, char** argv) {
  base::AtExitManager at_exit;
  CommandLine::Init(argc, argv);

  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
