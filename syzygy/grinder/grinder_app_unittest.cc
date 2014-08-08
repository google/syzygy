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

#include "syzygy/grinder/grinder_app.h"

#include "base/files/scoped_temp_dir.h"
#include "gtest/gtest.h"
#include "syzygy/common/application.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/unittest_util.h"
#include "syzygy/sampler/unittest_util.h"

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
      : cmd_line_(base::FilePath(L"grinder.exe")),
        impl_(app_.implementation()) {
  }

  virtual void SetUp() OVERRIDE {
    Super::SetUp();

    // Setup the IO streams.
    ASSERT_NO_FATAL_FAILURE(CreateTemporaryDir(&temp_dir_));
    stdin_path_ = temp_dir_.Append(L"NUL");
    stdout_path_ = temp_dir_.Append(L"stdout.txt");
    stderr_path_ = temp_dir_.Append(L"stderr.txt");
    ASSERT_NO_FATAL_FAILURE(InitStreams(
        stdin_path_, stdout_path_, stderr_path_));

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
  base::FilePath temp_dir_;

  // @name File paths used for the standard IO streams.
  // @{
  base::FilePath stdin_path_;
  base::FilePath stdout_path_;
  base::FilePath stderr_path_;
  // @}
};

}  // namespace

TEST_F(GrinderAppTest, ParseCommandLineFailsWithNoMode) {
  cmd_line_.AppendArgPath(base::FilePath(L"foo.dat"));
  ASSERT_FALSE(impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(GrinderAppTest, ParseCommandLineFailsWithNoFiles) {
  cmd_line_.AppendSwitchASCII("mode", "profile");
  ASSERT_FALSE(impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(GrinderAppTest, ParseCommandLineTraceFiles) {
  std::vector<base::FilePath> temp_files;
  cmd_line_.AppendSwitchASCII("mode", "profile");
  for (size_t i = 0; i < 10; ++i) {
    base::FilePath temp_file;
    ASSERT_TRUE(base::CreateTemporaryFileInDir(temp_dir_, &temp_file));
    cmd_line_.AppendArgPath(temp_file);
    temp_files.push_back(temp_file);
  }

  ASSERT_TRUE(impl_.ParseCommandLine(&cmd_line_));
  ASSERT_EQ(temp_files, impl_.trace_files_);
}

TEST_F(GrinderAppTest, ParseCommandLineOutputFile) {
  ASSERT_TRUE(impl_.output_file_.empty());
  cmd_line_.AppendSwitchASCII("mode", "profile");
  cmd_line_.AppendSwitchPath("output-file", base::FilePath(L"output.txt"));
  cmd_line_.AppendArgPath(testing::GetExeTestDataRelativePath(
      testing::kProfileTraceFiles[0]));

  ASSERT_TRUE(impl_.ParseCommandLine(&cmd_line_));
  ASSERT_EQ(L"output.txt", impl_.output_file_.value());
}

TEST_F(GrinderAppTest, BasicBlockEntryEndToEnd) {
  cmd_line_.AppendSwitchASCII("mode", "bbentry");
  cmd_line_.AppendArgPath(testing::GetExeTestDataRelativePath(
      testing::kBBEntryTraceFiles[0]));

  base::FilePath output_file;
  ASSERT_TRUE(base::CreateTemporaryFileInDir(temp_dir_, &output_file));
  ASSERT_TRUE(base::DeleteFile(output_file, false));
  cmd_line_.AppendSwitchPath("output-file", output_file);

  ASSERT_TRUE(!base::PathExists(output_file));

  EXPECT_EQ(0, app_.Run());

  // Verify that the output file was created.
  EXPECT_TRUE(base::PathExists(output_file));
}

TEST_F(GrinderAppTest, ProfileEndToEnd) {
  cmd_line_.AppendSwitchASCII("mode", "profile");
  cmd_line_.AppendArgPath(testing::GetExeTestDataRelativePath(
      testing::kProfileTraceFiles[0]));

  base::FilePath output_file;
  ASSERT_TRUE(base::CreateTemporaryFileInDir(temp_dir_, &output_file));
  ASSERT_TRUE(base::DeleteFile(output_file, false));
  cmd_line_.AppendSwitchPath("output-file", output_file);

  ASSERT_TRUE(!base::PathExists(output_file));

  EXPECT_EQ(0, app_.Run());

  // Verify that the output file was created.
  EXPECT_TRUE(base::PathExists(output_file));
}

TEST_F(GrinderAppTest, CoverageEndToEnd) {
  cmd_line_.AppendSwitchASCII("mode", "coverage");
  cmd_line_.AppendArgPath(testing::GetExeTestDataRelativePath(
      testing::kCoverageTraceFiles[0]));

  base::FilePath output_file;
  ASSERT_TRUE(base::CreateTemporaryFileInDir(temp_dir_, &output_file));
  ASSERT_TRUE(base::DeleteFile(output_file, false));
  cmd_line_.AppendSwitchPath("output-file", output_file);
  cmd_line_.AppendSwitchASCII("output-format", "lcov");

  ASSERT_TRUE(!base::PathExists(output_file));

  EXPECT_EQ(0, app_.Run());

  // Verify that the output file was created.
  EXPECT_TRUE(base::PathExists(output_file));
}

TEST_F(GrinderAppTest, SampleEndToEnd) {
  base::FilePath trace_file = temp_dir_.Append(L"sampler.bin");
  ASSERT_NO_FATAL_FAILURE(testing::WriteDummySamplerTraceFile(trace_file));
  ASSERT_TRUE(base::PathExists(trace_file));

  cmd_line_.AppendSwitchASCII("mode", "sample");
  cmd_line_.AppendSwitchPath(
      "image", testing::GetOutputRelativePath(testing::kTestDllName));
  cmd_line_.AppendArgPath(trace_file);

  base::FilePath output_file;
  ASSERT_TRUE(base::CreateTemporaryFileInDir(temp_dir_, &output_file));
  ASSERT_TRUE(base::DeleteFile(output_file, false));
  cmd_line_.AppendSwitchPath("output-file", output_file);

  ASSERT_TRUE(!base::PathExists(output_file));

  EXPECT_EQ(0, app_.Run());

  // Verify that the output file was created.
  EXPECT_TRUE(base::PathExists(output_file));
}

}  // namespace grinder
