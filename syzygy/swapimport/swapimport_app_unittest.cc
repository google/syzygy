// Copyright 2014 Google Inc. All Rights Reserved.
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

#include "syzygy/swapimport/swapimport_app.h"

#include "base/file_util.h"
#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/unittest_util.h"

namespace swapimport {

namespace {

class TestSwapImportApp : public SwapImportApp {
 public:
  using SwapImportApp::import_name_;
  using SwapImportApp::input_image_;
  using SwapImportApp::output_image_;
  using SwapImportApp::overwrite_;
  using SwapImportApp::verbose_;
};

typedef common::Application<TestSwapImportApp> TestApp;

class SwapImportAppTest : public testing::PELibUnitTest {
 public:
  typedef testing::PELibUnitTest Super;

  SwapImportAppTest()
      : cmd_line_(base::FilePath(L"swapimport.exe")),
        test_impl_(test_app_.implementation()) {
  }

  void SetUp() {
    Super::SetUp();

    logging::SetMinLogLevel(logging::LOG_ERROR);

    // Setup the IO streams.
    CreateTemporaryDir(&temp_dir_);
    stdin_path_ = temp_dir_.Append(L"NUL");
    stdout_path_ = temp_dir_.Append(L"stdout.txt");
    stderr_path_ = temp_dir_.Append(L"stderr.txt");
    InitStreams(stdin_path_, stdout_path_, stderr_path_);

    ASSERT_NO_FATAL_FAILURE(ConfigureTestApp(&test_app_));

    input_image_ = testing::GetOutputRelativePath(testing::kTestDllName);
    output_image_ = temp_dir_.Append(testing::kTestDllName);

    input_image_64_ = testing::GetOutputRelativePath(testing::kTestDllName64);
    output_image_64_ = temp_dir_.Append(testing::kTestDllName64);
  }

  template <class PEFileType>
  void ValidateFirstImport(const base::FilePath& image,
                           const char* import_name) {
    PEFileType pe_file;
    ASSERT_TRUE(pe_file.Init(image));

    // Get the absolute address of the first import entry.
    PEFileType::AbsoluteAddress iid_addr(
        pe_file.nt_headers()->OptionalHeader.ImageBase +
            pe_file.nt_headers()->OptionalHeader.DataDirectory[
                IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    // Read the import entry.
    IMAGE_IMPORT_DESCRIPTOR iid = {};
    ASSERT_TRUE(pe_file.ReadImage(iid_addr, &iid, sizeof(iid)));

    // Read the name of the import entry.
    PEFileType::AbsoluteAddress name_addr(
        pe_file.nt_headers()->OptionalHeader.ImageBase + iid.Name);
    std::string name;
    ASSERT_TRUE(pe_file.ReadImageString(name_addr, &name));
    ASSERT_EQ(0, base::strcasecmp(name.c_str(), import_name));
  }

  void ValidateImportsSwapped() {
    ASSERT_NO_FATAL_FAILURE(ValidateFirstImport<pe::PEFile>(input_image_,
                                                            "export_dll.dll"));
    ASSERT_NO_FATAL_FAILURE(ValidateFirstImport<pe::PEFile>(output_image_,
                                                            "kernel32.dll"));
  }

  void ValidateImportsSwapped64() {
    ASSERT_NO_FATAL_FAILURE(ValidateFirstImport<pe::PEFile64>(input_image_64_,
                                                              "user32.dll"));
    ASSERT_NO_FATAL_FAILURE(ValidateFirstImport<pe::PEFile64>(output_image_64_,
                                                              "kernel32.dll"));
  }

  // Points the application at the fixture's command-line and IO streams.
  template<typename TestAppType>
  void ConfigureTestApp(TestAppType* test_app) {
    test_app->set_command_line(&cmd_line_);
    test_app->set_in(in());
    test_app->set_out(out());
    test_app->set_err(err());
  }

  // Stashes the current log-level before each test instance and restores it
  // after each test completes.
  testing::ScopedLogLevelSaver log_level_saver;

  // @name The application under test.
  // @{
  TestApp test_app_;
  TestApp::Implementation& test_impl_;
  base::FilePath temp_dir_;
  base::FilePath stdin_path_;
  base::FilePath stdout_path_;
  base::FilePath stderr_path_;
  // @}

  CommandLine cmd_line_;
  base::FilePath input_image_;
  base::FilePath output_image_;
  base::FilePath input_image_64_;
  base::FilePath output_image_64_;
};

}  // namespace

TEST_F(SwapImportAppTest, GetHelp) {
  cmd_line_.AppendSwitch("help");
  EXPECT_FALSE(test_impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(SwapImportAppTest, ParseEmptyCommandLineFails) {
  EXPECT_FALSE(test_impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(SwapImportAppTest, ParseEmptyCommandFailsNoInputImage) {
  cmd_line_.AppendSwitchPath("output-image", input_image_);
  cmd_line_.AppendArg("kernel32.dll");
  EXPECT_FALSE(test_impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(SwapImportAppTest, ParseEmptyCommandFailsNoOutputImage) {
  cmd_line_.AppendSwitchPath("input-image", input_image_);
  cmd_line_.AppendArg("kernel32.dll");
  EXPECT_FALSE(test_impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(SwapImportAppTest, ParseEmptyCommandFailsNoImportName) {
  cmd_line_.AppendSwitchPath("input-image", input_image_);
  cmd_line_.AppendSwitchPath("output-image", input_image_);
  EXPECT_FALSE(test_impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(SwapImportAppTest, ParseEmptyCommandMinimal) {
  cmd_line_.AppendSwitchPath("input-image", input_image_);
  cmd_line_.AppendSwitchPath("output-image", input_image_);
  cmd_line_.AppendArg("kernel32.dll");
  EXPECT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(SwapImportAppTest, ParseEmptyCommandMaximal) {
  cmd_line_.AppendSwitchPath("input-image", input_image_);
  cmd_line_.AppendSwitchPath("output-image", input_image_);
  cmd_line_.AppendSwitch("overwrite");
  cmd_line_.AppendSwitch("verbose");
  cmd_line_.AppendArg("kernel32.dll");
  EXPECT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(SwapImportAppTest, RunFailsInputAndOutputSame) {
  cmd_line_.AppendSwitchPath("input-image", input_image_);
  cmd_line_.AppendSwitchPath("output-image", input_image_);
  cmd_line_.AppendArg("kernel32.dll");
  ASSERT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  EXPECT_NE(0, test_impl_.Run());
}

TEST_F(SwapImportAppTest, RunFailsOutputExists) {
  file_util::WriteFile(output_image_, "a", 1);

  cmd_line_.AppendSwitchPath("input-image", input_image_);
  cmd_line_.AppendSwitchPath("output-image", output_image_);
  cmd_line_.AppendArg("kernel32.dll");
  ASSERT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  EXPECT_NE(0, test_impl_.Run());
}

TEST_F(SwapImportAppTest, RunFailsImportNameNotMatched) {
  cmd_line_.AppendSwitchPath("input-image", input_image_);
  cmd_line_.AppendSwitchPath("output-image", output_image_);
  cmd_line_.AppendArg("nosuchimport.dll");
  ASSERT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  EXPECT_NE(0, test_impl_.Run());
}

TEST_F(SwapImportAppTest, RunSucceeds) {
  cmd_line_.AppendSwitchPath("input-image", input_image_);
  cmd_line_.AppendSwitchPath("output-image", output_image_);
  cmd_line_.AppendArg("kernel32.dll");
  ASSERT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  EXPECT_EQ(0, test_impl_.Run());

  ASSERT_NO_FATAL_FAILURE(ValidateImportsSwapped());
}

TEST_F(SwapImportAppTest, RunSucceedsOverwrite) {
  file_util::WriteFile(output_image_, "a", 1);

  cmd_line_.AppendSwitchPath("input-image", input_image_);
  cmd_line_.AppendSwitchPath("output-image", output_image_);
  cmd_line_.AppendSwitch("overwrite");
  cmd_line_.AppendArg("kernel32.dll");
  ASSERT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  EXPECT_EQ(0, test_impl_.Run());

  ASSERT_NO_FATAL_FAILURE(ValidateImportsSwapped());
}

TEST_F(SwapImportAppTest, RunSucceeds64) {
  cmd_line_.AppendSwitch("x64");
  cmd_line_.AppendSwitchPath("input-image", input_image_64_);
  cmd_line_.AppendSwitchPath("output-image", output_image_64_);
  cmd_line_.AppendArg("kernel32.dll");
  ASSERT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  EXPECT_EQ(0, test_impl_.Run());

  ASSERT_NO_FATAL_FAILURE(ValidateImportsSwapped64());
}

TEST_F(SwapImportAppTest, Run64On32BitBinaryFails) {
  cmd_line_.AppendSwitch("x64");
  cmd_line_.AppendSwitchPath("input-image", input_image_);
  cmd_line_.AppendSwitchPath("output-image", output_image_);
  cmd_line_.AppendArg("kernel32.dll");
  ASSERT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  EXPECT_NE(0, test_impl_.Run());
  EXPECT_FALSE(file_util::PathExists(output_image_));
}

TEST_F(SwapImportAppTest, Run32On64BitBinaryFails) {
  cmd_line_.AppendSwitchPath("input-image", input_image_64_);
  cmd_line_.AppendSwitchPath("output-image", output_image_64_);
  cmd_line_.AppendArg("kernel32.dll");
  ASSERT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  EXPECT_NE(0, test_impl_.Run());
  EXPECT_FALSE(file_util::PathExists(output_image_64_));
}

}  // namespace swapimport
