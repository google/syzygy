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

#include "syzygy/genfilter/genfilter_app.h"

#include "base/strings/stringprintf.h"
#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/image_filter.h"
#include "syzygy/pe/unittest_util.h"

namespace genfilter {

namespace {

class TestGenFilterApp : public GenFilterApp {
 public:
  // Expose for testing.
  using GenFilterApp::action_;
  using GenFilterApp::input_image_;
  using GenFilterApp::input_pdb_;
  using GenFilterApp::output_file_;
  using GenFilterApp::inputs_;
  using GenFilterApp::pretty_print_;
  using GenFilterApp::overwrite_;
};

class GenFilterAppTest : public testing::PELibUnitTest {
 public:
  typedef testing::PELibUnitTest Super;
  typedef common::Application<TestGenFilterApp> TestApplication;

  GenFilterAppTest()
      : cmd_line_(base::FilePath(L"genfilter.exe")),
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

    test_dll_ = testing::GetExeRelativePath(testing::kTestDllName);
    test_dll_pdb_ = testing::GetExeRelativePath(testing::kTestDllPdbName);
    output_file_ = temp_dir_.Append(L"output.json");
  }

  // Creates an empty file at the given path.
  void MakeFile(const base::FilePath& path) {
    base::ScopedFILE file(base::OpenFile(path, "wb"));
    ASSERT_TRUE(file.get() != NULL);
  }

  // Generates a file with the given name in the temp directory, returning the
  // path to it.
  void MakeFile(const wchar_t* filename, base::FilePath* path) {
    DCHECK(filename != NULL);
    DCHECK(path != NULL);
    *path = temp_dir_.Append(filename);
    ASSERT_NO_FATAL_FAILURE(MakeFile(*path));
    return;
  }

  // Builds a series of 2 filters, to test out the various set operation
  // actions. Populates filters_ and filter_paths_.
  void BuildFilters() {
    filters_.resize(2);
    filters_[0].Init(test_dll_);
    filters_[1].Init(test_dll_);

    // Create two filters with overlapping ranges so that we can test all of
    // the set operations.
    filters_[0].filter.Mark(pe::ImageFilter::RelativeAddressFilter::Range(
        core::RelativeAddress(0), 1024));
    filters_[1].filter.Mark(pe::ImageFilter::RelativeAddressFilter::Range(
        core::RelativeAddress(512), 1024));

    filter_paths_.resize(filters_.size());
    for (size_t i = 0; i < filters_.size(); ++i) {
      filter_paths_[i] = temp_dir_.Append(
          base::StringPrintf(L"filter-%d.json", i));
      ASSERT_TRUE(filters_[i].SaveToJSON(true, filter_paths_[i]));
    }

    pe::ImageFilter f(filters_[0]);
    f.signature.module_time_date_stamp ^= 0xBAADF00D;
    mismatched_filter_path_ = temp_dir_.Append(L"mismatched-filter.json");
    ASSERT_TRUE(f.SaveToJSON(false, mismatched_filter_path_));
  }

 protected:
  // The command line to be given to the application under test.
  CommandLine cmd_line_;

  // The application object under test.
  TestApplication app_;

  // A reference to the underlying application implementation for convenience.
  TestGenFilterApp& impl_;

  // A temporary folder where all IO will be stored.
  base::FilePath temp_dir_;

  // @name File paths used for the standard IO streams.
  // @{
  base::FilePath stdin_path_;
  base::FilePath stdout_path_;
  base::FilePath stderr_path_;
  // @}

  // A handful of paths.
  base::FilePath test_dll_;
  base::FilePath test_dll_pdb_;
  base::FilePath output_file_;

  // Some generated filters.
  std::vector<pe::ImageFilter> filters_;
  std::vector<base::FilePath> filter_paths_;
  base::FilePath mismatched_filter_path_;
};

}  // namespace

TEST_F(GenFilterAppTest, ParseCommandLineFailsWithNoAction) {
  cmd_line_.AppendArgPath(base::FilePath(L"foo.json"));
  ASSERT_FALSE(impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(GenFilterAppTest, ParseCommandLineFailsWithNoInputFiles) {
  cmd_line_.AppendSwitchASCII("action", "invert");
  ASSERT_FALSE(impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(GenFilterAppTest, ParseCommandLineExplicitInputFiles) {
  std::vector<base::FilePath> temp_files;
  cmd_line_.AppendSwitchASCII("action", "union");
  for (size_t i = 0; i < 10; ++i) {
    base::FilePath temp_file;
    ASSERT_TRUE(base::CreateTemporaryFileInDir(temp_dir_, &temp_file));
    cmd_line_.AppendArgPath(temp_file);
    temp_files.push_back(temp_file);
  }

  ASSERT_TRUE(impl_.ParseCommandLine(&cmd_line_));
  ASSERT_EQ(temp_files, impl_.inputs_);
}

TEST_F(GenFilterAppTest, ParseCommandLineInputFilesGlob) {
  std::vector<base::FilePath> temp_files;
  cmd_line_.AppendSwitchASCII("action", "union");
  for (size_t i = 0; i < 10; ++i) {
    base::FilePath path =
        temp_dir_.Append(base::StringPrintf(L"filter-%d.json", i));
    base::ScopedFILE file(base::OpenFile(path, "wb"));
    temp_files.push_back(path);
  }
  cmd_line_.AppendArgPath(temp_dir_.Append(L"*.json"));

  ASSERT_TRUE(impl_.ParseCommandLine(&cmd_line_));
  ASSERT_EQ(temp_files, impl_.inputs_);
}

TEST_F(GenFilterAppTest, ParseCommandLineMinimal) {
  base::FilePath foo_json;
  ASSERT_NO_FATAL_FAILURE(MakeFile(L"foo.json", &foo_json));

  cmd_line_.AppendArgPath(foo_json);
  cmd_line_.AppendSwitchASCII("action", "invert");
  ASSERT_TRUE(impl_.ParseCommandLine(&cmd_line_));
  EXPECT_EQ(GenFilterApp::kInvert, impl_.action_);
  EXPECT_TRUE(impl_.input_image_.empty());
  EXPECT_TRUE(impl_.input_pdb_.empty());
  EXPECT_TRUE(impl_.output_file_.empty());
  EXPECT_EQ(1u, impl_.inputs_.size());
  EXPECT_FALSE(impl_.overwrite_);
  EXPECT_FALSE(impl_.pretty_print_);
}

TEST_F(GenFilterAppTest, ParseCommandLineFull) {
  base::FilePath foo1_txt, foo2_txt;
  ASSERT_NO_FATAL_FAILURE(MakeFile(L"foo1.txt", &foo1_txt));
  ASSERT_NO_FATAL_FAILURE(MakeFile(L"foo2.txt", &foo2_txt));

  cmd_line_.AppendArgPath(foo1_txt);
  cmd_line_.AppendArgPath(foo2_txt);
  cmd_line_.AppendSwitchASCII("action", "compile");
  cmd_line_.AppendSwitchPath("input-image", test_dll_);
  cmd_line_.AppendSwitchPath("input-pdb", test_dll_pdb_);
  cmd_line_.AppendSwitchPath("output-file", output_file_);
  cmd_line_.AppendSwitch("overwrite");
  cmd_line_.AppendSwitch("pretty-print");
  ASSERT_TRUE(impl_.ParseCommandLine(&cmd_line_));
  EXPECT_EQ(GenFilterApp::kCompile, impl_.action_);
  EXPECT_EQ(test_dll_, impl_.input_image_);
  EXPECT_EQ(test_dll_pdb_, impl_.input_pdb_);
  EXPECT_EQ(output_file_, impl_.output_file_);
  EXPECT_EQ(2u, impl_.inputs_.size());
  EXPECT_TRUE(impl_.overwrite_);
  EXPECT_TRUE(impl_.pretty_print_);
}

TEST_F(GenFilterAppTest, ParseCommandLineInvertFailsWithMultipleInputs) {
  base::FilePath foo1_json, foo2_json;
  ASSERT_NO_FATAL_FAILURE(MakeFile(L"foo1.json", &foo1_json));
  ASSERT_NO_FATAL_FAILURE(MakeFile(L"foo2.json", &foo2_json));

  cmd_line_.AppendSwitchASCII("action", "invert");
  cmd_line_.AppendArgPath(foo1_json);
  cmd_line_.AppendArgPath(foo2_json);
  ASSERT_FALSE(impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(GenFilterAppTest, ParseCommandLineIntersectFailsWithSingleInput) {
  base::FilePath foo_json;
  ASSERT_NO_FATAL_FAILURE(MakeFile(L"foo.json", &foo_json));

  cmd_line_.AppendSwitchASCII("action", "intersect");
  cmd_line_.AppendArgPath(foo_json);
  ASSERT_FALSE(impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(GenFilterAppTest, ParseCommandLineUnionFailsWithSingleInput) {
  base::FilePath foo_json;
  ASSERT_NO_FATAL_FAILURE(MakeFile(L"foo.json", &foo_json));

  cmd_line_.AppendSwitchASCII("action", "union");
  cmd_line_.AppendArgPath(foo_json);
  ASSERT_FALSE(impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(GenFilterAppTest, ParseCommandLineSubtractFailsWithSingleInput) {
  base::FilePath foo_json;
  ASSERT_NO_FATAL_FAILURE(MakeFile(L"foo.json", &foo_json));

  cmd_line_.AppendSwitchASCII("action", "subtract");
  cmd_line_.AppendArgPath(foo_json);
  ASSERT_FALSE(impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(GenFilterAppTest, InvertDoesNotOverwriteExistingOutput) {
  ASSERT_NO_FATAL_FAILURE(BuildFilters());
  ASSERT_NO_FATAL_FAILURE(MakeFile(output_file_));

  cmd_line_.AppendSwitchASCII("action", "invert");
  cmd_line_.AppendArgPath(filter_paths_[0]);
  cmd_line_.AppendSwitchPath("output-file", output_file_);

  base::CopyFile(filter_paths_[0], output_file_);

  ASSERT_TRUE(impl_.ParseCommandLine(&cmd_line_));
  ASSERT_EQ(1, impl_.Run());
}

TEST_F(GenFilterAppTest, InvertOverwriteExistingOutputWorks) {
  ASSERT_NO_FATAL_FAILURE(BuildFilters());
  ASSERT_NO_FATAL_FAILURE(MakeFile(output_file_));

  cmd_line_.AppendSwitchASCII("action", "invert");
  cmd_line_.AppendArgPath(filter_paths_[0]);
  cmd_line_.AppendSwitchPath("output-file", output_file_);
  cmd_line_.AppendSwitch("overwrite");

  base::CopyFile(filter_paths_[0], output_file_);

  ASSERT_TRUE(impl_.ParseCommandLine(&cmd_line_));
  ASSERT_EQ(0, impl_.Run());
}

TEST_F(GenFilterAppTest, InvertSucceeds) {
  ASSERT_NO_FATAL_FAILURE(BuildFilters());

  cmd_line_.AppendSwitchASCII("action", "invert");
  cmd_line_.AppendArgPath(filter_paths_[0]);
  cmd_line_.AppendSwitchPath("output-file", output_file_);

  ASSERT_TRUE(impl_.ParseCommandLine(&cmd_line_));
  ASSERT_EQ(0, impl_.Run());

  ASSERT_TRUE(base::PathExists(output_file_));
  pe::ImageFilter f;
  ASSERT_TRUE(f.LoadFromJSON(output_file_));

  filters_[0].filter.Invert(&filters_[0].filter);
  EXPECT_EQ(filters_[0].filter, f.filter);
}

TEST_F(GenFilterAppTest, IntersectSucceeds) {
  ASSERT_NO_FATAL_FAILURE(BuildFilters());

  cmd_line_.AppendSwitchASCII("action", "intersect");
  cmd_line_.AppendArgPath(filter_paths_[0]);
  cmd_line_.AppendArgPath(filter_paths_[1]);
  cmd_line_.AppendSwitchPath("output-file", output_file_);

  ASSERT_TRUE(impl_.ParseCommandLine(&cmd_line_));
  ASSERT_EQ(0, impl_.Run());

  ASSERT_TRUE(base::PathExists(output_file_));
  pe::ImageFilter f;
  ASSERT_TRUE(f.LoadFromJSON(output_file_));

  filters_[0].filter.Intersect(filters_[1].filter, &filters_[0].filter);
  EXPECT_EQ(filters_[0].filter, f.filter);
}

TEST_F(GenFilterAppTest, SubtractSucceeds) {
  ASSERT_NO_FATAL_FAILURE(BuildFilters());

  cmd_line_.AppendSwitchASCII("action", "subtract");
  cmd_line_.AppendArgPath(filter_paths_[0]);
  cmd_line_.AppendArgPath(filter_paths_[1]);
  cmd_line_.AppendSwitchPath("output-file", output_file_);

  ASSERT_TRUE(impl_.ParseCommandLine(&cmd_line_));
  ASSERT_EQ(0, impl_.Run());

  ASSERT_TRUE(base::PathExists(output_file_));
  pe::ImageFilter f;
  ASSERT_TRUE(f.LoadFromJSON(output_file_));

  filters_[0].filter.Subtract(filters_[1].filter, &filters_[0].filter);
  EXPECT_EQ(filters_[0].filter, f.filter);
}

TEST_F(GenFilterAppTest, UnionSucceeds) {
  ASSERT_NO_FATAL_FAILURE(BuildFilters());

  cmd_line_.AppendSwitchASCII("action", "union");
  cmd_line_.AppendArgPath(filter_paths_[0]);
  cmd_line_.AppendArgPath(filter_paths_[1]);
  cmd_line_.AppendSwitchPath("output-file", output_file_);

  ASSERT_TRUE(impl_.ParseCommandLine(&cmd_line_));
  ASSERT_EQ(0, impl_.Run());

  ASSERT_TRUE(base::PathExists(output_file_));
  pe::ImageFilter f;
  ASSERT_TRUE(f.LoadFromJSON(output_file_));

  filters_[0].filter.Union(filters_[1].filter, &filters_[0].filter);
  EXPECT_EQ(filters_[0].filter, f.filter);
}

TEST_F(GenFilterAppTest, IntersectFailsMismatchedFilters) {
  ASSERT_NO_FATAL_FAILURE(BuildFilters());

  cmd_line_.AppendSwitchASCII("action", "intersect");
  cmd_line_.AppendArgPath(filter_paths_[0]);
  cmd_line_.AppendArgPath(mismatched_filter_path_);
  cmd_line_.AppendSwitchPath("output-file", output_file_);

  ASSERT_TRUE(impl_.ParseCommandLine(&cmd_line_));
  ASSERT_NE(0, impl_.Run());
}

TEST_F(GenFilterAppTest, SubtractFailsMismatchedFilters) {
  ASSERT_NO_FATAL_FAILURE(BuildFilters());

  cmd_line_.AppendSwitchASCII("action", "subtract");
  cmd_line_.AppendArgPath(filter_paths_[0]);
  cmd_line_.AppendArgPath(mismatched_filter_path_);
  cmd_line_.AppendSwitchPath("output-file", output_file_);

  ASSERT_TRUE(impl_.ParseCommandLine(&cmd_line_));
  ASSERT_NE(0, impl_.Run());
}

TEST_F(GenFilterAppTest, UnionFailsMismatchedFilters) {
  ASSERT_NO_FATAL_FAILURE(BuildFilters());

  cmd_line_.AppendSwitchASCII("action", "union");
  cmd_line_.AppendArgPath(filter_paths_[0]);
  cmd_line_.AppendArgPath(mismatched_filter_path_);
  cmd_line_.AppendSwitchPath("output-file", output_file_);

  ASSERT_TRUE(impl_.ParseCommandLine(&cmd_line_));
  ASSERT_NE(0, impl_.Run());
}

TEST_F(GenFilterAppTest, CompileFailsInvalidInput) {
  base::FilePath filter_txt = temp_dir_.Append(L"badfilter.txt");
  {
    base::ScopedFILE file(base::OpenFile(filter_txt, "wb"));
    ::fprintf(file.get(), "This is a badly formatted filter file.");
  }

  cmd_line_.AppendSwitchASCII("action", "compile");
  cmd_line_.AppendArgPath(filter_txt);
  cmd_line_.AppendSwitchPath("output-file", output_file_);
  cmd_line_.AppendSwitchPath("input-image", test_dll_);
  cmd_line_.AppendSwitchPath("input-pdb", test_dll_pdb_);

  ASSERT_TRUE(impl_.ParseCommandLine(&cmd_line_));
  ASSERT_NE(0, impl_.Run());
}

TEST_F(GenFilterAppTest, CompileSucceeds) {
  base::FilePath filter_txt = temp_dir_.Append(L"goodfilter.txt");
  {
    base::ScopedFILE file(base::OpenFile(filter_txt, "wb"));
    ::fprintf(file.get(), "# A commend.\n");
    ::fprintf(file.get(), "+function:DllMain\n");
  }

  cmd_line_.AppendSwitchASCII("action", "compile");
  cmd_line_.AppendArgPath(filter_txt);
  cmd_line_.AppendSwitchPath("output-file", output_file_);
  cmd_line_.AppendSwitchPath("input-image", test_dll_);
  cmd_line_.AppendSwitchPath("input-pdb", test_dll_pdb_);

  ASSERT_TRUE(impl_.ParseCommandLine(&cmd_line_));
  ASSERT_EQ(0, impl_.Run());

  ASSERT_TRUE(base::PathExists(output_file_));
  pe::ImageFilter f;
  ASSERT_TRUE(f.LoadFromJSON(output_file_));
}

}  // namespace genfilter
