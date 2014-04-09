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

#include "syzygy/ar/ar_writer.h"

#include "base/file_util.h"
#include "gtest/gtest.h"
#include "syzygy/ar/ar_reader.h"
#include "syzygy/core/unittest_util.h"

namespace ar {

namespace {

const wchar_t* kObjectFiles[] = {
    L"syzygy\\ar\\test_data\\adler32.obj",
    L"syzygy\\ar\\test_data\\compress.obj" };
const size_t kSymbolCounts[] = { 3, 3 };

// Test fixture.
class ArWriterTest : public testing::Test {
 public:
  virtual void SetUp() OVERRIDE {
    for (size_t i = 0; i < arraysize(kObjectFiles); ++i)
      object_files_.push_back(testing::GetSrcRelativePath(kObjectFiles[i]));

    ASSERT_TRUE(file_util::CreateNewTempDirectory(L"ArWriterTest",
                                                  &temp_dir_));

    lib_path_ = temp_dir_.Append(L"foo.lib");
  }

  virtual void TearDown() OVERRIDE {
    ASSERT_TRUE(file_util::Delete(temp_dir_, true));
  }

  void AddObjectFiles() {
    for (size_t i = 0; i < object_files_.size(); ++i) {
      size_t old_symbol_count = writer_.symbols().size();
      EXPECT_TRUE(writer_.AddFile(object_files_[i]));
      size_t new_symbol_count = writer_.symbols().size();
      size_t symbol_count = new_symbol_count - old_symbol_count;
      EXPECT_EQ(symbol_count, kSymbolCounts[0]);
    }
  }

  void AddDuplicateObjectFile() {
    ASSERT_TRUE(contents_.empty());

    size_t old_symbol_count = writer_.symbols().size();

    // Add the same object file again but with a different name. This should
    // cause duplicate symbols to be encountered, but it should't be a problem.
    int64 size = 0;
    ASSERT_TRUE(file_util::GetFileSize(object_files_[0], &size));
    contents_.resize(size);
    ASSERT_TRUE(file_util::ReadFile(object_files_[0],
                                    reinterpret_cast<char*>(contents_.data()),
                                    contents_.size()));
    EXPECT_TRUE(writer_.AddFile("foo.obj", base::Time::Now(), 0, &contents_));

    size_t new_symbol_count = writer_.symbols().size();
    EXPECT_EQ(old_symbol_count, new_symbol_count);
  }

  // The object under test.
  ArWriter writer_;

  std::vector<base::FilePath> object_files_;
  base::FilePath temp_dir_;
  base::FilePath lib_path_;

  // Used by 'AddFirstObjectFileWithNewName'.
  DataBuffer contents_;
};

}  // namespace

TEST_F(ArWriterTest, AddValidFiles) {
  EXPECT_NO_FATAL_FAILURE(AddObjectFiles());
  EXPECT_NO_FATAL_FAILURE(AddDuplicateObjectFile());
}

TEST_F(ArWriterTest, AddEmptyFileFails) {
  DataBuffer contents;
  EXPECT_FALSE(writer_.AddFile("foo.obj", base::Time::Now(), 0, &contents));
  EXPECT_TRUE(writer_.files().empty());
  EXPECT_TRUE(writer_.symbols().empty());

  base::FilePath empty_file = temp_dir_.Append(L"empty.obj");
  ASSERT_EQ(0, file_util::WriteFile(empty_file, NULL, 0));
  ASSERT_TRUE(file_util::PathExists(empty_file));
  EXPECT_FALSE(writer_.AddFile(empty_file));
  EXPECT_TRUE(writer_.files().empty());
  EXPECT_TRUE(writer_.symbols().empty());
}

TEST_F(ArWriterTest, AddInvalidObjectFileFails) {
  static const char kContent[] = "hey there";
  base::FilePath dummy_file = temp_dir_.Append(L"dummy.obj");
  ASSERT_EQ(arraysize(kContent),
            file_util::WriteFile(dummy_file, kContent, arraysize(kContent)));
  ASSERT_TRUE(file_util::PathExists(dummy_file));
  EXPECT_FALSE(writer_.AddFile(dummy_file));
  EXPECT_TRUE(writer_.files().empty());
  EXPECT_TRUE(writer_.symbols().empty());
}

TEST_F(ArWriterTest, TestArWriterRoundTrip) {
  EXPECT_NO_FATAL_FAILURE(AddObjectFiles());

  EXPECT_TRUE(writer_.Write(lib_path_));
  EXPECT_TRUE(file_util::PathExists(lib_path_));

  // Read the file to validate it.
  ArReader reader;
  EXPECT_TRUE(reader.Init(lib_path_));
  EXPECT_EQ(2u, reader.offsets().size());
  EXPECT_EQ(6u, reader.symbols().size());
  EXPECT_TRUE(reader.BuildFileIndex());
  while (reader.HasNext()) {
    ParsedArFileHeader header;
    EXPECT_TRUE(reader.ExtractNext(&header, NULL));
  }
}

TEST_F(ArWriterTest, TestArWriterRoundTripDuplicateSymbols) {
  for (size_t i = 0; i < object_files_.size(); ++i)
    EXPECT_TRUE(writer_.AddFile(object_files_[i]));
  EXPECT_NO_FATAL_FAILURE(AddDuplicateObjectFile());

  EXPECT_TRUE(writer_.Write(lib_path_));
  EXPECT_TRUE(file_util::PathExists(lib_path_));

  // Read the file to validate it.
  ArReader reader;
  EXPECT_TRUE(reader.Init(lib_path_));
  EXPECT_EQ(3u, reader.offsets().size());
  EXPECT_EQ(6u, reader.symbols().size());
  EXPECT_TRUE(reader.BuildFileIndex());
  while (reader.HasNext()) {
    ParsedArFileHeader header;
    EXPECT_TRUE(reader.ExtractNext(&header, NULL));
  }
}

}  // namespace ar
