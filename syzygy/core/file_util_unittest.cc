// Copyright 2011 Google Inc. All Rights Reserved.
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
//
// Unittests for core::file_util.h.

#include "syzygy/core/file_util.h"

#include "base/command_line.h"
#include "base/file_util.h"
#include "base/files/scoped_temp_dir.h"
#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"

namespace core {

namespace {

// For FilePath pretty-printing.
std::ostream& operator<<(std::ostream& ostream, const base::FilePath& path) {
  ostream << "base::FilePath(" << path.value().c_str() << ")";
  return ostream;
}

class CompareFilePathsTest : public testing::Test {
 public:
  virtual void SetUp() {
    // Initialize the temp directory for the first test.
    if (temp_dir_.get() == NULL) {
      temp_dir_.reset(new base::ScopedTempDir());
      ASSERT_TRUE(temp_dir_->CreateUniqueTempDir());
    }

    existing_path_ = testing::GetSrcRelativePath(L"syzygy\\core\\file_util.h");
    alternate_existing_path_ = testing::GetSrcRelativePath(
        L"syzygy\\core\\..\\..\\syzygy\\core\\file_util.h");
    another_existing_path_ =
        testing::GetSrcRelativePath(L"syzygy\\core\\file_util.cc");

    ASSERT_TRUE(base::PathExists(existing_path_));
    ASSERT_TRUE(base::PathExists(alternate_existing_path_));
    ASSERT_NE(existing_path_, alternate_existing_path_);
    ASSERT_TRUE(base::PathExists(another_existing_path_));

    nonexisting_path_ = temp_dir_->path().Append(L"does\\not\\exist.txt");
    alternate_nonexisting_path_ = temp_dir_->path().Append(
        L"does\\not\\..\\not\\exist.txt");
    another_nonexisting_path_ = temp_dir_->path().Append(
        L"nonexisting.txt");

    ASSERT_FALSE(base::PathExists(nonexisting_path_));
    ASSERT_FALSE(base::PathExists(alternate_nonexisting_path_));
    ASSERT_NE(nonexisting_path_, alternate_nonexisting_path_);
    ASSERT_FALSE(base::PathExists(another_nonexisting_path_));
  }

  base::FilePath existing_path_;
  base::FilePath alternate_existing_path_;
  base::FilePath another_existing_path_;

  base::FilePath nonexisting_path_;
  base::FilePath alternate_nonexisting_path_;
  base::FilePath another_nonexisting_path_;

  // This is static so that it is only initialized once for this whole group
  // of tests.
  static scoped_ptr<base::ScopedTempDir> temp_dir_;
};

scoped_ptr<base::ScopedTempDir> CompareFilePathsTest::temp_dir_;

}  // namespace

TEST_F(CompareFilePathsTest, NeitherExistsDistinctPaths) {
  EXPECT_EQ(kUnableToCompareFilePaths,
            CompareFilePaths(nonexisting_path_,
                             another_nonexisting_path_));
}

TEST_F(CompareFilePathsTest, NeitherExistsIdenticalPaths) {
  EXPECT_EQ(kEquivalentFilePaths,
            CompareFilePaths(nonexisting_path_,
                             nonexisting_path_));
}

TEST_F(CompareFilePathsTest, NeitherExistsEquivalentPaths) {
  EXPECT_EQ(kEquivalentFilePaths,
            CompareFilePaths(nonexisting_path_,
                             alternate_nonexisting_path_));
}

TEST_F(CompareFilePathsTest, OnlyPath1Exists) {
  EXPECT_EQ(kDistinctFilePaths,
            CompareFilePaths(existing_path_,
                             nonexisting_path_));
}

TEST_F(CompareFilePathsTest, OnlyPath2Exists) {
  EXPECT_EQ(kDistinctFilePaths,
            CompareFilePaths(nonexisting_path_,
                             existing_path_));
}

TEST_F(CompareFilePathsTest, BothExistDistinctPaths) {
  EXPECT_EQ(kDistinctFilePaths,
            CompareFilePaths(existing_path_,
                             another_existing_path_));
}

TEST_F(CompareFilePathsTest, BothExistSamePath) {
  EXPECT_EQ(kEquivalentFilePaths,
            CompareFilePaths(existing_path_,
                             existing_path_));
}

TEST_F(CompareFilePathsTest, BothExistEquivalentPath) {
  EXPECT_EQ(kEquivalentFilePaths,
            CompareFilePaths(existing_path_,
                             alternate_existing_path_));
}

TEST(GuessFileTypeTest, GuessFromInMemoryBuffer) {
  // Read a file into memory.
  base::FilePath path = testing::GetSrcRelativePath(
      testing::kExampleCoffImportDefinition);
  int64 file_size = 0;
  ASSERT_TRUE(base::GetFileSize(path, &file_size));
  size_t length = static_cast<size_t>(file_size);
  std::vector<uint8> buffer(length);
  ASSERT_TRUE(base::ReadFile(
      path, reinterpret_cast<char*>(buffer.data()), buffer.size()));

  FileType file_type = kUnknownFileType;
  EXPECT_TRUE(GuessFileType(buffer.data(), buffer.size(), &file_type));
  EXPECT_EQ(kImportDefinitionFileType, file_type);
}

TEST(GuessFileTypeTest, IdentifiesAllTypes) {
  base::FilePath fake(L"C:\\this\\path\\should\\not\\exist-at.all");
  base::FilePath dir = testing::GetSrcRelativePath(L"syzygy\\core\\test_data");
  base::FilePath pe_dll = testing::GetSrcRelativePath(testing::kExamplePeDll);
  base::FilePath coff_obj = testing::GetSrcRelativePath(testing::kExampleCoff);
  base::FilePath ltcg_obj = testing::GetSrcRelativePath(
      testing::kExampleCoffLtcgName);
  base::FilePath pe_exe = testing::GetSrcRelativePath(testing::kExamplePeExe);
  base::FilePath pdb = testing::GetSrcRelativePath(testing::kExamplePdbName);
  base::FilePath null_machine_coff = testing::GetSrcRelativePath(
      testing::kExampleCoffMachineTypeNullName);
  base::FilePath resources32 = testing::GetSrcRelativePath(
      testing::kExampleResources32Name);
  base::FilePath archive = testing::GetSrcRelativePath(
      testing::kExampleArchiveName);
  base::FilePath import_def = testing::GetSrcRelativePath(
      testing::kExampleCoffImportDefinition);

  // Doesn't exist.
  FileType file_type = kUnknownFileType;
  EXPECT_FALSE(GuessFileType(fake, &file_type));
  EXPECT_EQ(kUnknownFileType, file_type);

  // Can't be opened for reading.
  file_type = kUnknownFileType;
  EXPECT_FALSE(GuessFileType(dir, &file_type));
  EXPECT_EQ(kUnknownFileType, file_type);

  file_type = kUnknownFileType;
  EXPECT_TRUE(GuessFileType(pe_dll, &file_type));
  EXPECT_EQ(kPeFileType, file_type);

  file_type = kUnknownFileType;
  EXPECT_TRUE(GuessFileType(coff_obj, &file_type));
  EXPECT_EQ(kCoffFileType, file_type);

  file_type = kUnknownFileType;
  EXPECT_TRUE(GuessFileType(ltcg_obj, &file_type));
  EXPECT_EQ(kAnonymousCoffFileType, file_type);

  file_type = kUnknownFileType;
  EXPECT_TRUE(GuessFileType(pe_exe, &file_type));
  EXPECT_EQ(kPeFileType, file_type);

  file_type = kUnknownFileType;
  EXPECT_TRUE(GuessFileType(pdb, &file_type));
  EXPECT_EQ(kPdbFileType, file_type);

  file_type = kUnknownFileType;
  EXPECT_TRUE(GuessFileType(null_machine_coff, &file_type));
  EXPECT_EQ(kCoffFileType, file_type);

  file_type = kUnknownFileType;
  EXPECT_TRUE(GuessFileType(resources32, &file_type));
  EXPECT_EQ(kResourceFileType, file_type);

  file_type = kUnknownFileType;
  EXPECT_TRUE(GuessFileType(archive, &file_type));
  EXPECT_EQ(kArchiveFileType, file_type);

  file_type = kUnknownFileType;
  EXPECT_TRUE(GuessFileType(import_def, &file_type));
  EXPECT_EQ(kImportDefinitionFileType, file_type);
}

}  // namespace core
