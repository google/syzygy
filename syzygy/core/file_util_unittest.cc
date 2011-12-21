// Copyright 2011 Google Inc.
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
#include "base/scoped_temp_dir.h"
#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"

namespace core {

namespace {

// For FilePath pretty-printing.
std::ostream& operator<<(std::ostream& ostream, const FilePath& path) {
  ostream << "FilePath(" << path.value().c_str() << ")";
  return ostream;
}

class CompareFilePathsTest : public testing::Test {
 public:
  virtual void SetUp() {
    // Initialize the temp directory for the first test.
    if (temp_dir_.get() == NULL) {
      temp_dir_.reset(new ScopedTempDir());
      ASSERT_TRUE(temp_dir_->CreateUniqueTempDir());
    }

    existing_path_ = testing::GetSrcRelativePath(L"syzygy\\core\\file_util.h");
    alternate_existing_path_ = testing::GetSrcRelativePath(
        L"syzygy\\core\\..\\..\\syzygy\\core\\file_util.h");
    another_existing_path_ =
        testing::GetSrcRelativePath(L"syzygy\\core\\file_util.cc");

    ASSERT_TRUE(file_util::PathExists(existing_path_));
    ASSERT_TRUE(file_util::PathExists(alternate_existing_path_));
    ASSERT_NE(existing_path_, alternate_existing_path_);
    ASSERT_TRUE(file_util::PathExists(another_existing_path_));

    nonexisting_path_ = temp_dir_->path().Append(L"does\\not\\exist.txt");
    alternate_nonexisting_path_ = temp_dir_->path().Append(
        L"does\\not\\..\\not\\exist.txt");
    another_nonexisting_path_ = temp_dir_->path().Append(
        L"nonexisting.txt");

    ASSERT_FALSE(file_util::PathExists(nonexisting_path_));
    ASSERT_FALSE(file_util::PathExists(alternate_nonexisting_path_));
    ASSERT_NE(nonexisting_path_, alternate_nonexisting_path_);
    ASSERT_FALSE(file_util::PathExists(another_nonexisting_path_));
  }

  FilePath existing_path_;
  FilePath alternate_existing_path_;
  FilePath another_existing_path_;

  FilePath nonexisting_path_;
  FilePath alternate_nonexisting_path_;
  FilePath another_nonexisting_path_;

  // This is static so that it is only initialized once for this whole group
  // of tests.
  static scoped_ptr<ScopedTempDir> temp_dir_;
};

scoped_ptr<ScopedTempDir> CompareFilePathsTest::temp_dir_;

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

}  // namespace core
