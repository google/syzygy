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

#include "syzygy/grinder/find.h"

#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/unittest_util.h"

namespace grinder {

namespace {

class GrinderFindTest: public testing::PELibUnitTest {
 public:
  GrinderFindTest()
      : bad_pe_path(L"nonexistent_pe_file.dll"),
        self_path(testing::GetOutputRelativePath(L"grinder_unittests.exe")) {
  }

  base::FilePath self_path;
  base::FilePath bad_pe_path;
};

}  // namespace

TEST_F(GrinderFindTest, PeFilesAreRelatedFailsBadTransformedPath) {
  EXPECT_FALSE(PeFilesAreRelated(
      bad_pe_path,
      testing::GetExeTestDataRelativePath(testing::kTestDllName)));
}

TEST_F(GrinderFindTest, PeFilesAreRelatedFailsBadOriginalPath) {
  EXPECT_FALSE(PeFilesAreRelated(
      testing::GetExeTestDataRelativePath(
          testing::kCoverageInstrumentedTestDllName),
      bad_pe_path));
}

TEST_F(GrinderFindTest, PeFilesAreRelatedFailsNoMetadata) {
  EXPECT_FALSE(PeFilesAreRelated(
      testing::GetExeTestDataRelativePath(testing::kTestDllName),
      self_path));
}

TEST_F(GrinderFindTest, PeFilesAreRelatedFailsMismatchedPeFiles) {
  EXPECT_FALSE(PeFilesAreRelated(
      testing::GetExeTestDataRelativePath(
          testing::kCoverageInstrumentedTestDllName),
      self_path));
}

TEST_F(GrinderFindTest, PeFilesAreRelatedWorks) {
  EXPECT_TRUE(PeFilesAreRelated(
      testing::GetExeTestDataRelativePath(
          testing::kCoverageInstrumentedTestDllName),
      testing::GetOutputRelativePath(testing::kTestDllName)));
}

TEST_F(GrinderFindTest, FindOriginalPeFileFailsBadPath) {
  base::FilePath path;
  EXPECT_FALSE(FindOriginalPeFile(bad_pe_path, &path));
  EXPECT_TRUE(path.empty());
}

TEST_F(GrinderFindTest, FindOriginalPeFileFailsNoMetadata) {
  // We provide a valid PE file as input, but a file that is not transformed.
  // This should fail because it contains no metadata.
  base::FilePath path;
  EXPECT_FALSE(FindOriginalPeFile(
      testing::GetOutputRelativePath(testing::kTestDllName), &path));
  EXPECT_TRUE(path.empty());
}

TEST_F(GrinderFindTest, FindOriginalPeFileWorksWithHint) {
  base::FilePath expected_path = testing::GetOutputRelativePath(
      testing::kTestDllName);

  // By default FindOriginalPeFile will want to find the test_dll.dll in the
  // test_data directory, not its copy in the output directory. However, by
  // providing it with that as a hint it should look there first.
  base::FilePath path = expected_path;
  EXPECT_TRUE(FindOriginalPeFile(
      testing::GetExeTestDataRelativePath(
          testing::kCoverageInstrumentedTestDllName),
      &path));
  EXPECT_FALSE(path.empty());

  EXPECT_SAME_FILE(expected_path, path);
}

TEST_F(GrinderFindTest, FindOriginalPeFileWorksWithoutHint) {
  // Even though we are searching for the module relative to the unittest
  // executable, we expect it to find the module relative to the original build
  // directory. There are not the same paths in the case of our coverage bot,
  // which copies things to another folder.
  base::FilePath expected_path = testing::GetOutputRelativePath(L"test_data")
      .Append(testing::kTestDllName);

  // In this case we don't provide an explicit hint so it should find the
  // original test_dll.dll in the test_data directory.
  base::FilePath path;
  EXPECT_TRUE(FindOriginalPeFile(
      testing::GetExeTestDataRelativePath(
          testing::kCoverageInstrumentedTestDllName),
      &path));
  EXPECT_FALSE(path.empty());

  EXPECT_SAME_FILE(expected_path, path);
}

}  // namespace grinder
