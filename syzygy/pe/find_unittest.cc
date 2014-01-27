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

#include "syzygy/pe/find.h"

#include "base/win/scoped_handle.h"
#include "gtest/gtest.h"
#include "syzygy/common/com_utils.h"
#include "syzygy/core/file_util.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/unittest_util.h"

namespace pe {

namespace {

class PeFindTest: public testing::PELibUnitTest {
  // Insert your customizations here.
};

}  // namespace

TEST_F(PeFindTest, PeAndPdbAreMatchedMissingFiles) {
  EXPECT_FALSE(PeAndPdbAreMatched(
      base::FilePath(L"nonexistent_pe_file.dll"),
      base::FilePath(L"nonexistent_pdb_file.pdb")));
}

TEST_F(PeFindTest, PeAndPdbAreMatchedMismatchedInputs) {
  EXPECT_FALSE(PeAndPdbAreMatched(
      testing::GetOutputRelativePath(testing::kTestDllName),
      testing::GetOutputRelativePath(L"pe_unittests.exe.pdb")));
}

TEST_F(PeFindTest, PeAndPdbAreMatched) {
  EXPECT_TRUE(PeAndPdbAreMatched(
      testing::GetOutputRelativePath(testing::kTestDllName),
      testing::GetOutputRelativePath(testing::kTestDllPdbName)));
}

TEST_F(PeFindTest, PeFindTestDllNoHint) {
  const base::FilePath module_path(testing::GetOutputRelativePath(
      testing::kTestDllName));

  PEFile pe_file;
  ASSERT_TRUE(pe_file.Init(module_path));

  PEFile::Signature module_signature;
  pe_file.GetSignature(&module_signature);

  base::FilePath found_path;
  EXPECT_TRUE(FindModuleBySignature(module_signature, &found_path));

  EXPECT_SAME_FILE(module_path, found_path);
}

TEST_F(PeFindTest, PeFindTestDllWithHint) {
  const base::FilePath orig_module_path(testing::GetOutputRelativePath(
      testing::kTestDllName));
  const base::FilePath test_data_module_path(
      testing::GetExeTestDataRelativePath(testing::kTestDllName));

  PEFile pe_file;
  ASSERT_TRUE(pe_file.Init(orig_module_path));

  PEFile::Signature module_signature;
  pe_file.GetSignature(&module_signature);

  // We expect the version of test_dll.dll in test_data to be found first
  // because we provide an explicit hint guiding the search in that direction.
  base::FilePath found_path = test_data_module_path;
  EXPECT_TRUE(FindModuleBySignature(module_signature, &found_path));

  EXPECT_SAME_FILE(test_data_module_path, found_path);
}

TEST_F(PeFindTest, PeFindTestDllPdbNoHint) {
  // We have to be careful to use the output relative path, rather than simply
  // the executable relative path. This is because in the coverage unittests
  // pe_unittests.exe and test_dll.dll are copied to a new output directory
  // that contains the instrumented binaries. The copied test_dll.dll still
  // refers to the original test_dll.pdb in the Debug or Release output
  // directory, so that's the one that will be found first.
  const base::FilePath module_path(testing::GetOutputRelativePath(
      testing::kTestDllName));
  const base::FilePath pdb_path(testing::GetOutputRelativePath(
      testing::kTestDllPdbName));

  base::FilePath found_path;
  EXPECT_TRUE(FindPdbForModule(module_path, &found_path));

  EXPECT_SAME_FILE(pdb_path, found_path);
}

TEST_F(PeFindTest, PeFindTestDllPdbWithHint) {
  const base::FilePath module_path(testing::GetOutputRelativePath(
      testing::kTestDllName));
  const base::FilePath pdb_path(testing::GetExeTestDataRelativePath(
      testing::kTestDllPdbName));

  // We provide an explicit hint to look in the test_data directory first. Even
  // though this is not the path that will be found in the debug data directory
  // it should be found first.
  base::FilePath found_path = pdb_path;
  EXPECT_TRUE(FindPdbForModule(module_path, &found_path));

  EXPECT_SAME_FILE(pdb_path, found_path);
}

}  // namespace pe
