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
#include "syzygy/pe/find.h"

#include "base/win/scoped_handle.h"
#include "gtest/gtest.h"
#include "sawbuck/common/com_utils.h"
#include "syzygy/pe/unittest_util.h"

namespace pe {

namespace {

// Gets the FileInformation associated with the file at a given path. Returns
// true on success, false on failure (ie: the file doesn't exist).
bool GetFileInformation(const FilePath& path,
                        BY_HANDLE_FILE_INFORMATION* file_info) {
  DCHECK(file_info != NULL);

  // Open the file in the least restrictive possible way.
  base::win::ScopedHandle handle(
      ::CreateFile(path.value().c_str(),
                   SYNCHRONIZE,
                   FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                   NULL,
                   OPEN_EXISTING,
                   FILE_ATTRIBUTE_NORMAL,
                   NULL));
  if (!handle.IsValid()) {
    LOG(ERROR) << "Unable to open \"" << path.value() << "\": " << com::LogWe();
    return false;
  }

  if (!::GetFileInformationByHandle(handle.Get(), file_info)) {
    LOG(ERROR) << "GetFileInformationByHandle failed for \"" << path.value()
               << "\": " << com::LogWe();
    return false;
  }

  return true;
}

// Compares two paths, returning true if they refer to the same file object.
// Returns 1 if the paths are equal, 0 if not, and -1 on error.
int FilePathsReferToSameFile(const FilePath& path1, const FilePath& path2) {
  BY_HANDLE_FILE_INFORMATION info1 = {};
  if (!GetFileInformation(path1, &info1))
    return -1;

  BY_HANDLE_FILE_INFORMATION info2 = {};
  if (!GetFileInformation(path2, &info2))
    return -1;

  return info1.dwVolumeSerialNumber == info2.dwVolumeSerialNumber &&
      info1.nFileIndexLow == info2.nFileIndexLow &&
      info1.nFileIndexHigh == info2.nFileIndexHigh;
}

// A utility for ensuring that two file paths point to the same file. Upon
// failure, outputs the actual paths as well.
::testing::AssertionResult AssertAreSameFile(const char* path1_expr,
                                             const char* path2_expr,
                                             const FilePath& path1,
                                             const FilePath& path2) {
  int i = FilePathsReferToSameFile(path1, path2);
  if (i == 1)
    return ::testing::AssertionSuccess();

  return ::testing::AssertionFailure() << "FilePathsReferToSameFile("
      << path1_expr << ", " << path2_expr << ") returned " << i
      << ", expected 1 (" << path1_expr << " = \"" << path1.value() << "\", "
      << path2_expr << " = \"" << path2.value() << "\").";
}

// A gtest-like macro for ensuring two paths refer to the same file.
#define EXPECT_SAME_FILE(path1, path2) \
    EXPECT_PRED_FORMAT2(AssertAreSameFile, path1, path2)

class FindTest: public testing::PELibUnitTest {
  // Insert your customizations here.
};

}  // namespace

TEST_F(FindTest, FindTestDll) {
  const FilePath module_path(GetExeRelativePath(kDllName));

  PEFile pe_file;
  ASSERT_TRUE(pe_file.Init(module_path));

  PEFile::Signature module_signature;
  pe_file.GetSignature(&module_signature);

  FilePath found_path;
  EXPECT_TRUE(FindModuleBySignature(module_signature, &found_path));

  EXPECT_SAME_FILE(module_path, found_path);
}

TEST_F(FindTest, FindTestDllPdb) {
  const FilePath module_path(GetExeRelativePath(kDllName));
  const FilePath pdb_path(GetExeRelativePath(kDllPdbName));

  FilePath found_path;
  EXPECT_TRUE(FindPdbForModule(module_path, &found_path));

  EXPECT_SAME_FILE(pdb_path, found_path);
}

}  // namespace pe
