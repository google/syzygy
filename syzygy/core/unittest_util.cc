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

#include "syzygy/core/unittest_util.h"

#include "base/path_service.h"
#include "syzygy/core/file_util.h"

namespace testing {

const wchar_t kExampleArchiveName[] =
    L"syzygy\\core\\test_data\\archive.lib";
const wchar_t kExampleCoff[] =
    L"syzygy\\core\\test_data\\coff.obj";
const wchar_t kExampleCoffLtcgName[] =
    L"syzygy\\core\\test_data\\coff_ltcg.obj";
const wchar_t kExampleCoffMachineTypeNullName[] =
    L"syzygy\\core\\test_data\\machine_type_null.obj";
const wchar_t kExamplePdbName[] =
    L"syzygy\\core\\test_data\\foo.pdb";
const wchar_t kExamplePeDll[] =
    L"syzygy\\core\\test_data\\foo.dll";
const wchar_t kExamplePeExe[] =
    L"syzygy\\core\\test_data\\foo.exe";
const wchar_t kExampleResources32Name[] =
    L"syzygy\\core\\test_data\\resources32.obj";

base::FilePath GetSrcRelativePath(const wchar_t* rel_path) {
  base::FilePath src_dir;
  PathService::Get(base::DIR_SOURCE_ROOT, &src_dir);
  return src_dir.Append(rel_path);
}

base::FilePath GetExeRelativePath(const wchar_t* rel_path) {
  base::FilePath exe_dir;
  PathService::Get(base::DIR_EXE, &exe_dir);
  return exe_dir.Append(rel_path);
}

base::FilePath GetOutputRelativePath(const wchar_t* rel_path) {
  base::FilePath src_dir;
  PathService::Get(base::DIR_SOURCE_ROOT, &src_dir);
  // Append the output path configured by the build system.
  src_dir = src_dir.AppendASCII(BUILD_OUTPUT_DIR);
  return src_dir.Append(rel_path);
}

base::FilePath GetExeTestDataRelativePath(const wchar_t* rel_path) {
  base::FilePath exe_dir;
  PathService::Get(base::DIR_EXE, &exe_dir);
  base::FilePath test_data = exe_dir.Append(L"test_data");
  return test_data.Append(rel_path);
}

base::FilePath GetRelativePath(const base::FilePath& abs_path,
                               const base::FilePath& root_path) {
  DCHECK(abs_path.IsAbsolute());
  DCHECK(!abs_path.empty());
  DCHECK(root_path.IsAbsolute());
  DCHECK(!root_path.empty());

  typedef std::vector<base::FilePath::StringType> PathComponents;

  // Get the components of the target path.
  PathComponents abs_parts;
  abs_path.GetComponents(&abs_parts);

  // Get the components of the current working directory.
  PathComponents root_parts;
  root_path.GetComponents(&root_parts);

  // Make sure they have a common root.
  if (!base::FilePath::CompareEqualIgnoreCase(root_parts[0], abs_parts[0]))
    return base::FilePath();

  // Figure out how much is shared.
  size_t i = 1;
  while (i < std::min(root_parts.size(), abs_parts.size()) &&
         base::FilePath::CompareEqualIgnoreCase(root_parts[i], abs_parts[i])) {
    ++i;
  }

  base::FilePath rel_path;

  // Add parent directory traversal.
  for (size_t j = i; j < root_parts.size(); ++j)
    rel_path = rel_path.Append(base::FilePath::kParentDirectory);

  // Append the rest of the path.
  for (size_t k = i; k < abs_parts.size(); ++k)
    rel_path = rel_path.Append(abs_parts[k]);

  if (rel_path.empty())
    rel_path = base::FilePath(base::FilePath::kCurrentDirectory);

  return rel_path;
}

base::FilePath GetRelativePath(const base::FilePath& abs_path) {
  base::FilePath cur_dir;
  file_util::GetCurrentDirectory(&cur_dir);
  return GetRelativePath(abs_path, cur_dir);
}

AssertionResult AssertAreSameFile(const char* path1_expr,
                                  const char* path2_expr,
                                  const base::FilePath& path1,
                                  const base::FilePath& path2) {
  core::FilePathCompareResult result = core::CompareFilePaths(path1, path2);
  if (result == core::kEquivalentFilePaths)
    return ::testing::AssertionSuccess();

  return ::testing::AssertionFailure() << "FilePathsReferToSameFile("
      << path1_expr << ", " << path2_expr << ") returned " << result
      << ", expected " << core::kEquivalentFilePaths << " (" << path1_expr
      << " = \"" << path1.value() << "\", " << path2_expr << " = \""
      << path2.value() << "\").";
}

}  // namespace testing
