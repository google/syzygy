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
#ifndef SYZYGY_PE_UNITTEST_UTIL_H_
#define SYZYGY_PE_UNITTEST_UTIL_H_

#include <windows.h>
#include "base/file_path.h"
#include "gtest/gtest.h"

namespace testing {

class PELibUnitTest : public testing::Test {
 public:
  // Name of the test DLL and PDB.
  static const wchar_t* const kDllName;
  static const wchar_t* const kDllPdbName;

  // Cleans up after each test invocation.
  virtual void TearDown();

  // Computes the absolute path to image_name, where image_name is relative to
  // the current executable's parent directory.
  static FilePath GetExeRelativePath(const wchar_t* image_name);

  // Computes the absolute path to @p path, where image_name is relative to
  // the output directory of the build.
  static FilePath GetOutputRelativePath(const wchar_t* path);

  // Retrieves the PDB path associated with the PE file at a given path and
  // compares it to an expected path value.
  void CheckEmbeddedPdbPath(const FilePath& pe_path,
                            const FilePath& expected_pdb_path);

  // Creates a temporary directory, which is cleaned up after the test runs.
  void CreateTemporaryDir(FilePath* temp_dir);

  // Performs a series of assertations on the test DLL's integrity.
  static void CheckTestDll(const FilePath& path);

 private:
  typedef testing::Test Super;
  typedef std::vector<const FilePath> DirList;

  // List of temporary directorys created during this test invocation.
  DirList temp_dirs_;
};

}  // namespace testing

#endif  // SYZYGY_PE_UNITTEST_UTIL_H_
