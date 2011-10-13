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

#include "gtest/gtest.h"
#include "syzygy/pe/unittest_util.h"

// An ostream operator for FilePath objects. This allows the unittest macros to
// pretty-print FilePath objects.
std::ostream& operator<<(std::ostream& os, const FilePath& file_path) {
  os << file_path.value();
  return os;
}

namespace pe {

namespace {

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

  EXPECT_EQ(module_path, found_path);
}

TEST_F(FindTest, FindTestDllPdb) {
  const FilePath module_path(GetExeRelativePath(kDllName));
  const FilePath pdb_path(GetExeRelativePath(kDllPdbName));

  FilePath found_path;
  EXPECT_TRUE(FindPdbForModule(module_path, &found_path));

  EXPECT_EQ(pdb_path, found_path);
}

}  // namespace pe
