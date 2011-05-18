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
#include "syzygy/pe/unittest_util.h"

#include <imagehlp.h>
#include "base/file_util.h"
#include "base/logging.h"
#include "base/path_service.h"
#include "base/stringprintf.h"
#include "base/utf_string_conversions.h"
#include "base/win/pe_image.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace {

bool EnumImportsProc(const base::win::PEImage &image,
                     const char* module,
                     DWORD ordinal,
                     const char* name,
                     DWORD hint,
                     IMAGE_THUNK_DATA* iat,
                     void* cookie) {
  DCHECK(module != NULL);
  DCHECK(iat != NULL);
  DCHECK(cookie != NULL);

  std::set<std::string>* export_dll_imports =
      reinterpret_cast<std::set<std::string>*>(cookie);

  if (strcmp(module, "export_dll.dll") == 0) {
    if (name != NULL) {
      EXPECT_TRUE(export_dll_imports->insert(name).second);
    } else {
      std::string ordinal_name(base::StringPrintf("#%d", ordinal));
      EXPECT_TRUE(export_dll_imports->insert(ordinal_name).second);
    }
  }

  return true;
}

void CheckLoadedTestDll(HMODULE module) {
  // Load the exported TestExport function and invoke it.
  typedef DWORD (WINAPI* TestExportFunc)(size_t buf_len, char* buf);
  TestExportFunc test_func = reinterpret_cast<TestExportFunc>(
      ::GetProcAddress(module, "TestExport"));
  ASSERT_TRUE(test_func != NULL);

  char buffer[1024] = { 0 };
  EXPECT_EQ(0, test_func(arraysize(buffer), buffer));
  EXPECT_STREQ("The quick brown fox jumped over the lazy dog", buffer);

  // Load the exported TestUnusedFunc function and invoke it.
  typedef void (CALLBACK* TestUnusedFuncs)(HWND, HINSTANCE, LPSTR, int);
  TestUnusedFuncs test_func2 = reinterpret_cast<TestUnusedFuncs>(
      ::GetProcAddress(module, "TestUnusedFuncs"));
  ASSERT_TRUE(test_func2 != NULL);
  test_func2(0, 0, 0, 0);

  // Check the image file for sanity.
  base::win::PEImage image(module);
  ASSERT_TRUE(image.VerifyMagic());

  std::set<std::string> export_dll_imports;
  // Verify all the imports from export_dll.
  ASSERT_TRUE(image.EnumAllImports(EnumImportsProc, &export_dll_imports));

  std::set<std::string> expected_imports;
  expected_imports.insert("function1");
  expected_imports.insert("#7");
  expected_imports.insert("function3");
  EXPECT_THAT(expected_imports, testing::ContainerEq(export_dll_imports));
}

}  // namespace

namespace testing {

const wchar_t* const PELibUnitTest::kDllName = L"test_dll.dll";
const wchar_t* const PELibUnitTest::kDllPdbName = L"test_dll.pdb";

void PELibUnitTest::CreateTemporaryDir(FilePath* temp_dir) {
  ASSERT_TRUE(file_util::CreateNewTempDirectory(L"", temp_dir));
  temp_dirs_.push_back(*temp_dir);
}

void PELibUnitTest::TearDown() {
  DirList::const_iterator iter;
  for (iter = temp_dirs_.begin(); iter != temp_dirs_.end(); ++iter) {
    file_util::Delete(*iter, true);
  }

  Super::TearDown();
}

FilePath PELibUnitTest::GetExeRelativePath(const wchar_t* image_name) {
  FilePath exe_dir;
  PathService::Get(base::DIR_EXE, &exe_dir);

  return exe_dir.Append(image_name);
}

void PELibUnitTest::CheckTestDll(const FilePath& path) {
  LOADED_IMAGE loaded_image = {};
  ASSERT_TRUE(::MapAndLoad(WideToUTF8(path.value()).c_str(),
                           NULL,
                           &loaded_image,
                           FALSE,
                           FALSE));

  EXPECT_TRUE(::UnMapAndLoad(&loaded_image));

  HMODULE loaded = ::LoadLibrary(path.value().c_str());
  ASSERT_TRUE(loaded != NULL);
  CheckLoadedTestDll(loaded);
  ::FreeLibrary(loaded);
}

}  // namespace testing
