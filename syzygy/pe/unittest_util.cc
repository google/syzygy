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

#include <algorithm>

#include "base/command_line.h"
#include "base/file_util.h"
#include "base/logging.h"
#include "base/path_service.h"
#include "base/process_util.h"
#include "base/stringprintf.h"
#include "base/utf_string_conversions.h"
#include "base/win/pe_image.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/pe/pe_data.h"

using pe::CvInfoPdb70;

namespace {

// This class wraps an HMODULE and ensures that ::FreeLibrary is called when it
// goes out of scope.
class ScopedHMODULE {
 public:
  explicit ScopedHMODULE(HMODULE v): value_(v) {
  }

  ~ScopedHMODULE() {
    if (value_) {
      ::FreeLibrary(value_);
    }
  }

  operator HMODULE() const {
    return value_;
  }

 private:
  HMODULE value_;
};

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

void CheckLoadedDllHasSortedSafeSehTable(HMODULE module) {
  // Verify that the Safe SEH Table is sorted.
  // http://code.google.com/p/sawbuck/issues/detail?id=42
  ASSERT_TRUE(module != NULL);
  base::win::PEImage image(module);

  // Locate the load config directory.
  PIMAGE_LOAD_CONFIG_DIRECTORY load_config_directory =
      reinterpret_cast<PIMAGE_LOAD_CONFIG_DIRECTORY>(
          image.GetImageDirectoryEntryAddr(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG));
  ASSERT_TRUE(load_config_directory != NULL);

  // Find the bounds of the Safe SEH Table.
  DWORD* seh_table_begin =
      reinterpret_cast<DWORD*>(load_config_directory->SEHandlerTable);
  size_t seh_table_size = load_config_directory->SEHandlerCount;
  DWORD* seh_table_end = seh_table_begin + seh_table_size;

  // Unfortunately, std::is_sorted is an extension pre-c++0x. An equivalent
  // test is to see if there are any adjacent elements such that the first
  // is greater than its successor. So, let's look for the first element for
  // which this is true, and if we get to the end, then there were no such
  // elements.
  DWORD* out_of_order_iter = std::adjacent_find(seh_table_begin,
                                                seh_table_end,
                                                std::greater<DWORD>());
  ASSERT_TRUE(out_of_order_iter == seh_table_end)
      << "The Safe SEH Table must be sorted.";
}

void CheckLoadedTestDll(HMODULE module) {
  // Validate that the DLL is properly constructed.
  CheckLoadedDllHasSortedSafeSehTable(module);

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

const wchar_t PELibUnitTest::kDllName[] = L"test_dll.dll";
const wchar_t PELibUnitTest::kDllPdbName[] = L"test_dll.pdb";
const wchar_t PELibUnitTest::kInstrumentedDllName[] =
    L"instrumented_test_dll.dll";
const wchar_t PELibUnitTest::kInstrumentedDllPdbName[] =
    L"instrumented_test_dll.pdb";

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

// TODO(chrisha): Centralize this routine, and others like it, as they've
//     started to be duplicated quite a bit now.
FilePath PELibUnitTest::GetExeRelativePath(const wchar_t* image_name) {
  FilePath exe_dir;
  PathService::Get(base::DIR_EXE, &exe_dir);
  return exe_dir.Append(image_name);
}

FilePath PELibUnitTest::GetOutputRelativePath(const wchar_t* path) {
#if defined(_DEBUG)
  // TODO(chrisha): Expose $(ProjectDir) and $(OutputDir) via defines in the
  //     project gyp file. Do this when centralizing all of these functions!
  static const wchar_t kOutputDir[] = L"Debug";
#else
#if defined(NDEBUG)
  static const wchar_t kOutputDir[] = L"Release";
#else
#error Unknown build profile.
#endif
#endif

  FilePath src_dir;
  PathService::Get(base::DIR_SOURCE_ROOT, &src_dir);
  src_dir = src_dir.Append(L"syzygy");
  src_dir = src_dir.Append(kOutputDir);
  return src_dir.Append(path);
}

FilePath PELibUnitTest::GetExeTestDataRelativePath(const wchar_t* path) {
  FilePath exe_dir;
  PathService::Get(base::DIR_EXE, &exe_dir);
  FilePath test_data = exe_dir.Append(L"test_data");
  return test_data.Append(path);
}

void PELibUnitTest::CheckEmbeddedPdbPath(const FilePath& pe_path,
                                         const FilePath& expected_pdb_path) {
  ASSERT_FALSE(pe_path.empty());
  ASSERT_FALSE(expected_pdb_path.empty());

  ScopedHMODULE module(::LoadLibrary(pe_path.value().c_str()));
  ASSERT_FALSE(module == NULL);

  base::win::PEImage pe(module);

  ASSERT_EQ(sizeof(IMAGE_DEBUG_DIRECTORY),
            pe.GetImageDirectoryEntrySize(IMAGE_DIRECTORY_ENTRY_DEBUG));

  PIMAGE_DEBUG_DIRECTORY debug_directory =
      reinterpret_cast<PIMAGE_DEBUG_DIRECTORY>(
        pe.GetImageDirectoryEntryAddr(IMAGE_DIRECTORY_ENTRY_DEBUG));

  size_t expected_size =
      sizeof(CvInfoPdb70) + expected_pdb_path.value().length();

  ASSERT_FALSE(debug_directory == NULL);
  ASSERT_EQ(expected_size, debug_directory->SizeOfData);

  void* raw_debug_info = pe.RVAToAddr(debug_directory->AddressOfRawData);
  ASSERT_FALSE(raw_debug_info == NULL);

  CvInfoPdb70* debug_info = reinterpret_cast<CvInfoPdb70*>(raw_debug_info);

  FilePath pdb_path(UTF8ToWide(debug_info->pdb_file_name));

  ASSERT_TRUE(pdb_path == expected_pdb_path);
}

void PELibUnitTest::CheckTestDll(const FilePath& path) {
  LOADED_IMAGE loaded_image = {};
  ASSERT_TRUE(::MapAndLoad(WideToUTF8(path.value()).c_str(),
                           NULL,
                           &loaded_image,
                           FALSE,
                           FALSE));

  EXPECT_TRUE(::UnMapAndLoad(&loaded_image));

  ScopedHMODULE module(::LoadLibrary(path.value().c_str()));
  ASSERT_TRUE(module != NULL);
  CheckLoadedTestDll(module);
}

}  // namespace testing
