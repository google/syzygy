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
#include "sawbuck/common/com_utils.h"
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
  expected_imports.insert("kExportedData");
  expected_imports.insert("function1");
  expected_imports.insert("#7");
  expected_imports.insert("function3");
  EXPECT_THAT(expected_imports, testing::ContainerEq(export_dll_imports));
}

}  // namespace

namespace testing {

const wchar_t PELibUnitTest::kDllName[] = L"test_dll.dll";
const wchar_t PELibUnitTest::kDllPdbName[] = L"test_dll.pdb";
const wchar_t PELibUnitTest::kAsanInstrumentedDllName[] =
    L"asan_instrumented_test_dll.dll";
const wchar_t PELibUnitTest::kAsanInstrumentedDllPdbName[] =
    L"asan_instrumented_test_dll.pdb";
const wchar_t PELibUnitTest::kRandomizedTestDllName[] =
    L"randomized_test_dll.dll";
const wchar_t PELibUnitTest::kRandomizedTestDllPdbName[] =
    L"randomized_test_dll.pdb";
const wchar_t PELibUnitTest::kRpcInstrumentedDllName[] =
    L"rpc_instrumented_test_dll.dll";
const wchar_t PELibUnitTest::kRpcInstrumentedDllPdbName[] =
    L"rpc_instrumented_test_dll.pdb";

void PELibUnitTest::CheckTestDll(const FilePath& path) {
  LOADED_IMAGE loaded_image = {};
  BOOL success = ::MapAndLoad(WideToUTF8(path.value()).c_str(),
                              NULL,
                              &loaded_image,
                              FALSE,
                              FALSE);
  EXPECT_EQ(ERROR_SUCCESS, ::GetLastError());
  ASSERT_TRUE(success);
  EXPECT_TRUE(::UnMapAndLoad(&loaded_image));

  ScopedHMODULE module(::LoadLibrary(path.value().c_str()));
  if (module == NULL) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "LoadLibrary failed: " << com::LogWe(error);
  }
  ASSERT_TRUE(module != NULL);
  CheckLoadedTestDll(module);
}

}  // namespace testing
