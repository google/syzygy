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

#include <functional>

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
#include "syzygy/block_graph/typed_block.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/decomposer.h"
#include "syzygy/pe/new_decomposer.h"
#include "syzygy/pe/pe_data.h"

namespace testing {

namespace {

using block_graph::BlockGraph;
using block_graph::TypedBlock;
using pe::CvInfoPdb70;

typedef TypedBlock<CvInfoPdb70> CvInfoPdb;
typedef TypedBlock<IMAGE_DOS_HEADER> DosHeader;
typedef TypedBlock<IMAGE_NT_HEADERS> NtHeaders;
typedef TypedBlock<IMAGE_DEBUG_DIRECTORY> ImageDebugDirectory;

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

const wchar_t testing::kTestDllName[] = L"test_dll.dll";
const wchar_t testing::kTestDllPdbName[] = L"test_dll.dll.pdb";

const wchar_t testing::kTestDllCoffObjName[] = L"test_dll.coff_obj";
const wchar_t testing::kTestDllLtcgObjName[] = L"test_dll.ltcg_obj";
const wchar_t testing::kTestDllCoffObjPdbName[] = L"test_dll.coff_obj.pdb";
const wchar_t testing::kTestDllLtcgObjPdbName[] = L"test_dll.ltcg_obj.pdb";

const wchar_t testing::kMachineTypeNullCoffName[] =
    L"syzygy\\pe\\test_data\\machine_type_null.obj";

const wchar_t kAsanInstrumentedTestDllName[] =
    L"asan_instrumented_test_dll.dll";
const wchar_t kAsanInstrumentedTestDllPdbName[] =
    L"asan_instrumented_test_dll.dll.pdb";
const wchar_t kBBEntryInstrumentedTestDllName[] =
    L"basic_block_entry_instrumented_test_dll.dll";
const wchar_t kBBEntryInstrumentedTestDllPdbName[] =
    L"basic_block_entry_instrumented_test_dll.dll.pdb";
const wchar_t kCallTraceInstrumentedTestDllName[] =
    L"call_trace_instrumented_test_dll.dll";
const wchar_t kCallTraceInstrumentedTestDllPdbName[] =
    L"call_trace_instrumented_test_dll.dll.pdb";
const wchar_t kCoverageInstrumentedTestDllName[] =
    L"coverage_instrumented_test_dll.dll";
const wchar_t kCoverageInstrumentedTestDllPdbName[] =
    L"coverage_instrumented_test_dll.dll.pdb";
const wchar_t kProfileInstrumentedTestDllName[] =
    L"profile_instrumented_test_dll.dll";
const wchar_t kProfileInstrumentedTestDllPdbName[] =
    L"profile_instrumented_test_dll.dll.pdb";
const wchar_t kRandomizedTestDllName[] =
    L"randomized_test_dll.dll";
const wchar_t kRandomizedTestDllPdbName[] =
    L"randomized_test_dll.dll.pdb";

const wchar_t *kBBEntryTraceFiles[4] = {
    L"basic_block_entry_traces\\trace-1.bin",
    L"basic_block_entry_traces\\trace-2.bin",
    L"basic_block_entry_traces\\trace-3.bin",
    L"basic_block_entry_traces\\trace-4.bin",
};

const wchar_t *kBranchTraceFiles[4] = {
    L"branch_traces\\trace-1.bin",
    L"branch_traces\\trace-2.bin",
    L"branch_traces\\trace-3.bin",
    L"branch_traces\\trace-4.bin",
};

const wchar_t *kCallTraceTraceFiles[4] = {
    L"call_trace_traces\\trace-1.bin",
    L"call_trace_traces\\trace-2.bin",
    L"call_trace_traces\\trace-3.bin",
    L"call_trace_traces\\trace-4.bin",
};

const wchar_t *kCoverageTraceFiles[4] = {
    L"coverage_traces\\trace-1.bin",
    L"coverage_traces\\trace-2.bin",
    L"coverage_traces\\trace-3.bin",
    L"coverage_traces\\trace-4.bin",
};

const wchar_t *kProfileTraceFiles[4] = {
    L"profile_traces\\trace-1.bin",
    L"profile_traces\\trace-2.bin",
    L"profile_traces\\trace-3.bin",
    L"profile_traces\\trace-4.bin",
};

ScopedHMODULE::ScopedHMODULE() : value_(0) {
}

ScopedHMODULE::ScopedHMODULE(HMODULE v) : value_(v) {
}

void ScopedHMODULE::Reset(HMODULE value) {
  if (value_ != value) {
    Release();
    value_ = value;
  }
}

void ScopedHMODULE::Release() {
  if (value_) {
    ::FreeLibrary(value_);
    value_ = 0;
  }
}

ScopedHMODULE::~ScopedHMODULE() {
  Release();
}

void TwiddlePdbGuidAndPath(BlockGraph::Block* dos_header_block) {
  ASSERT_NE(reinterpret_cast<BlockGraph::Block*>(NULL), dos_header_block);

  DosHeader dos_header;
  ASSERT_TRUE(dos_header.Init(0, dos_header_block));

  NtHeaders nt_headers;
  ASSERT_TRUE(dos_header.Dereference(dos_header->e_lfanew, &nt_headers));

  const IMAGE_DATA_DIRECTORY& debug_dir_info =
    nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
  ImageDebugDirectory debug_dir;
  ASSERT_TRUE(nt_headers.Dereference(debug_dir_info.VirtualAddress,
                                     &debug_dir));

  // Find the codeview debug directory entry.
  int32 index = -1;
  for (size_t i = 0; i < debug_dir.ElementCount(); ++i) {
    if (debug_dir[i].Type == IMAGE_DEBUG_TYPE_CODEVIEW) {
      index = i;
      break;
    }
  }
  ASSERT_NE(-1, index);

  CvInfoPdb cv_info_pdb;
  ASSERT_TRUE(debug_dir.Dereference(debug_dir[index].PointerToRawData,
                                    &cv_info_pdb));

  // Modify the GUID.
  cv_info_pdb->signature.Data1 ^= 0xFFFFFFFF;

  // Write a nonsense name using a simple encoding.
  size_t block_size = cv_info_pdb.block()->size();
  size_t string_start = cv_info_pdb.OffsetOf(cv_info_pdb->pdb_file_name);
  ASSERT_LT(string_start, block_size);
  size_t string_len = block_size - string_start;
  for (size_t i = 0; i < string_len && cv_info_pdb->pdb_file_name[i] != 0;
       ++i) {
    char& c = cv_info_pdb->pdb_file_name[i];
    if (c >= 'a' && c <= 'z') {
      c = 'z' - (c - 'a');
    } else if (c >= 'A' && c <= 'Z') {
      c = 'Z' - (c - 'A');
    } else if (c >= '0' && c <= '9') {
      c = '9' - (c - '0');
    }
  }
}

void PELibUnitTest::LoadTestDll(const base::FilePath& path,
                                ScopedHMODULE* module) {
  DCHECK(module != NULL);

  LOADED_IMAGE loaded_image = {};
  BOOL success = ::MapAndLoad(WideToUTF8(path.value()).c_str(),
                              NULL,
                              &loaded_image,
                              FALSE,
                              FALSE);
  EXPECT_EQ(ERROR_SUCCESS, ::GetLastError());
  ASSERT_TRUE(success);
  EXPECT_TRUE(::UnMapAndLoad(&loaded_image));

  module->Reset(::LoadLibrary(path.value().c_str()));
  if (*module == NULL) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "LoadLibrary failed: " << com::LogWe(error);
  }
  ASSERT_TRUE(module != NULL);
}

void PELibUnitTest::DecomposeTestDll(bool use_old_decomposer,
                                     pe::PEFile* pe_file,
                                     pe::ImageLayout* image_layout) {
  ASSERT_TRUE(pe_file != NULL);
  ASSERT_TRUE(image_layout != NULL);

  base::FilePath test_dll = GetOutputRelativePath(kTestDllName);
  ASSERT_TRUE(pe_file->Init(test_dll));

  if (use_old_decomposer) {
    pe::Decomposer decomposer(*pe_file);
    ASSERT_TRUE(decomposer.Decompose(image_layout));
  } else {
    pe::NewDecomposer decomposer(*pe_file);
    ASSERT_TRUE(decomposer.Decompose(image_layout));
  }
}

void PELibUnitTest::CheckTestDll(const base::FilePath& path) {
  ScopedHMODULE module;
  LoadTestDll(path, &module);
  CheckLoadedTestDll(module);
}

}  // namespace testing
