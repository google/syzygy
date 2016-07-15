// Copyright 2015 Google Inc. All Rights Reserved.
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

#include "syzygy/kasko/loader_lock.h"

#include "Psapi.h"

#include "base/files/file_path.h"
#include "base/strings/utf_string_conversions.h"
#include "gtest/gtest.h"
#include "syzygy/common/unittest_util.h"
#include "syzygy/pe/dia_util.h"
#include "syzygy/pe/find.h"

namespace kasko {

namespace {

base::FilePath GetModulePath(HMODULE module) {
  wchar_t module_path[MAX_PATH];
  DWORD size = ::GetModuleFileName(module, module_path, MAX_PATH);
  DCHECK(size != 0);

  return base::FilePath(module_path);
}

ULONGLONG GetModuleBaseAddress(HMODULE module) {
  return reinterpret_cast<ULONGLONG>(module);
}

class LoaderLockTest : public ::testing::Test {
 public:
  LoaderLockTest() {}
  ~LoaderLockTest() override {}

 private:
  void SetUp() override { ASSERT_TRUE(scoped_symbol_path_.Setup()); }

  testing::ScopedSymbolPath scoped_symbol_path_;

  DISALLOW_COPY_AND_ASSIGN(LoaderLockTest);
};

}  // namespace

// Tests that the offset used for finding the loader lock address in the Process
// Environment Block is correct. This is done by looking into the PDB file for
// ntdll.
//
// NOTE: Currently disabled as it relies on being able to retrieve the symbols
// for ntdll.dll, which doesn't always work on the bots.
TEST_F(LoaderLockTest, DISABLED_SymbolOffset) {
  HMODULE ntdll_handle = ::GetModuleHandle(L"ntdll.dll");

  base::FilePath ntdll_path = GetModulePath(ntdll_handle);
  ASSERT_FALSE(ntdll_path.empty());

  base::FilePath ntdll_pdb_path;
  ASSERT_TRUE(pe::FindPdbForModule(ntdll_path, &ntdll_pdb_path));
  ASSERT_FALSE(ntdll_pdb_path.empty());

  // Open the pdb file.
  base::win::ScopedComPtr<IDiaDataSource> source;
  ASSERT_TRUE(pe::CreateDiaSource(source.Receive()));
  base::win::ScopedComPtr<IDiaSession> session;
  ASSERT_TRUE(
      pe::CreateDiaSession(ntdll_pdb_path, source.get(), session.Receive()));

  // Set the load address of the dia session to get the computed virtual address
  // of the loader lock.
  ASSERT_HRESULT_SUCCEEDED(
      session->put_loadAddress(GetModuleBaseAddress(ntdll_handle)));

  base::win::ScopedComPtr<IDiaSymbol> global_scope;
  ASSERT_HRESULT_SUCCEEDED(session->get_globalScope(global_scope.Receive()));

  // Find the loader lock using its symbol name.
  base::win::ScopedComPtr<IDiaEnumSymbols> symbols_enum;
  ASSERT_HRESULT_SUCCEEDED(
      global_scope->findChildren(SymTagPublicSymbol, L"_LdrpLoaderLock",
                                 nsfCaseSensitive, symbols_enum.Receive()));

  // Sanity check. Only one symbol should have been found.
  LONG count = 0;
  ASSERT_HRESULT_SUCCEEDED(symbols_enum->get_Count(&count));
  ASSERT_EQ(1, count);

  base::win::ScopedComPtr<IDiaSymbol> loader_lock_symbol;
  ASSERT_HRESULT_SUCCEEDED(symbols_enum->Item(0, loader_lock_symbol.Receive()));
  ULONGLONG loader_lock_va = 0;
  ASSERT_HRESULT_SUCCEEDED(
      loader_lock_symbol->get_virtualAddress(&loader_lock_va));

  ASSERT_EQ(loader_lock_va, reinterpret_cast<uintptr_t>(GetLoaderLock()));
}

}  // namespace kasko
