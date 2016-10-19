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

#include "syzygy/agent/asan/iat_patcher.h"

#include <vector>

#include "base/bind.h"
#include "base/files/file_path.h"
#include "base/win/pe_image.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/agent/asan/constants.h"
#include "syzygy/core/unittest_util.h"

namespace agent {
namespace asan {

namespace {

class LenientIATPatcherTest : public testing::Test {
 public:
  using ImportTable = std::vector<FunctionPointer>;

  LenientIATPatcherTest() : test_dll_(nullptr) {
  }

  void SetUp() override {
    base::FilePath path =
#ifndef _WIN64
        testing::GetExeRelativePath(L"test_dll.dll");
#else
        testing::GetExeRelativePath(L"test_dll_x64.dll");
#endif
    test_dll_ = ::LoadLibrary(path.value().c_str());
    ASSERT_NE(nullptr, test_dll_);
  }

  void TearDown() override {
    if (test_dll_ != nullptr) {
      ::FreeLibrary(test_dll_);
      test_dll_ = nullptr;
    }
  }

  ImportTable GetIAT(HMODULE module) {
    base::win::PEImage image(module);
    ImportTable ret;

    image.EnumAllImports(OnImport, &ret);

    return ret;
  }

  DWORD GetIATPageProtection(HMODULE module) {
    base::win::PEImage image(module);

    const void* iat =
        image.GetImageDirectoryEntryAddr(IMAGE_DIRECTORY_ENTRY_IAT);

    MEMORY_BASIC_INFORMATION memory_info {};
    EXPECT_TRUE(::VirtualQuery(iat, &memory_info, sizeof(memory_info)));

    return memory_info.Protect;
  }

  void ReprotectPage(void* page, DWORD old_prot) {
    DWORD prot = 0;
    ASSERT_TRUE(::VirtualProtect(
        page, agent::asan::GetPageSize(), old_prot, &prot));
  }

  MOCK_METHOD2(OnUnprotect, void(void*, DWORD));

 protected:
  static bool OnImport(const base::win::PEImage &image, LPCSTR module,
                       DWORD ordinal, LPCSTR name, DWORD hint,
                       PIMAGE_THUNK_DATA iat, PVOID cookie) {
    ImportTable* imports = reinterpret_cast<ImportTable*>(cookie);
    imports->push_back(reinterpret_cast<FunctionPointer>(iat->u1.Function));

    return true;
  }

  HMODULE test_dll_;
};
using IATPatcherTest = testing::StrictMock<LenientIATPatcherTest>;

static void PatchDestination() {
}

}  // namespace

TEST_F(IATPatcherTest, PatchIATForModule) {
  // Capture the IAT of the test module before patching.
  ImportTable iat_before = GetIAT(test_dll_);
  DWORD prot_before = GetIATPageProtection(test_dll_);

  const DWORD kWritableMask =
      PAGE_READWRITE | PAGE_WRITECOPY |
      PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;

  // We expect the IAT not to be writable.
  ASSERT_EQ(0, prot_before & kWritableMask);

  // None of the imports should point to the dummy destination.
  for (auto fn : iat_before)
    ASSERT_TRUE(PatchDestination != fn);

  // Construct a patch map to patch the named export_dll imports to a dummy
  // function.
  IATPatchMap patches;
  patches["function1"] = PatchDestination;
  patches["function3"] = PatchDestination;

  // Patch'er up!
  ASSERT_EQ(PATCH_SUCCEEDED, PatchIATForModule(test_dll_, patches));

  // Make sure the IAT page protections have been reset.
  ASSERT_EQ(prot_before, GetIATPageProtection(test_dll_));

  // Capture the IAT of the test module after patching and verify that the
  // expected number of functions got redirected to the dummy destination.
  ImportTable iat_after = GetIAT(test_dll_);
  size_t patched = 0;
  for (auto func : iat_after) {
    if (func == &PatchDestination)
      ++patched;
  }

  ASSERT_EQ(2, patched);
}

TEST_F(IATPatcherTest, FailsWithAccessViolation) {
  // Construct a patch map to patch the named export_dll imports to a dummy
  // function.
  IATPatchMap patches;
  patches["function1"] = PatchDestination;
  patches["function3"] = PatchDestination;

  // Create a callback to the mock.
  ScopedPageProtections::OnUnprotectCallback on_unprotect =
      base::Bind(&IATPatcherTest::OnUnprotect, base::Unretained(this));

  // Expect a single call to the function to unprotect the IAT. In that call
  // reprotect the page.
  EXPECT_CALL(*this, OnUnprotect(testing::_, testing::_)).WillOnce(
      testing::Invoke(this, &IATPatcherTest::ReprotectPage));

  // Expect the patching to fail with an access violation, and expect the IAT
  // to remain unchanged.
  ImportTable iat_before = GetIAT(test_dll_);
  auto result = PatchIATForModule(test_dll_, patches, on_unprotect);
  ASSERT_NE(0u, PATCH_FAILED_ACCESS_VIOLATION & result);
  ImportTable iat_after = GetIAT(test_dll_);
  EXPECT_EQ(iat_before, iat_after);
}

}  // namespace asan
}  // namespace agent
