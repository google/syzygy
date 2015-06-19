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

#include "base/files/file_path.h"
#include "base/win/pe_image.h"
#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"

namespace agent {
namespace asan {

namespace {

class IATPatcherTest : public testing::Test {
 public:
  using ImportTable = std::vector<FunctionPointer>;

  IATPatcherTest() : test_dll_(nullptr) {
  }

  void SetUp() override {
    base::FilePath path =
        testing::GetExeRelativePath(L"test_dll.dll");
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
  ASSERT_TRUE(PatchIATForModule(test_dll_, patches));

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

}  // namespace asan
}  // namespace agent
