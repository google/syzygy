// Copyright 2009 Google Inc.
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
//
// Test fixture for registry tests.
#include "sawbuck/viewer/registry_test.h"

#include <atlbase.h>
#include <statreg.h>
#include "gtest/gtest.h"
#include "sawbuck/viewer/const_config.h"

namespace testing {

const wchar_t* kHKCUReplacement =
    L"Software\\Google\\RegistryTest\\HKCU";
const wchar_t* kHKLMReplacement =
    L"Software\\Google\\RegistryTest\\HKLM";

RegistryTest::~RegistryTest() {
  EXPECT_TRUE(hkcu_.Handle() == NULL);
  EXPECT_TRUE(hklm_.Handle() == NULL);
}

void RegistryTest::SetUp() {
  // Wipe the keys we redirect to.
  // This gives us a stable run, even in the presence of previous
  // crashes or failures.
  LSTATUS err = SHDeleteKey(HKEY_CURRENT_USER, kHKCUReplacement);
  EXPECT_TRUE(err == ERROR_SUCCESS || err == ERROR_FILE_NOT_FOUND);
  err = SHDeleteKey(HKEY_CURRENT_USER, kHKLMReplacement);
  EXPECT_TRUE(err == ERROR_SUCCESS || err == ERROR_FILE_NOT_FOUND);

  // Create the keys we're redirecting HKCU and HKLM to.
  ASSERT_TRUE(hkcu_.Create(HKEY_CURRENT_USER, kHKCUReplacement, KEY_READ));
  ASSERT_TRUE(hklm_.Create(HKEY_CURRENT_USER, kHKLMReplacement, KEY_READ));

  // And do the switcharoo.
  ASSERT_EQ(ERROR_SUCCESS,
            ::RegOverridePredefKey(HKEY_CURRENT_USER, hkcu_.Handle()));
  ASSERT_EQ(ERROR_SUCCESS,
            ::RegOverridePredefKey(HKEY_LOCAL_MACHINE, hklm_.Handle()));
}

void RegistryTest::TearDown() {
  // Undo the redirection.
  EXPECT_EQ(ERROR_SUCCESS, ::RegOverridePredefKey(HKEY_CURRENT_USER, NULL));
  EXPECT_EQ(ERROR_SUCCESS, ::RegOverridePredefKey(HKEY_LOCAL_MACHINE, NULL));

  // Close our handles and delete the temp keys we redirected to.
  hkcu_.Close();
  hklm_.Close();
  EXPECT_EQ(ERROR_SUCCESS, SHDeleteKey(HKEY_CURRENT_USER, kHKCUReplacement));
  EXPECT_EQ(ERROR_SUCCESS, SHDeleteKey(HKEY_CURRENT_USER, kHKLMReplacement));
}

bool RegistryTest::Register(const wchar_t* reg_file) {
  CRegObject ro;

  return SUCCEEDED(ro.FinalConstruct()) &&
      SUCCEEDED(ro.StringRegister(reg_file));
}

}  // namespace
