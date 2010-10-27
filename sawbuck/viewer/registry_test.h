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
#ifndef SAWBUCK_VIEWER_REGISTRY_TEST_H_
#define SAWBUCK_VIEWER_REGISTRY_TEST_H_

#include "base/win/registry.h"
#include "gtest/gtest.h"

namespace testing {

// This test fixture redirects the HKLM and HKCU registry hives for
// the duration of the test to make it independent of the machine
// and user settings.
class RegistryTest : public testing::Test {
 protected:
  ~RegistryTest();

  // Redirects HKCU and HKLM to a fresh set of registry keys.
  virtual void SetUp();
  // Undoes redirection and deletes any keys created during Setup or test.
  virtual void TearDown();

  // Register the supplied ATL registry script.
  bool Register(const wchar_t* reg_file);

 private:
  base::win::RegKey hkcu_;
  base::win::RegKey hklm_;
};

}  // namespace testing

#endif  // SAWBUCK_VIEWER_REGISTRY_TEST_H_
