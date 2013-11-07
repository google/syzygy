// Copyright 2013 Google Inc. All Rights Reserved.
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

#include "syzygy/integration_tests/integration_tests_dll.h"

#include <windows.h>  // NOLINT

#include "base/basictypes.h"
#include "syzygy/integration_tests/asan_check_tests.h"
#include "syzygy/integration_tests/asan_interceptors_tests.h"
#include "syzygy/integration_tests/bb_entry_tests.h"
#include "syzygy/integration_tests/behavior_tests.h"
#include "syzygy/integration_tests/coverage_tests.h"
#include "syzygy/integration_tests/profile_tests.h"

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
  return TRUE;
}

unsigned int CALLBACK EndToEndTest(testing::EndToEndTestId test) {
  switch (test) {
#define DECLARE_END_TO_END_SWITCH_TABLE(enum_name, function_to_call) \
    case testing::enum_name: { \
      return function_to_call(); \
    }
  END_TO_END_TEST_ID_TABLE(DECLARE_END_TO_END_SWITCH_TABLE)
#undef DECLARE_END_TO_END_SWITCH_TABLE
    default:
      return 0;
  }
}
