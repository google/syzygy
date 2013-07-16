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

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
  return TRUE;
}

unsigned int CALLBACK EndToEndTest(testing::EndToEndTestId test) {
  // This function is used to dispatch test id to its corresponding function.
  switch (test) {
    // Behavior test cases.
    case testing::kArrayComputation1TestId:
      return testing::ArrayComputation1();
    case testing::kArrayComputation2TestId:
      return testing::ArrayComputation2();

    // Asan Memory Error test cases..
    case testing::kAsanRead8BufferOverflowTestId:
      return testing::AsanReadBufferOverflow<int8>();
    case testing::kAsanRead16BufferOverflowTestId:
      return testing::AsanReadBufferOverflow<int16>();
    case testing::kAsanRead32BufferOverflowTestId:
      return testing::AsanReadBufferOverflow<int32>();
    case testing::kAsanRead64BufferOverflowTestId:
      return testing::AsanReadBufferOverflow<double>();

    case testing::kAsanRead8BufferUnderflowTestId:
      return testing::AsanReadBufferUnderflow<int8>();
    case testing::kAsanRead16BufferUnderflowTestId:
      return testing::AsanReadBufferUnderflow<int16>();
    case testing::kAsanRead32BufferUnderflowTestId:
      return testing::AsanReadBufferUnderflow<int32>();
    case testing::kAsanRead64BufferUnderflowTestId:
      return testing::AsanReadBufferUnderflow<double>();

    case testing::kAsanWrite8BufferOverflowTestId:
      return testing::AsanWriteBufferOverflow<int8>();
    case testing::kAsanWrite16BufferOverflowTestId:
      return testing::AsanWriteBufferOverflow<int16>();
    case testing::kAsanWrite32BufferOverflowTestId:
      return testing::AsanWriteBufferOverflow<int32>();
    case testing::kAsanWrite64BufferOverflowTestId:
      return testing::AsanWriteBufferOverflow<double>();

    case testing::kAsanWrite8BufferUnderflowTestId:
      return testing::AsanWriteBufferUnderflow<int8>();
    case testing::kAsanWrite16BufferUnderflowTestId:
      return testing::AsanWriteBufferUnderflow<int16>();
    case testing::kAsanWrite32BufferUnderflowTestId:
      return testing::AsanWriteBufferUnderflow<int32>();
    case testing::kAsanWrite64BufferUnderflowTestId:
      return testing::AsanWriteBufferUnderflow<double>();

    case testing::kAsanRead8UseAfterFreeTestId:
      return testing::AsanReadUseAfterFree<int8>();
    case testing::kAsanRead16UseAfterFreeTestId:
      return testing::AsanReadUseAfterFree<int16>();
    case testing::kAsanRead32UseAfterFreeTestId:
      return testing::AsanReadUseAfterFree<int32>();
    case testing::kAsanRead64UseAfterFreeTestId:
      return testing::AsanReadUseAfterFree<double>();

    case testing::kAsanWrite8UseAfterFreeTestId:
      return testing::AsanWriteUseAfterFree<int8>();
    case testing::kAsanWrite16UseAfterFreeTestId:
      return testing::AsanWriteUseAfterFree<int16>();
    case testing::kAsanWrite32UseAfterFreeTestId:
      return testing::AsanWriteUseAfterFree<int32>();
    case testing::kAsanWrite64UseAfterFreeTestId:
      return testing::AsanWriteUseAfterFree<double>();

    // Asan interceptors test cases.
    case testing::kAsanMemsetOverflow:
      return testing::AsanMemsetOverflow<int32>();
    case testing::kAsanMemsetUnderflow:
      return testing::AsanMemsetUnderflow<int32>();
    case testing::kAsanMemchrOverflow:
      return testing::AsanMemchrOverflow<int32>();
    case testing::kAsanMemchrUnderflow:
      return testing::AsanMemchrUnderflow<int32>();

    // Basic block entry test cases.
    case testing::kBBEntryCallOnce:
      return BBEntryCallOnce();
    case testing::kBBEntryCallTree:
      return BBEntryCallTree();
    case testing::kBBEntryCallRecursive:
      return BBEntryCallRecursive();

    // Coverage test cases.
    case testing::kCoverage1:
      return testing::coverage_func1();
    case testing::kCoverage2:
      return testing::coverage_func2();
    case testing::kCoverage3:
      return testing::coverage_func3();
  }
  return 0;
}
