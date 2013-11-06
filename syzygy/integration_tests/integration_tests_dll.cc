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
  // This function is used to dispatch test id to its corresponding function.
  // TODO(sebmarchand): Move this to a macro to facilitate the maintainance of
  //     this list.
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
      return testing::AsanMemsetUnderflow<int8>();
    case testing::kAsanMemsetUseAfterFree:
      return testing::AsanMemsetUseAfterFree<size_t>();
    case testing::kAsanMemchrOverflow:
      return testing::AsanMemchrOverflow<double>();
    case testing::kAsanMemchrUnderflow:
      return testing::AsanMemchrUnderflow<int32>();
    case testing::kAsanMemchrUseAfterFree:
      return testing::AsanMemchrUseAfterFree<double>();
    case testing::kAsanMemmoveReadOverflow:
      return testing::AsanMemmoveReadOverflow<double>();
    case testing::kAsanMemmoveReadUnderflow:
      return testing::AsanMemmoveReadUnderflow<int16>();
    case testing::kAsanMemmoveUseAfterFree:
      return testing::AsanMemmoveUseAfterFree<uint32>();
    case testing::kAsanMemmoveWriteOverflow:
      return testing::AsanMemmoveWriteOverflow<size_t>();
    case testing::kAsanMemmoveWriteUnderflow:
      return testing::AsanMemmoveWriteUnderflow<int8>();
    case testing::kAsanMemcpyReadOverflow:
      return testing::AsanMemcpyReadOverflow<int32>();
    case testing::kAsanMemcpyReadUnderflow:
      return testing::AsanMemcpyReadUnderflow<int8>();
    case testing::kAsanMemcpyUseAfterFree:
      return testing::AsanMemcpyUseAfterFree<int16>();
    case testing::kAsanMemcpyWriteOverflow:
      return testing::AsanMemcpyWriteOverflow<double>();
    case testing::kAsanMemcpyWriteUnderflow:
      return testing::AsanMemcpyWriteUnderflow<int16>();

    case testing::kAsanStrcspnKeysOverflow:
      return testing::AsanStrcspnKeysOverflow();
    case testing::kAsanStrcspnKeysUnderflow:
      return testing::AsanStrcspnKeysUnderflow();
    case testing::kAsanStrcspnKeysUseAfterFree:
      return testing::AsanStrcspnKeysUseAfterFree();
    case testing::kAsanStrcspnSrcOverflow:
      return testing::AsanStrcspnSrcOverflow();
    case testing::kAsanStrcspnSrcUnderflow:
      return testing::AsanStrcspnSrcUnderflow();
    case testing::kAsanStrcspnSrcUseAfterFree:
      return testing::AsanStrcspnSrcUseAfterFree();
    case testing::kAsanStrlenOverflow:
      return testing::AsanStrlenOverflow();
    case testing::kAsanStrlenUnderflow:
      return testing::AsanStrlenUnderflow();
    case testing::kAsanStrlenUseAfterFree:
      return testing::AsanStrlenUseAfterFree();
    case testing::kAsanStrrchrOverflow:
      return testing::AsanStrrchrOverflow();
    case testing::kAsanStrrchrUnderflow:
      return testing::AsanStrrchrUnderflow();
    case testing::kAsanStrrchrUseAfterFree:
      return testing::AsanStrrchrUseAfterFree();
    case testing::kAsanStrcmpSrc1Overflow:
      return testing::AsanStrcmpSrc1Overflow();
    case testing::kAsanStrcmpSrc1Underflow:
      return testing::AsanStrcmpSrc1Underflow();
    case testing::kAsanStrcmpSrc1UseAfterFree:
      return testing::AsanStrcmpSrc1UseAfterFree();
    case testing::kAsanStrcmpSrc2Overflow:
      return testing::AsanStrcmpSrc2Overflow();
    case testing::kAsanStrcmpSrc2Underflow:
      return testing::AsanStrcmpSrc2Underflow();
    case testing::kAsanStrcmpSrc2UseAfterFree:
      return testing::AsanStrcmpSrc2UseAfterFree();
    case testing::kAsanStrpbrkKeysOverflow:
      return testing::AsanStrpbrkKeysOverflow();
    case testing::kAsanStrpbrkKeysUnderflow:
      return testing::AsanStrpbrkKeysUnderflow();
    case testing::kAsanStrpbrkKeysUseAfterFree:
      return testing::AsanStrpbrkKeysUseAfterFree();
    case testing::kAsanStrpbrkSrcOverflow:
      return testing::AsanStrpbrkSrcOverflow();
    case testing::kAsanStrpbrkSrcUnderflow:
      return testing::AsanStrpbrkSrcUnderflow();
    case testing::kAsanStrpbrkSrcUseAfterFree:
      return testing::AsanStrpbrkSrcUseAfterFree();
    case testing::kAsanStrstrSrc1Overflow:
      return testing::AsanStrstrSrc1Overflow();
    case testing::kAsanStrstrSrc1Underflow:
      return testing::AsanStrstrSrc1Underflow();
    case testing::kAsanStrstrSrc1UseAfterFree:
      return testing::AsanStrstrSrc1UseAfterFree();
    case testing::kAsanStrstrSrc2Overflow:
      return testing::AsanStrstrSrc2Overflow();
    case testing::kAsanStrstrSrc2Underflow:
      return testing::AsanStrstrSrc2Underflow();
    case testing::kAsanStrstrSrc2UseAfterFree:
      return testing::AsanStrstrSrc2UseAfterFree();
    case testing::kAsanStrspnKeysOverflow:
      return testing::AsanStrspnKeysOverflow();
    case testing::kAsanStrspnKeysUnderflow:
      return testing::AsanStrspnKeysUnderflow();
    case testing::kAsanStrspnKeysUseAfterFree:
      return testing::AsanStrspnKeysUseAfterFree();
    case testing::kAsanStrspnSrcOverflow:
      return testing::AsanStrspnSrcOverflow();
    case testing::kAsanStrspnSrcUnderflow:
      return testing::AsanStrspnSrcUnderflow();
    case testing::kAsanStrspnSrcUseAfterFree:
      return testing::AsanStrspnSrcUseAfterFree();
    case testing::kAsanStrncpySrcOverflow:
      return testing::AsanStrncpySrcOverflow();
    case testing::kAsanStrncpySrcUnderflow:
      return testing::AsanStrncpySrcUnderflow();
    case testing::kAsanStrncpySrcUseAfterFree:
      return testing::AsanStrncpySrcUseAfterFree();
    case testing::kAsanStrncpyDstOverflow:
      return testing::AsanStrncpyDstOverflow();
    case testing::kAsanStrncpyDstUnderflow:
      return testing::AsanStrncpyDstUnderflow();
    case testing::kAsanStrncpyDstUseAfterFree:
      return testing::AsanStrncpyDstUseAfterFree();
    case testing::kAsanStrncatSuffixOverflow:
      return testing::AsanStrncatSuffixOverflow();
    case testing::kAsanStrncatSuffixUnderflow:
      return testing::AsanStrncatSuffixUnderflow();
    case testing::kAsanStrncatSuffixUseAfterFree:
      return testing::AsanStrncatSuffixUseAfterFree();
    case testing::kAsanStrncatDstOverflow:
      return testing::AsanStrncatDstOverflow();
    case testing::kAsanStrncatDstUnderflow:
      return testing::AsanStrncatDstUnderflow();
    case testing::kAsanStrncatDstUseAfterFree:
      return testing::AsanStrncatDstUseAfterFree();

    case testing::kAsanReadFileOverflow:
      return testing::AsanReadFileOverflow();
    case testing::kAsanReadFileUseAfterFree:
      return testing::AsanReadFileUseAfterFree();

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

    // Profile test cases.
    case testing::kProfileCallExport:
      return testing::CallExportedFunction();
    case testing::kProfileGetMyRVA:
      return testing::GetMyRVA();
  }
  return 0;
}
