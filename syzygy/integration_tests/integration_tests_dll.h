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
//
// This file declares the entry point for the different end to end
// instrumentation tests.
#ifndef SYZYGY_INTEGRATION_TESTS_INTEGRATION_TESTS_DLL_H_
#define SYZYGY_INTEGRATION_TESTS_INTEGRATION_TESTS_DLL_H_

namespace testing {

// This enumeration contains an unique id for each end to end test. It is used
// to perform an indirect call through the DLL entry point 'EndToEndTest'.
enum EndToEndTestId {
  kArrayComputation1TestId,
  kArrayComputation2TestId,

  kAsanRead8BufferOverflowTestId,
  kAsanRead16BufferOverflowTestId,
  kAsanRead32BufferOverflowTestId,
  kAsanRead64BufferOverflowTestId,
  kAsanRead8BufferUnderflowTestId,
  kAsanRead16BufferUnderflowTestId,
  kAsanRead32BufferUnderflowTestId,
  kAsanRead64BufferUnderflowTestId,

  kAsanWrite8BufferOverflowTestId,
  kAsanWrite16BufferOverflowTestId,
  kAsanWrite32BufferOverflowTestId,
  kAsanWrite64BufferOverflowTestId,
  kAsanWrite8BufferUnderflowTestId,
  kAsanWrite16BufferUnderflowTestId,
  kAsanWrite32BufferUnderflowTestId,
  kAsanWrite64BufferUnderflowTestId,

  kAsanRead8UseAfterFreeTestId,
  kAsanRead16UseAfterFreeTestId,
  kAsanRead32UseAfterFreeTestId,
  kAsanRead64UseAfterFreeTestId,

  kAsanWrite8UseAfterFreeTestId,
  kAsanWrite16UseAfterFreeTestId,
  kAsanWrite32UseAfterFreeTestId,
  kAsanWrite64UseAfterFreeTestId,

  kAsanMemchrOverflow,
  kAsanMemchrUnderflow,
  kAsanMemchrUseAfterFree,
  kAsanMemcpyReadOverflow,
  kAsanMemcpyReadUnderflow,
  kAsanMemcpyUseAfterFree,
  kAsanMemcpyWriteOverflow,
  kAsanMemcpyWriteUnderflow,
  kAsanMemmoveReadOverflow,
  kAsanMemmoveReadUnderflow,
  kAsanMemmoveUseAfterFree,
  kAsanMemmoveWriteOverflow,
  kAsanMemmoveWriteUnderflow,
  kAsanMemsetOverflow,
  kAsanMemsetUnderflow,
  kAsanMemsetUseAfterFree,

  kAsanStrcspnKeysOverflow,
  kAsanStrcspnKeysUnderflow,
  kAsanStrcspnKeysUseAfterFree,
  kAsanStrcspnSrcOverflow,
  kAsanStrcspnSrcUnderflow,
  kAsanStrcspnSrcUseAfterFree,
  kAsanStrlenOverflow,
  kAsanStrlenUnderflow,
  kAsanStrlenUseAfterFree,
  kAsanStrrchrOverflow,
  kAsanStrrchrUnderflow,
  kAsanStrrchrUseAfterFree,
  kAsanStrcmpSrc1Overflow,
  kAsanStrcmpSrc1Underflow,
  kAsanStrcmpSrc1UseAfterFree,
  kAsanStrcmpSrc2Overflow,
  kAsanStrcmpSrc2Underflow,
  kAsanStrcmpSrc2UseAfterFree,
  kAsanStrpbrkKeysOverflow,
  kAsanStrpbrkKeysUnderflow,
  kAsanStrpbrkKeysUseAfterFree,
  kAsanStrpbrkSrcOverflow,
  kAsanStrpbrkSrcUnderflow,
  kAsanStrpbrkSrcUseAfterFree,
  kAsanStrstrSrc1Overflow,
  kAsanStrstrSrc1Underflow,
  kAsanStrstrSrc1UseAfterFree,
  kAsanStrstrSrc2Overflow,
  kAsanStrstrSrc2Underflow,
  kAsanStrstrSrc2UseAfterFree,
  kAsanStrspnKeysOverflow,
  kAsanStrspnKeysUnderflow,
  kAsanStrspnKeysUseAfterFree,
  kAsanStrspnSrcOverflow,
  kAsanStrspnSrcUnderflow,
  kAsanStrspnSrcUseAfterFree,
  kAsanStrncpySrcOverflow,
  kAsanStrncpySrcUnderflow,
  kAsanStrncpySrcUseAfterFree,
  kAsanStrncpyDstOverflow,
  kAsanStrncpyDstUnderflow,
  kAsanStrncpyDstUseAfterFree,
  kAsanStrncatSuffixOverflow,
  kAsanStrncatSuffixUnderflow,
  kAsanStrncatSuffixUseAfterFree,
  kAsanStrncatDstOverflow,
  kAsanStrncatDstUnderflow,
  kAsanStrncatDstUseAfterFree,

  kAsanReadFileOverflow,
  kAsanReadFileUseAfterFree,

  kBBEntryCallOnce,
  kBBEntryCallTree,
  kBBEntryCallRecursive,

  kCoverage1,
  kCoverage2,
  kCoverage3,

  kProfileCallExport,
  kProfileGetMyRVA,
};

}  // namespace testing

#endif  // SYZYGY_INTEGRATION_TESTS_INTEGRATION_TESTS_DLL_H_
