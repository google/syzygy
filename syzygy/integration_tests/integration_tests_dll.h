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

// This macro declares the tests ids and the function that they're associated
// with.
#define END_TO_END_TEST_ID_TABLE(decl) \
    decl(kArrayComputation1TestId, testing::ArrayComputation1)  \
    decl(kArrayComputation2TestId, testing::ArrayComputation2)  \
    decl(kAsanRead8BufferOverflowTestId,  \
         testing::AsanReadBufferOverflow<int8>)  \
    decl(kAsanRead16BufferOverflowTestId,  \
         testing::AsanReadBufferOverflow<int16>)  \
    decl(kAsanRead32BufferOverflowTestId,  \
         testing::AsanReadBufferOverflow<int32>)  \
    decl(kAsanRead64BufferOverflowTestId,  \
         testing::AsanReadBufferOverflow<double>)  \
    decl(kAsanRead8BufferUnderflowTestId,  \
         testing::AsanReadBufferUnderflow<int8>)  \
    decl(kAsanRead16BufferUnderflowTestId,  \
         testing::AsanReadBufferUnderflow<int16>)  \
    decl(kAsanRead32BufferUnderflowTestId,  \
         testing::AsanReadBufferUnderflow<int32>)  \
    decl(kAsanRead64BufferUnderflowTestId,  \
         testing::AsanReadBufferUnderflow<double>)  \
    decl(kAsanWrite8BufferOverflowTestId,  \
         testing::AsanWriteBufferOverflow<int8>)  \
    decl(kAsanWrite16BufferOverflowTestId,  \
         testing::AsanWriteBufferOverflow<int16>)  \
    decl(kAsanWrite32BufferOverflowTestId,  \
         testing::AsanWriteBufferOverflow<int32>)  \
    decl(kAsanWrite64BufferOverflowTestId,  \
         testing::AsanWriteBufferOverflow<double>)  \
    decl(kAsanWrite8BufferUnderflowTestId,  \
         testing::AsanWriteBufferUnderflow<int8>)  \
    decl(kAsanWrite16BufferUnderflowTestId,  \
         testing::AsanWriteBufferUnderflow<int16>)  \
    decl(kAsanWrite32BufferUnderflowTestId,  \
         testing::AsanWriteBufferUnderflow<int32>)  \
    decl(kAsanWrite64BufferUnderflowTestId,  \
         testing::AsanWriteBufferUnderflow<double>)  \
    decl(kAsanRead8UseAfterFreeTestId, testing::AsanReadUseAfterFree<int8>)  \
    decl(kAsanRead16UseAfterFreeTestId, testing::AsanReadUseAfterFree<int16>)  \
    decl(kAsanRead32UseAfterFreeTestId, testing::AsanReadUseAfterFree<int32>)  \
    decl(kAsanRead64UseAfterFreeTestId,  \
         testing::AsanReadUseAfterFree<double>)  \
    decl(kAsanWrite8UseAfterFreeTestId, testing::AsanWriteUseAfterFree<int8>)  \
    decl(kAsanWrite16UseAfterFreeTestId,  \
         testing::AsanWriteUseAfterFree<int16>)  \
    decl(kAsanWrite32UseAfterFreeTestId,  \
         testing::AsanWriteUseAfterFree<int32>)  \
    decl(kAsanWrite64UseAfterFreeTestId,  \
         testing::AsanWriteUseAfterFree<double>)  \
    decl(kAsanMemsetOverflow, testing::AsanMemsetOverflow<int32>)  \
    decl(kAsanMemsetUnderflow, testing::AsanMemsetUnderflow<int8>)  \
    decl(kAsanMemsetUseAfterFree, testing::AsanMemsetUseAfterFree<size_t>)  \
    decl(kAsanMemchrOverflow, testing::AsanMemchrOverflow<double>)  \
    decl(kAsanMemchrUnderflow, testing::AsanMemchrUnderflow<int32>)  \
    decl(kAsanMemchrUseAfterFree, testing::AsanMemchrUseAfterFree<double>)  \
    decl(kAsanMemmoveReadOverflow, testing::AsanMemmoveReadOverflow<double>)  \
    decl(kAsanMemmoveReadUnderflow, testing::AsanMemmoveReadUnderflow<int16>)  \
    decl(kAsanMemmoveUseAfterFree, testing::AsanMemmoveUseAfterFree<uint32>)  \
    decl(kAsanMemmoveWriteOverflow,  \
         testing::AsanMemmoveWriteOverflow<size_t>)  \
    decl(kAsanMemmoveWriteUnderflow,  \
         testing::AsanMemmoveWriteUnderflow<int8>)  \
    decl(kAsanMemcpyReadOverflow, testing::AsanMemcpyReadOverflow<int32>)  \
    decl(kAsanMemcpyReadUnderflow, testing::AsanMemcpyReadUnderflow<int8>)  \
    decl(kAsanMemcpyUseAfterFree, testing::AsanMemcpyUseAfterFree<int16>)  \
    decl(kAsanMemcpyWriteOverflow, testing::AsanMemcpyWriteOverflow<double>)  \
    decl(kAsanMemcpyWriteUnderflow, testing::AsanMemcpyWriteUnderflow<int16>)  \
    decl(kAsanStrcspnKeysOverflow, testing::AsanStrcspnKeysOverflow)  \
    decl(kAsanStrcspnKeysUnderflow, testing::AsanStrcspnKeysUnderflow)  \
    decl(kAsanStrcspnKeysUseAfterFree, testing::AsanStrcspnKeysUseAfterFree)  \
    decl(kAsanStrcspnSrcOverflow, testing::AsanStrcspnSrcOverflow)  \
    decl(kAsanStrcspnSrcUnderflow, testing::AsanStrcspnSrcUnderflow)  \
    decl(kAsanStrcspnSrcUseAfterFree, testing::AsanStrcspnSrcUseAfterFree)  \
    decl(kAsanStrlenOverflow, testing::AsanStrlenOverflow)  \
    decl(kAsanStrlenUnderflow, testing::AsanStrlenUnderflow)  \
    decl(kAsanStrlenUseAfterFree, testing::AsanStrlenUseAfterFree)  \
    decl(kAsanStrrchrOverflow, testing::AsanStrrchrOverflow)  \
    decl(kAsanStrrchrUnderflow, testing::AsanStrrchrUnderflow)  \
    decl(kAsanStrrchrUseAfterFree, testing::AsanStrrchrUseAfterFree)  \
    decl(kAsanWcsrchrOverflow, testing::AsanWcsrchrOverflow)  \
    decl(kAsanWcsrchrUnderflow, testing::AsanWcsrchrUnderflow)  \
    decl(kAsanWcsrchrUseAfterFree, testing::AsanWcsrchrUseAfterFree)  \
    decl(kAsanWcschrOverflow, testing::AsanWcschrOverflow)  \
    decl(kAsanWcschrUnderflow, testing::AsanWcschrUnderflow)  \
    decl(kAsanWcschrUseAfterFree, testing::AsanWcschrUseAfterFree)  \
    decl(kAsanStrcmpSrc1Overflow, testing::AsanStrcmpSrc1Overflow)  \
    decl(kAsanStrcmpSrc1Underflow, testing::AsanStrcmpSrc1Underflow)  \
    decl(kAsanStrcmpSrc1UseAfterFree, testing::AsanStrcmpSrc1UseAfterFree)  \
    decl(kAsanStrcmpSrc2Overflow, testing::AsanStrcmpSrc2Overflow)  \
    decl(kAsanStrcmpSrc2Underflow, testing::AsanStrcmpSrc2Underflow)  \
    decl(kAsanStrcmpSrc2UseAfterFree, testing::AsanStrcmpSrc2UseAfterFree)  \
    decl(kAsanStrpbrkKeysOverflow, testing::AsanStrpbrkKeysOverflow)  \
    decl(kAsanStrpbrkKeysUnderflow, testing::AsanStrpbrkKeysUnderflow)  \
    decl(kAsanStrpbrkKeysUseAfterFree, testing::AsanStrpbrkKeysUseAfterFree)  \
    decl(kAsanStrpbrkSrcOverflow, testing::AsanStrpbrkSrcOverflow)  \
    decl(kAsanStrpbrkSrcUnderflow, testing::AsanStrpbrkSrcUnderflow)  \
    decl(kAsanStrpbrkSrcUseAfterFree, testing::AsanStrpbrkSrcUseAfterFree)  \
    decl(kAsanStrstrSrc1Overflow, testing::AsanStrstrSrc1Overflow)  \
    decl(kAsanStrstrSrc1Underflow, testing::AsanStrstrSrc1Underflow)  \
    decl(kAsanStrstrSrc1UseAfterFree, testing::AsanStrstrSrc1UseAfterFree)  \
    decl(kAsanStrstrSrc2Overflow, testing::AsanStrstrSrc2Overflow)  \
    decl(kAsanStrstrSrc2Underflow, testing::AsanStrstrSrc2Underflow)  \
    decl(kAsanStrstrSrc2UseAfterFree, testing::AsanStrstrSrc2UseAfterFree)  \
    decl(kAsanWcsstrKeysOverflow, testing::AsanWcsstrKeysOverflow)  \
    decl(kAsanStrspnKeysOverflow, testing::AsanStrspnKeysOverflow)  \
    decl(kAsanStrspnKeysUnderflow, testing::AsanStrspnKeysUnderflow)  \
    decl(kAsanStrspnKeysUseAfterFree, testing::AsanStrspnKeysUseAfterFree)  \
    decl(kAsanStrspnSrcOverflow, testing::AsanStrspnSrcOverflow)  \
    decl(kAsanStrspnSrcUnderflow, testing::AsanStrspnSrcUnderflow)  \
    decl(kAsanStrspnSrcUseAfterFree, testing::AsanStrspnSrcUseAfterFree)  \
    decl(kAsanStrncpySrcOverflow, testing::AsanStrncpySrcOverflow)  \
    decl(kAsanStrncpySrcUnderflow, testing::AsanStrncpySrcUnderflow)  \
    decl(kAsanStrncpySrcUseAfterFree, testing::AsanStrncpySrcUseAfterFree)  \
    decl(kAsanStrncpyDstOverflow, testing::AsanStrncpyDstOverflow)  \
    decl(kAsanStrncpyDstUnderflow, testing::AsanStrncpyDstUnderflow)  \
    decl(kAsanStrncpyDstUseAfterFree, testing::AsanStrncpyDstUseAfterFree)  \
    decl(kAsanStrncatSuffixOverflow, testing::AsanStrncatSuffixOverflow)  \
    decl(kAsanStrncatSuffixUnderflow, testing::AsanStrncatSuffixUnderflow)  \
    decl(kAsanStrncatSuffixUseAfterFree,  \
         testing::AsanStrncatSuffixUseAfterFree)  \
    decl(kAsanStrncatDstOverflow, testing::AsanStrncatDstOverflow)  \
    decl(kAsanStrncatDstUnderflow, testing::AsanStrncatDstUnderflow)  \
    decl(kAsanStrncatDstUseAfterFree, testing::AsanStrncatDstUseAfterFree)  \
    decl(kAsanReadFileOverflow, testing::AsanReadFileOverflow)  \
    decl(kAsanReadFileUseAfterFree, testing::AsanReadFileUseAfterFree)  \
    decl(kAsanWriteFileOverflow, testing::AsanWriteFileOverflow)  \
    decl(kAsanWriteFileUseAfterFree, testing::AsanWriteFileUseAfterFree)  \
    decl(kAsanCorruptBlock, testing::AsanCorruptBlock)  \
    decl(kAsanCorruptBlockInQuarantine,  \
         testing::AsanCorruptBlockInQuarantine)  \
    decl(kBBEntryCallOnce, BBEntryCallOnce)  \
    decl(kBBEntryCallTree, BBEntryCallTree)  \
    decl(kBBEntryCallRecursive, BBEntryCallRecursive)  \
    decl(kCoverage1, testing::coverage_func1)  \
    decl(kCoverage2, testing::coverage_func2)  \
    decl(kCoverage3, testing::coverage_func3)  \
    decl(kProfileCallExport, testing::CallExportedFunction)  \
    decl(kProfileGetMyRVA, testing::GetMyRVA)  \
    decl(kAsanInvalidAccessWithCorruptAllocatedBlockHeader,  \
         testing::AsanInvalidAccessWithCorruptAllocatedBlockHeader)  \
    decl(kAsanInvalidAccessWithCorruptAllocatedBlockTrailer,  \
         testing::AsanInvalidAccessWithCorruptAllocatedBlockTrailer)  \
    decl(kAsanInvalidAccessWithCorruptFreedBlock,  \
         testing::AsanInvalidAccessWithCorruptFreedBlock)

// This enumeration contains an unique id for each end to end test. It is used
// to perform an indirect call through the DLL entry point 'EndToEndTest'.
enum EndToEndTestId {
#define DECLARE_END_TO_END_ENUM(enum_name, function_to_call) enum_name,
  END_TO_END_TEST_ID_TABLE(DECLARE_END_TO_END_ENUM)
#undef DECLARE_END_TO_END_ENUM
};

}  // namespace testing

#endif  // SYZYGY_INTEGRATION_TESTS_INTEGRATION_TESTS_DLL_H_
