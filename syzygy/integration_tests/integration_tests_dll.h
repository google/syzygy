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

#include <stdint.h>

namespace testing {

// This macro declares the SyzyAsan tests ids and the function that they're
// associated with.
#define END_TO_END_ASAN_TESTS(decl)  \
    decl(kAsanRead8BufferOverflow, testing::AsanReadBufferOverflow<int8_t>)  \
    decl(kAsanRead16BufferOverflow, testing::AsanReadBufferOverflow<int16_t>)  \
    decl(kAsanRead32BufferOverflow, testing::AsanReadBufferOverflow<int32_t>)  \
    decl(kAsanRead64BufferOverflow, testing::AsanReadBufferOverflow<double>)  \
    decl(kAsanRead8BufferUnderflow, testing::AsanReadBufferUnderflow<int8_t>)  \
    decl(kAsanRead16BufferUnderflow,  \
         testing::AsanReadBufferUnderflow<int16_t>)  \
    decl(kAsanRead32BufferUnderflow,  \
         testing::AsanReadBufferUnderflow<int32_t>)  \
    decl(kAsanRead64BufferUnderflow,  \
         testing::AsanReadBufferUnderflow<double>)  \
    decl(kAsanWrite8BufferOverflow, testing::AsanWriteBufferOverflow<int8_t>)  \
    decl(kAsanWrite16BufferOverflow,  \
         testing::AsanWriteBufferOverflow<int16_t>)  \
    decl(kAsanWrite32BufferOverflow,  \
         testing::AsanWriteBufferOverflow<int32_t>)  \
    decl(kAsanWrite64BufferOverflow,  \
         testing::AsanWriteBufferOverflow<double>)  \
    decl(kAsanWrite8BufferUnderflow,  \
         testing::AsanWriteBufferUnderflow<int8_t>)  \
    decl(kAsanWrite16BufferUnderflow,  \
         testing::AsanWriteBufferUnderflow<int16_t>)  \
    decl(kAsanWrite32BufferUnderflow,  \
         testing::AsanWriteBufferUnderflow<int32_t>)  \
    decl(kAsanWrite64BufferUnderflow,  \
         testing::AsanWriteBufferUnderflow<double>)  \
    decl(kAsanRead8UseAfterFree, testing::AsanReadUseAfterFree<int8_t>)  \
    decl(kAsanRead16UseAfterFree, testing::AsanReadUseAfterFree<int16_t>)  \
    decl(kAsanRead32UseAfterFree, testing::AsanReadUseAfterFree<int32_t>)  \
    decl(kAsanRead64UseAfterFree, testing::AsanReadUseAfterFree<double>)  \
    decl(kAsanWrite8UseAfterFree, testing::AsanWriteUseAfterFree<int8_t>)  \
    decl(kAsanWrite16UseAfterFree, testing::AsanWriteUseAfterFree<int16_t>)  \
    decl(kAsanWrite32UseAfterFree, testing::AsanWriteUseAfterFree<int32_t>)  \
    decl(kAsanWrite64UseAfterFree, testing::AsanWriteUseAfterFree<double>)  \
    decl(kAsanMemsetOverflow, testing::AsanMemsetOverflow<int32_t>)  \
    decl(kAsanMemsetUnderflow, testing::AsanMemsetUnderflow<int8_t>)  \
    decl(kAsanMemsetUseAfterFree, testing::AsanMemsetUseAfterFree<size_t>)  \
    decl(kAsanMemchrOverflow, testing::AsanMemchrOverflow<double>)  \
    decl(kAsanMemchrUnderflow, testing::AsanMemchrUnderflow<int32_t>)  \
    decl(kAsanMemchrUseAfterFree, testing::AsanMemchrUseAfterFree<double>)  \
    decl(kAsanMemmoveReadOverflow, testing::AsanMemmoveReadOverflow<double>)  \
    decl(kAsanMemmoveReadUnderflow,  \
         testing::AsanMemmoveReadUnderflow<int16_t>)  \
    decl(kAsanMemmoveUseAfterFree,  \
         testing::AsanMemmoveUseAfterFree<uint32_t>)  \
    decl(kAsanMemmoveWriteOverflow,  \
         testing::AsanMemmoveWriteOverflow<size_t>)  \
    decl(kAsanMemmoveWriteUnderflow,  \
         testing::AsanMemmoveWriteUnderflow<int8_t>)  \
    decl(kAsanMemcpyReadOverflow, testing::AsanMemcpyReadOverflow<int32_t>)  \
    decl(kAsanMemcpyReadUnderflow, testing::AsanMemcpyReadUnderflow<int8_t>)  \
    decl(kAsanMemcpyUseAfterFree, testing::AsanMemcpyUseAfterFree<int16_t>)  \
    decl(kAsanMemcpyWriteOverflow, testing::AsanMemcpyWriteOverflow<double>)  \
    decl(kAsanMemcpyWriteUnderflow,  \
         testing::AsanMemcpyWriteUnderflow<int16_t>)  \
    decl(kAsanStrcspnKeysOverflow, testing::AsanStrcspnKeysOverflow)  \
    decl(kAsanStrcspnKeysUnderflow, testing::AsanStrcspnKeysUnderflow)  \
    decl(kAsanStrcspnKeysUseAfterFree, testing::AsanStrcspnKeysUseAfterFree)  \
    decl(kAsanStrcspnSrcOverflow, testing::AsanStrcspnSrcOverflow)  \
    decl(kAsanStrcspnSrcUnderflow, testing::AsanStrcspnSrcUnderflow)  \
    decl(kAsanStrcspnSrcUseAfterFree, testing::AsanStrcspnSrcUseAfterFree)  \
    decl(kAsanStrlenOverflow, testing::AsanStrlenOverflow)  \
    decl(kAsanStrlenUnderflow, testing::AsanStrlenUnderflow)  \
    decl(kAsanStrlenUseAfterFree, testing::AsanStrlenUseAfterFree)  \
    decl(kAsanStrnlenOverflow, testing::AsanStrnlenOverflow)  \
    decl(kAsanStrnlenUnderflow, testing::AsanStrnlenUnderflow)  \
    decl(kAsanStrnlenUseAfterFree, testing::AsanStrnlenUseAfterFree)  \
    decl(kAsanWcsnlenOverflow, testing::AsanWcsnlenOverflow)  \
    decl(kAsanWcsnlenUnderflow, testing::AsanWcsnlenUnderflow)  \
    decl(kAsanWcsnlenUseAfterFree, testing::AsanWcsnlenUseAfterFree)  \
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
    decl(kAsanInvalidAccessWithCorruptAllocatedBlockHeader,  \
         testing::AsanInvalidAccessWithCorruptAllocatedBlockHeader)  \
    decl(kAsanInvalidAccessWithCorruptAllocatedBlockTrailer,  \
         testing::AsanInvalidAccessWithCorruptAllocatedBlockTrailer)  \
    decl(kAsanInvalidAccessWithCorruptFreedBlock,  \
         testing::AsanInvalidAccessWithCorruptFreedBlock)  \
    decl(kAsanReadLargeAllocationTrailerBeforeFree,  \
         testing::AsanReadLargeAllocationTrailerBeforeFree)  \
    decl(kAsanReadLargeAllocationBodyAfterFree,  \
         testing::AsanReadLargeAllocationBodyAfterFree)  \
    decl(kAsanReadPageAllocationTrailerBeforeFreeAllocation,  \
         testing::AsanReadPageAllocationTrailerBeforeFree)  \
    decl(kAsanWritePageAllocationBodyAfterFree,  \
         testing::AsanWritePageAllocationBodyAfterFree)  \
    decl(kAsanMemcmpAccessViolation, testing::AsanMemcmpAccessViolation)  \
    decl(kAsanCorruptBlockWithPageProtections,  \
         testing::AsanCorruptBlockWithPageProtections) \
    decl(kAsanNearNullptrAccessHeapCorruptionInstrumented, \
         testing::AsanNearNullptrAccessHeapCorruptionInstrumented) \
    decl(kAsanNearNullptrAccessHeapCorruptionUninstrumented, \
         testing::AsanNearNullptrAccessHeapCorruptionUninstrumented) \
    decl(kAsanNearNullptrAccessNoHeapCorruptionInstrumented, \
         testing::AsanNearNullptrAccessNoHeapCorruptionInstrumented) \
    decl(kAsanNearNullptrAccessNoHeapCorruptionUninstrumented, \
         testing::AsanNearNullptrAccessNoHeapCorruptionUninstrumented) \
    decl(kAsanNullptrAccessNoHeapCorruptionUninstrumented, \
         testing::AsanNullptrAccessNoHeapCorruptionUninstrumented) \
    decl(kAsanDeferredFreeTLS, testing::AsanDeferredFreeTLS)

// This macro declares the non SyzyAsan tests ids and the function that they're
// associated with.
#define END_TO_END_NON_ASAN_TESTS(decl)  \
    decl(kArrayComputation1, testing::ArrayComputation1)  \
    decl(kArrayComputation2, testing::ArrayComputation2)  \
    decl(kBBEntryCallOnce, BBEntryCallOnce)  \
    decl(kBBEntryCallTree, BBEntryCallTree)  \
    decl(kBBEntryCallRecursive, BBEntryCallRecursive)  \
    decl(kCoverage1, testing::coverage_func1)  \
    decl(kCoverage2, testing::coverage_func2)  \
    decl(kCoverage3, testing::coverage_func3)  \
    decl(kProfileCallExport, testing::CallExportedFunction)  \
    decl(kProfileGetMyRVA, testing::GetMyRVA)

// Only run the Asan tests for the Clang builds.
// The order of inclusion matters because it affects the IDs assigned to
// test cases. First include Asan tests then non Asan tests.
#ifdef __clang__
#define END_TO_END_TEST_ID_TABLE(decl) END_TO_END_ASAN_TESTS(decl)
#else
#define END_TO_END_TEST_ID_TABLE(decl)  \
    END_TO_END_ASAN_TESTS(decl) END_TO_END_NON_ASAN_TESTS(decl)
#endif // __clang__

// This enumeration contains an unique id for each end to end test. It is used
// to perform an indirect call through the DLL entry point 'EndToEndTest'.
enum EndToEndTestId {
#define DECLARE_END_TO_END_ENUM(enum_name, function_to_call) enum_name,
  END_TO_END_TEST_ID_TABLE(DECLARE_END_TO_END_ENUM)
#undef DECLARE_END_TO_END_ENUM
};

}  // namespace testing

#endif  // SYZYGY_INTEGRATION_TESTS_INTEGRATION_TESTS_DLL_H_
