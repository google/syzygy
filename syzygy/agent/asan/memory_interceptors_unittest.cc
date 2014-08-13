// Copyright 2014 Google Inc. All Rights Reserved.
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

#include "syzygy/agent/asan/memory_interceptors.h"

#include "base/bind.h"
#include "base/environment.h"
#include "base/strings/stringprintf.h"
#include "gtest/gtest.h"
#include "syzygy/agent/asan/asan_rtl_impl.h"
#include "syzygy/agent/asan/asan_runtime.h"
#include "syzygy/agent/asan/error_info.h"
#include "syzygy/agent/asan/unittest_util.h"
#include "syzygy/trace/protocol/call_trace_defs.h"

namespace agent {
namespace asan {

namespace {

using testing::MemoryAccessorTester;

// Redefine some enums for local use.
enum AccessMode {
  AsanReadAccess = agent::asan::ASAN_READ_ACCESS,
  AsanWriteAccess = agent::asan::ASAN_WRITE_ACCESS,
  AsanUnknownAccess = agent::asan::ASAN_UNKNOWN_ACCESS,
};

struct InterceptFunction {
  void(*function)();
  size_t size;
};

static const InterceptFunction intercept_functions[] = {
#define DEFINE_INTERCEPT_FUNCTION_TABLE(access_size, access_mode_str, \
                                        access_mode) \
  { asan_check_ ## access_size ## _byte_ ## access_mode_str, access_size },

ASAN_MEM_INTERCEPT_FUNCTIONS(DEFINE_INTERCEPT_FUNCTION_TABLE)

#undef DEFINE_INTERCEPT_FUNCTION_TABLE
};

struct StringInterceptFunction {
  void(*function)();
  size_t size;
  AccessMode dst_access_mode;
  AccessMode src_access_mode;
  bool uses_counter;
};

const bool kCounterInit_ecx = true;
const bool kCounterInit_1 = false;

static const StringInterceptFunction string_intercept_functions[] = {
#define DEFINE_STRING_INTERCEPT_FUNCTION_TABLE(func, prefix, counter, \
    dst_mode, src_mode, access_size, compare) \
  { asan_check ## prefix ## access_size ## _byte_ ## func ## _access, \
    access_size, dst_mode, src_mode, kCounterInit_##counter },

ASAN_STRING_INTERCEPT_FUNCTIONS(DEFINE_STRING_INTERCEPT_FUNCTION_TABLE)

#undef DEFINE_STRINGINTERCEPT_FUNCTION_TABLE
};

class MemoryInterceptorsTest : public testing::TestWithAsanLogger {
 public:
  MemoryInterceptorsTest() : heap_(NULL), src_(NULL), dst_(NULL) {
  }

  void SetUp() OVERRIDE {
    testing::TestWithAsanLogger::SetUp();

    // Make sure the logging routes to our instance.
    AppendToLoggerEnv(base::StringPrintf("syzyasan_rtl_unittests.exe,%u",
                                         ::GetCurrentProcessId()));

    asan_runtime_.SetUp(std::wstring());

    // Heap checking on error is expensive, so turn it down here.
    asan_runtime_.params().check_heap_on_failure = false;

    agent::asan::SetUpRtl(&asan_runtime_);

    asan_runtime_.SetErrorCallBack(
        base::Bind(testing::MemoryAccessorTester::AsanErrorCallback));
    heap_ = asan_HeapCreate(0, 0, 0);
    ASSERT_TRUE(heap_ != NULL);

    src_ = reinterpret_cast<byte*>(asan_HeapAlloc(heap_, 0, kAllocSize));
    dst_ = reinterpret_cast<byte*>(asan_HeapAlloc(heap_, 0, kAllocSize));
    ASSERT_TRUE(src_ && dst_);

    // String instructions may compare memory contents and bail early on
    // differences, so fill the buffers to make sure the checks go the full
    // distance.
    ::memset(src_, 0xFF, kAllocSize);
    ::memset(dst_, 0xFF, kAllocSize);
  }

  void TearDown() OVERRIDE {
    if (heap_ != NULL) {
      asan_HeapFree(heap_, 0, src_);
      asan_HeapFree(heap_, 0, dst_);

      asan_HeapDestroy(heap_);
      heap_ = NULL;
    }
    agent::asan::TearDownRtl();
    asan_runtime_.TearDown();
    testing::TestWithAsanLogger::TearDown();
  }

 protected:
  const size_t kAllocSize = 64;

  agent::asan::AsanRuntime asan_runtime_;
  HANDLE heap_;

  // Convenience allocs of kAllocSize. Valid from SetUp to TearDown.
  byte* src_;
  byte* dst_;
};

}  // namespace

TEST_F(MemoryInterceptorsTest, TestValidAccess) {
  for (size_t i = 0; i < arraysize(intercept_functions); ++i) {
    const InterceptFunction& fn = intercept_functions[i];

    MemoryAccessorTester tester;
    tester.CheckAccessAndCompareContexts(
        reinterpret_cast<FARPROC>(fn.function), src_);

    ASSERT_FALSE(tester.memory_error_detected());
  }
}

TEST_F(MemoryInterceptorsTest, TestOverrunAccess) {
  for (size_t i = 0; i < arraysize(intercept_functions); ++i) {
    const InterceptFunction& fn = intercept_functions[i];

    MemoryAccessorTester tester;
    tester.AssertMemoryErrorIsDetected(
        reinterpret_cast<FARPROC>(fn.function),
        src_ + kAllocSize,
        MemoryAccessorTester::BadAccessKind::HEAP_BUFFER_OVERFLOW);

    ASSERT_TRUE(tester.memory_error_detected());
  }
}

TEST_F(MemoryInterceptorsTest, TestUnderrrunAccess) {
  for (size_t i = 0; i < arraysize(intercept_functions); ++i) {
    const InterceptFunction& fn = intercept_functions[i];

    // TODO(someone): the 32 byte access checker does not fire on 32 byte
    //     underrun. I guess the checkers test a single shadow byte at most
    //     whereas it'd be more correct for access checkers to test as many
    //     shadow bytes as is appropriate for the range of memory they touch.
    MemoryAccessorTester tester;
    tester.AssertMemoryErrorIsDetected(
        reinterpret_cast<FARPROC>(fn.function),
        src_ - 8,
        MemoryAccessorTester::BadAccessKind::HEAP_BUFFER_UNDERFLOW);

    ASSERT_TRUE(tester.memory_error_detected());
  }
}

TEST_F(MemoryInterceptorsTest, TestStringValidAccess) {
  for (size_t i = 0; i < arraysize(string_intercept_functions); ++i) {
    const StringInterceptFunction& fn = string_intercept_functions[i];

    MemoryAccessorTester tester;
    tester.CheckSpecialAccessAndCompareContexts(
        reinterpret_cast<FARPROC>(fn.function),
        MemoryAccessorTester::DIRECTION_FORWARD,
        dst_, src_, kAllocSize / fn.size);
    ASSERT_FALSE(tester.memory_error_detected());

    tester.CheckSpecialAccessAndCompareContexts(
        reinterpret_cast<FARPROC>(fn.function),
        MemoryAccessorTester::DIRECTION_BACKWARD,
        dst_ + kAllocSize - fn.size, src_ + kAllocSize - fn.size,
        kAllocSize / fn.size);

    ASSERT_FALSE(tester.memory_error_detected());
  }
}

TEST_F(MemoryInterceptorsTest, TestStringOverrunAccess) {
  for (size_t i = 0; i < arraysize(string_intercept_functions); ++i) {
    const StringInterceptFunction& fn = string_intercept_functions[i];

    MemoryAccessorTester tester;
    size_t oob_len = 0;
    byte* oob_dst = NULL;
    byte* oob_src = NULL;

    // Half the string function intercepts are for rep-prefixed instructions,
    // which count on "ecx", and the other half is for non-prefixed
    // instructions that always perform a single access.
    // Compute appropriate pointers for both variants, forwards.
    if (fn.uses_counter) {
      oob_len = kAllocSize / fn.size;
      oob_dst = dst_ + fn.size;
      oob_src = src_ + fn.size;
    } else {
      oob_len = 1;
      oob_dst = dst_ + kAllocSize;
      oob_src = src_ + kAllocSize;
    }

    ASSERT_NE(ASAN_UNKNOWN_ACCESS, fn.dst_access_mode);
    // Overflow on dst forwards.
    tester.ExpectSpecialMemoryErrorIsDetected(
        reinterpret_cast<FARPROC>(fn.function),
        MemoryAccessorTester::DIRECTION_FORWARD, true,
        oob_dst, src_, oob_len,
        MemoryAccessorTester::BadAccessKind::HEAP_BUFFER_OVERFLOW);

    if (fn.src_access_mode != ASAN_UNKNOWN_ACCESS) {
      // Overflow on src forwards.
      tester.ExpectSpecialMemoryErrorIsDetected(
          reinterpret_cast<FARPROC>(fn.function),
          MemoryAccessorTester::DIRECTION_FORWARD, true,
          dst_, oob_src, oob_len,
          MemoryAccessorTester::BadAccessKind::HEAP_BUFFER_OVERFLOW);
    }

    // Compute appropriate pointers for both variants, backwards.
    if (fn.uses_counter) {
      oob_len = kAllocSize / fn.size;
    } else {
      oob_len = 1;
    }

    oob_dst = dst_ + kAllocSize;
    oob_src = src_ + kAllocSize;

    ASSERT_NE(ASAN_UNKNOWN_ACCESS, fn.dst_access_mode);
    // Overflow on dst backwards.
    tester.ExpectSpecialMemoryErrorIsDetected(
        reinterpret_cast<FARPROC>(fn.function),
        MemoryAccessorTester::DIRECTION_BACKWARD, true,
        oob_dst, src_ + kAllocSize - fn.size, oob_len,
        MemoryAccessorTester::BadAccessKind::HEAP_BUFFER_OVERFLOW);

    if (fn.src_access_mode != ASAN_UNKNOWN_ACCESS) {
      // Overflow on src backwards.
      tester.ExpectSpecialMemoryErrorIsDetected(
          reinterpret_cast<FARPROC>(fn.function),
          MemoryAccessorTester::DIRECTION_BACKWARD, true,
          dst_ + kAllocSize - fn.size, oob_dst, oob_len,
          MemoryAccessorTester::BadAccessKind::HEAP_BUFFER_OVERFLOW);
    }
  }
}

}  // namespace asan
}  // namespace agent
