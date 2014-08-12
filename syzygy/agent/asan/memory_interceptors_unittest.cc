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

#include "gtest/gtest.h"
#include "syzygy/agent/asan/error_info.h"
#include "syzygy/agent/asan/unittest_util.h"

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
  AccessMode access_mode;
};

static const InterceptFunction intercept_functions[] = {
#define DEFINE_INTERCEPT_FUNCTION_TABLE(access_size, access_mode_str, \
                                        access_mode) \
  { asan_check_ ## access_size ## _byte_ ## access_mode_str,  \
    access_size, access_mode, },

ASAN_MEM_INTERCEPT_FUNCTIONS(DEFINE_INTERCEPT_FUNCTION_TABLE)

#undef DEFINE_INTERCEPT_FUNCTION_TABLE
};

static const InterceptFunction string_intercept_functions[] = {
#define DEFINE_STRING_INTERCEPT_FUNCTION_TABLE(func, prefix, counter, \
    dst_mode, src_mode, access_size, compare) \
  { asan_check ## prefix ## access_size ## _byte_ ## func ## _access, \
    access_size, src_mode, },

ASAN_STRING_INTERCEPT_FUNCTIONS(DEFINE_STRING_INTERCEPT_FUNCTION_TABLE)

#undef DEFINE_STRINGINTERCEPT_FUNCTION_TABLE
};

typedef public testing::TestWithAsanHeap MemoryInterceptorsTest;

}  // namespace

TEST_F(MemoryInterceptorsTest, TestValidAccess) {
  char memory[128] = {};
  for (size_t i = 0; i < arraysize(intercept_functions); ++i) {
    const InterceptFunction& fn = intercept_functions[i];

    MemoryAccessorTester tester;
    tester.CheckAccessAndCompareContexts(
        reinterpret_cast<FARPROC>(fn.function), &memory);
  }
}

TEST_F(MemoryInterceptorsTest, TestValidStringAccess) {
  char src[128] = {};
  char dst[128] = {};
  for (size_t i = 0; i < arraysize(string_intercept_functions); ++i) {
    const InterceptFunction& fn = string_intercept_functions[i];

    MemoryAccessorTester tester;
    tester.CheckSpecialAccessAndCompareContexts(
        reinterpret_cast<FARPROC>(fn.function),
        MemoryAccessorTester::DIRECTION_FORWARD, dst, src, 13);
    tester.CheckSpecialAccessAndCompareContexts(
        reinterpret_cast<FARPROC>(fn.function),
        MemoryAccessorTester::DIRECTION_BACKWARD,
        dst + sizeof(dst), src + sizeof(src), 13);
  }
}

}  // namespace asan
}  // namespace agent
