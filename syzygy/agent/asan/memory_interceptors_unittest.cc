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
#include "syzygy/agent/asan/unittest_util.h"

namespace agent {
namespace asan {

namespace {

using testing::MemoryAccessorTester;
using testing::TestMemoryInterceptors;

static const TestMemoryInterceptors::InterceptFunction
    intercept_functions[] = {
#define DEFINE_INTERCEPT_FUNCTION_TABLE(access_size, access_mode_str, \
                                        access_mode) \
  { asan_check_ ## access_size ## _byte_ ## access_mode_str, access_size },

ASAN_MEM_INTERCEPT_FUNCTIONS(DEFINE_INTERCEPT_FUNCTION_TABLE)

#undef DEFINE_INTERCEPT_FUNCTION_TABLE
};

static const TestMemoryInterceptors::InterceptFunction
    intercept_functions_no_flags[] = {
#define DEFINE_INTERCEPT_FUNCTION_TABLE_NO_FLAGS(access_size, \
    access_mode_str, access_mode) \
  { asan_check_ ## access_size ## _byte_ ## access_mode_str ## _no_flags, \
    access_size },

ASAN_MEM_INTERCEPT_FUNCTIONS(DEFINE_INTERCEPT_FUNCTION_TABLE_NO_FLAGS)

#undef DEFINE_INTERCEPT_FUNCTION_TABLE_NO_FLAGS
};

static const TestMemoryInterceptors::StringInterceptFunction
    string_intercept_functions[] = {
#define DEFINE_STRING_INTERCEPT_FUNCTION_TABLE(func, prefix, counter, \
    dst_mode, src_mode, access_size, compare) \
  { asan_check ## prefix ## access_size ## _byte_ ## func ## _access, \
    access_size, TestMemoryInterceptors::dst_mode, \
    TestMemoryInterceptors::src_mode, \
    TestMemoryInterceptors::kCounterInit_##counter },

ASAN_STRING_INTERCEPT_FUNCTIONS(DEFINE_STRING_INTERCEPT_FUNCTION_TABLE)

#undef DEFINE_STRINGINTERCEPT_FUNCTION_TABLE
};

typedef TestMemoryInterceptors MemoryInterceptorsTest;

}  // namespace

TEST_F(MemoryInterceptorsTest, TestValidAccess) {
  TestValidAccess(intercept_functions);
  TestValidAccessIgnoreFlags(intercept_functions_no_flags);
}

TEST_F(MemoryInterceptorsTest, TestOverrunAccess) {
  TestOverrunAccess(intercept_functions);
  TestOverrunAccessIgnoreFlags(intercept_functions_no_flags);
}

TEST_F(MemoryInterceptorsTest, TestUnderrunAccess) {
  TestUnderrunAccess(intercept_functions);
  TestUnderrunAccessIgnoreFlags(intercept_functions_no_flags);
}

TEST_F(MemoryInterceptorsTest, TestStringValidAccess) {
  TestStringValidAccess(string_intercept_functions);
}

TEST_F(MemoryInterceptorsTest, TestStringOverrunAccess) {
  TestStringOverrunAccess(string_intercept_functions);
}

}  // namespace asan
}  // namespace agent
