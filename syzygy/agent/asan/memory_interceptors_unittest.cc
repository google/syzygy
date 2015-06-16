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
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/agent/asan/unittest_util.h"

namespace agent {
namespace asan {

namespace {

using testing::_;
using testing::MemoryAccessorTester;
using testing::Return;
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

static const TestMemoryInterceptors::InterceptFunction
    redirect_functions[] = {
#define DEFINE_REDIRECT_FUNCTION_TABLE(access_size, access_mode_str, \
    access_mode) \
  { asan_redirect_ ## access_size ## _byte_ ## access_mode_str, \
    access_size }, \

ASAN_MEM_INTERCEPT_FUNCTIONS(DEFINE_REDIRECT_FUNCTION_TABLE)

#undef DEFINE_REDIRECT_FUNCTION_TABLE
};

static const TestMemoryInterceptors::InterceptFunction
    redirect_functions_no_flags[] = {
#define DEFINE_REDIRECT_FUNCTION_TABLE_NO_FLAGS(access_size, access_mode_str, \
    access_mode) \
  { asan_redirect_ ## access_size ## _byte_ ## access_mode_str ## _no_flags, \
    access_size },

ASAN_MEM_INTERCEPT_FUNCTIONS(DEFINE_REDIRECT_FUNCTION_TABLE_NO_FLAGS)

#undef DEFINE_REDIRECT_FUNCTION_TABLE_NO_FLAGS
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

#undef DEFINE_STRING_INTERCEPT_FUNCTION_TABLE
};

static const TestMemoryInterceptors::StringInterceptFunction
    string_redirect_functions[] = {
#define DEFINE_STRING_REDIRECT_FUNCTION_TABLE(func, prefix, counter, \
    dst_mode, src_mode, access_size, compare) \
  { asan_redirect ## prefix ## access_size ## _byte_ ## func ## _access, \
    access_size, TestMemoryInterceptors::dst_mode, \
    TestMemoryInterceptors::src_mode, \
    TestMemoryInterceptors::kCounterInit_##counter },

ASAN_STRING_INTERCEPT_FUNCTIONS(DEFINE_STRING_REDIRECT_FUNCTION_TABLE)

#undef DEFINE_STRING_REDIRECT_FUNCTION_TABLE
};

class MemoryInterceptorsTest : public TestMemoryInterceptors {
 public:
  MOCK_METHOD1(OnRedirectorInvocation,
               MemoryAccessorMode(const void* caller_address));

  void SetUp() override {
    ASSERT_NO_FATAL_FAILURE(TestMemoryInterceptors::SetUp());

    SetRedirectEntryCallback(
        base::Bind(&MemoryInterceptorsTest::OnRedirectorInvocation,
                   base::Unretained(this)));
  }

  void TearDown() override {
    // Clear the redirect callback, if any.
    SetRedirectEntryCallback(RedirectEntryCallback());

    TestMemoryInterceptors::TearDown();
  }
};

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

TEST_F(MemoryInterceptorsTest, TestRedirectorsNoop) {
  // Test that the redirect functions pass through to the noop tester.
  EXPECT_CALL(*this, OnRedirectorInvocation(_))
      .Times(arraysize(redirect_functions))
      .WillRepeatedly(Return(MEMORY_ACCESSOR_MODE_NOOP));
  TestValidAccess(redirect_functions);

  EXPECT_CALL(*this, OnRedirectorInvocation(_))
      .Times(arraysize(redirect_functions_no_flags))
      .WillRepeatedly(Return(MEMORY_ACCESSOR_MODE_NOOP));
  TestValidAccessIgnoreFlags(redirect_functions_no_flags);
}

TEST_F(MemoryInterceptorsTest, TestRedirectors2G) {
  EXPECT_CALL(*this, OnRedirectorInvocation(_))
      .Times(3 * arraysize(redirect_functions))
      .WillRepeatedly(Return(MEMORY_ACCESSOR_MODE_2G));

  // Test valid, underrun and overrun.
  TestValidAccess(redirect_functions);
  TestUnderrunAccess(redirect_functions);
  TestOverrunAccess(redirect_functions);

  EXPECT_CALL(*this, OnRedirectorInvocation(_))
      .Times(3 * arraysize(redirect_functions_no_flags))
      .WillRepeatedly(Return(MEMORY_ACCESSOR_MODE_2G));

  // Test valid, underrun and overrun.
  TestValidAccessIgnoreFlags(redirect_functions_no_flags);
  TestUnderrunAccessIgnoreFlags(redirect_functions_no_flags);
  TestOverrunAccessIgnoreFlags(redirect_functions_no_flags);
}

TEST_F(MemoryInterceptorsTest, TestStringValidAccess) {
  TestStringValidAccess(string_intercept_functions);
}

TEST_F(MemoryInterceptorsTest, TestStringOverrunAccess) {
  TestStringOverrunAccess(string_intercept_functions);
}

TEST_F(MemoryInterceptorsTest, TestStringRedirectorsNoop) {
  EXPECT_CALL(*this, OnRedirectorInvocation(_))
      // Each function is tested twice, forwards and backwards.
      .Times(2 * arraysize(string_redirect_functions))
      .WillRepeatedly(Return(MEMORY_ACCESSOR_MODE_NOOP));

  TestStringValidAccess(string_redirect_functions);
}

TEST_F(MemoryInterceptorsTest, TestStringRedirectors2G) {
  EXPECT_CALL(*this, OnRedirectorInvocation(_))
      // Each string function is tested forwards and backwards.
      .Times(2 * arraysize(string_redirect_functions))
      .WillRepeatedly(Return(MEMORY_ACCESSOR_MODE_2G));

  // Test valid access.
  TestStringValidAccess(string_redirect_functions);

  EXPECT_CALL(*this, OnRedirectorInvocation(_))
      // For overrun each string function is tested forwards and backwards
      // on src and dst, for a grand total of four tests. This is with the
      // exception of the stos instruction, which is tested only in two modes
      // and six variants.
      .Times(4 * arraysize(string_redirect_functions) - 2 * 6)
      .WillRepeatedly(Return(MEMORY_ACCESSOR_MODE_2G));
  TestStringOverrunAccess(string_redirect_functions);
}

}  // namespace asan
}  // namespace agent
