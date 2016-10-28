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

#ifndef _WIN64
static const TestMemoryInterceptors::InterceptFunction intercept_functions[] = {
#define DEFINE_INTERCEPT_FUNCTION_TABLE(access_size, access_mode_str,      \
                                        access_mode)                       \
  { asan_check_##access_size##_byte_##access_mode_str##_2gb, access_size } \
  , {asan_check_##access_size##_byte_##access_mode_str##_4gb, access_size},

    ASAN_MEM_INTERCEPT_FUNCTIONS(DEFINE_INTERCEPT_FUNCTION_TABLE)

#undef DEFINE_INTERCEPT_FUNCTION_TABLE
};

static const TestMemoryInterceptors::InterceptFunction
    intercept_functions_no_flags[] = {
#define DEFINE_INTERCEPT_FUNCTION_TABLE_NO_FLAGS(access_size, access_mode_str, \
                                                 access_mode)                  \
  {                                                                            \
    asan_check_##access_size##_byte_##access_mode_str##_no_flags_2gb,          \
        access_size                                                            \
  }                                                                            \
  , {asan_check_##access_size##_byte_##access_mode_str##_no_flags_4gb,         \
     access_size},

ASAN_MEM_INTERCEPT_FUNCTIONS(DEFINE_INTERCEPT_FUNCTION_TABLE_NO_FLAGS)

#undef DEFINE_INTERCEPT_FUNCTION_TABLE_NO_FLAGS
};

static const TestMemoryInterceptors::InterceptFunction redirect_functions[] = {
#define DEFINE_REDIRECT_FUNCTION_TABLE(access_size, access_mode_str,    \
                                       access_mode)                     \
  { asan_redirect_##access_size##_byte_##access_mode_str, access_size } \
  ,

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
#endif

static const TestMemoryInterceptors::ClangInterceptFunction
    clang_intercept_functions[] = {
#ifndef _WIN64
#define DEFINE_CLANG_INTERCEPT_FUNCTION_TABLE(access_size, access_mode_str, \
                                              access_mode)                  \
  { asan_##access_mode_str##access_size##_2gb, access_size }                \
  , {asan_##access_mode_str##access_size##_4gb, access_size},
#else
#define DEFINE_CLANG_INTERCEPT_FUNCTION_TABLE(access_size, access_mode_str, \
                                              access_mode)                  \
  { asan_##access_mode_str##access_size##_8tb, access_size }                \
  , {asan_##access_mode_str##access_size##_128tb, access_size},
#endif
        CLANG_ASAN_MEM_INTERCEPT_FUNCTIONS(
            DEFINE_CLANG_INTERCEPT_FUNCTION_TABLE)

#undef DEFINE_CLANG_INTERCEPT_FUNCTION_TABLE
};

static const TestMemoryInterceptors::ClangInterceptFunction
    clang_redirect_functions[] = {
#define DEFINE_CLANG_REDIRECT_FUNCTION_TABLE(access_size, access_mode_str, \
                                             access_mode)                  \
  { asan_redirect_##access_mode_str##access_size, access_size }            \
  ,

        CLANG_ASAN_MEM_INTERCEPT_FUNCTIONS(DEFINE_CLANG_REDIRECT_FUNCTION_TABLE)

#undef DEFINE_CLANG_REDIRECT_FUNCTION_TABLE
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

// Define an interface for testing different kind of memory accesses
// with different types of memory interceptors (using different calling
// conventions).
class MemoryInterceptorTester {
 public:
  MemoryInterceptorTester() : test_fixture_(nullptr) {}
  virtual ~MemoryInterceptorTester() {}

  // Test the interceptors.
  virtual void TestValidAccess() = 0;
  virtual void TestOverrunAccess() = 0;
  virtual void TestUnderrunAccess() = 0;

  // Test the redirectors.
  virtual void TestRedirectorValidAccess() = 0;
  virtual void TestRedirectorOverrunAccess() = 0;
  virtual void TestRedirectorUnderrunAccess() = 0;

  // Number of interceptors.
  virtual size_t InterceptorsCount() = 0;

  // Number of redirectors.
  virtual size_t RedirectorsCount() = 0;

  // Set the test fixture that shoul be used to test the memory accesses.
  void SetTestFixture(MemoryInterceptorsTest* fixture) {
    test_fixture_ = fixture;
  }

 protected:
  MemoryInterceptorsTest* test_fixture_;
};

#ifndef _WIN64
// Specialization of the MemoryInterceptorTester class for the probes with the
// SyzyAsan custom calling convention (value to check in EDX).
class SyzyAsanMemoryInterceptorTester : public MemoryInterceptorTester {
 public:
  void TestValidAccess() override {
    test_fixture_->TestValidAccess(intercept_functions);
    test_fixture_->TestValidAccessIgnoreFlags(intercept_functions_no_flags);
  }
  void TestOverrunAccess() override {
    test_fixture_->TestOverrunAccess(intercept_functions);
    test_fixture_->TestOverrunAccessIgnoreFlags(intercept_functions_no_flags);
  }
  void TestUnderrunAccess() override {
    test_fixture_->TestUnderrunAccess(intercept_functions);
    test_fixture_->TestUnderrunAccessIgnoreFlags(intercept_functions_no_flags);
  }
  void TestRedirectorValidAccess() override {
    test_fixture_->TestValidAccess(redirect_functions);
    test_fixture_->TestValidAccessIgnoreFlags(redirect_functions_no_flags);
  }
  void TestRedirectorOverrunAccess() override {
    test_fixture_->TestOverrunAccess(redirect_functions);
    test_fixture_->TestOverrunAccessIgnoreFlags(redirect_functions_no_flags);
  }
  void TestRedirectorUnderrunAccess() override {
    test_fixture_->TestUnderrunAccess(redirect_functions);
    test_fixture_->TestUnderrunAccessIgnoreFlags(redirect_functions_no_flags);
  }
  size_t InterceptorsCount() override {
    return arraysize(intercept_functions) +
           arraysize(intercept_functions_no_flags);
  };
  size_t RedirectorsCount() override {
    return arraysize(redirect_functions) +
           arraysize(redirect_functions_no_flags);
  };
};
#endif

// Specialization of the MemoryInterceptorTester class for the probes with the
// cdecl calling convention.
class ClangMemoryInterceptorTester : public MemoryInterceptorTester {
 public:
  void TestValidAccess() override {
    test_fixture_->TestValidAccess(clang_intercept_functions);
  }
  void TestOverrunAccess() override {
    test_fixture_->TestOverrunAccess(clang_intercept_functions);
  }
  void TestUnderrunAccess() override {
    test_fixture_->TestUnderrunAccess(clang_intercept_functions);
  }
  void TestRedirectorValidAccess() override {
    test_fixture_->TestValidAccess(clang_redirect_functions);
  }
  void TestRedirectorOverrunAccess() override {
    test_fixture_->TestOverrunAccess(clang_redirect_functions);
  }
  void TestRedirectorUnderrunAccess() override {
    test_fixture_->TestUnderrunAccess(clang_redirect_functions);
  }
  size_t InterceptorsCount() override {
    return arraysize(clang_intercept_functions);
  };
  size_t RedirectorsCount() override {
    return arraysize(clang_redirect_functions);
  };
};

// Specialization of the MemoryInterceptorsTest for the test that should be done
// with different sets of probes.
template <class T>
class MemoryInterceptorsTypedTest : public MemoryInterceptorsTest {
 public:
  ~MemoryInterceptorsTypedTest() override {}

  void SetUp() override {
    MemoryInterceptorsTest::SetUp();
    tester_.SetTestFixture(this);
  }

 protected:
  T tester_;
};

#ifndef _WIN64
typedef ::testing::Types<SyzyAsanMemoryInterceptorTester,
                         ClangMemoryInterceptorTester> MemoryInterceptorsTypes;
#else
typedef ::testing::Types<ClangMemoryInterceptorTester> MemoryInterceptorsTypes;
#endif
TYPED_TEST_CASE(MemoryInterceptorsTypedTest, MemoryInterceptorsTypes);

}  // namespace

TYPED_TEST(MemoryInterceptorsTypedTest, TestValidAccess) {
  tester_.TestValidAccess();
}

TYPED_TEST(MemoryInterceptorsTypedTest, TestOverrunAccess) {
  tester_.TestOverrunAccess();
}

TYPED_TEST(MemoryInterceptorsTypedTest, TestUnderrunAccess) {
  tester_.TestUnderrunAccess();
}

TYPED_TEST(MemoryInterceptorsTypedTest, TestRedirectorsNoop) {
  // Test that the redirect functions pass through to the noop tester.
  EXPECT_CALL(*this, OnRedirectorInvocation(_))
      .Times(static_cast<int>(tester_.RedirectorsCount()))
      .WillRepeatedly(Return(MEMORY_ACCESSOR_MODE_NOOP));
  tester_.TestRedirectorValidAccess();
}

TYPED_TEST(MemoryInterceptorsTypedTest, TestRedirectorsSmallMemory) {
  EXPECT_CALL(*this, OnRedirectorInvocation(_))
      .Times(3 * static_cast<int>(tester_.RedirectorsCount()))
#ifndef _WIN64
      .WillRepeatedly(Return(MEMORY_ACCESSOR_MODE_2G));
#else
      .WillRepeatedly(Return(MEMORY_ACCESSOR_MODE_8TB));
#endif

  // Test valid, underrun and overrun.
  tester_.TestRedirectorValidAccess();
  tester_.TestRedirectorOverrunAccess();
  tester_.TestRedirectorUnderrunAccess();
}

#ifndef _WIN64
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
#endif

}  // namespace asan
}  // namespace agent
