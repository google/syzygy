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

#include "syzygy/agent/asan/asan_crt_interceptors.h"

#include <windows.h>

#include "base/bind.h"
#include "gtest/gtest.h"
#include "syzygy/agent/asan/unittest_util.h"

namespace agent {
namespace asan {

namespace {

using testing::ScopedASanAlloc;

typedef testing::TestAsanRtl CrtInterceptorsTest;

// An arbitrary size for the buffer we allocate in the different unittests.
const size_t kAllocSize = 13;

void AsanErrorCallback(AsanErrorInfo* error_info) {
  // Our tests should clean up after themselves and not leave any blocks
  // corrupted.
  ASSERT_NE(HeapProxy::CORRUPTED_BLOCK, error_info->error_type);

  // Raise an exception to prevent the intercepted function from corrupting
  // the block. If this error is not handled then this will cause the unittest
  // to fail.
  ::RaiseException(EXCEPTION_ARRAY_BOUNDS_EXCEEDED, 0, 0, 0);
}

}  // namespace

TEST_F(CrtInterceptorsTest, AsanCheckMemset) {
  const size_t kAllocSize = 13;
  ScopedASanAlloc<uint8> mem(this, kAllocSize);
  ASSERT_TRUE(mem.get() != NULL);
  SetCallBackFunction(&AsanErrorCallback);
  EXPECT_EQ(mem.get(), memsetFunction(mem.GetAs<void*>(), 0xAA, kAllocSize));
  for (size_t i = 0; i < kAllocSize; ++i)
    EXPECT_EQ(0xAA, mem[i]);

  memsetFunctionFailing(mem.get() - 1, 0xBB, kAllocSize);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferUnderFlow));
  ResetLog();

  memsetFunctionFailing(mem.get(), 0xCC, kAllocSize + 1);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferOverFlow));
  ResetLog();
}

TEST_F(CrtInterceptorsTest, AsanCheckMemchr) {
  const size_t kAllocSize = 13;
  ScopedASanAlloc<uint8> mem(this, kAllocSize);
  ASSERT_TRUE(mem.get() != NULL);
  memset(mem.get(), 0, kAllocSize);
  mem[4] = 0xAA;

  SetCallBackFunction(&AsanErrorCallback);
  EXPECT_EQ(mem.get() + 4, memchrFunction(mem.get(), mem[4], kAllocSize));
  EXPECT_EQ(NULL, memchrFunction(mem.get(), mem[4] + 1, kAllocSize));

  memchrFunctionFailing(mem.get() - 1, mem[4], kAllocSize);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferUnderFlow));
  ResetLog();

  memchrFunctionFailing(mem.get() + 1, mem[4], kAllocSize);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferOverFlow));
  ResetLog();
}

TEST_F(CrtInterceptorsTest, AsanCheckMemmove) {
  const size_t kAllocSize = 13;
  ScopedASanAlloc<uint8> mem_src(this, kAllocSize);
  ASSERT_TRUE(mem_src.get() != NULL);
  // Fill the array with value going from 0 to kAllocSize;
  for (size_t i = 0; i < kAllocSize; ++i)
    mem_src[i] = i;

  SetCallBackFunction(&AsanErrorCallback);
  // Shift all the value from one index to the right.
  EXPECT_EQ(mem_src.get() + 1,
            memmoveFunction(mem_src.get() + 1, mem_src.get(), kAllocSize - 1));
  EXPECT_EQ(0, mem_src[0]);
  for (size_t i = 1; i < kAllocSize; ++i)
    EXPECT_EQ(i - 1, mem_src[i]);

  // Re-shift them to the left.
  memmoveFunctionFailing(mem_src.get(), mem_src.get() + 1, kAllocSize);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferOverFlow));
  ResetLog();

  memmoveFunctionFailing(mem_src.get() - 1, mem_src.get(), kAllocSize);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferUnderFlow));
  ResetLog();
}

TEST_F(CrtInterceptorsTest, AsanCheckMemcpy) {
  const size_t kAllocSize = 13;
  ScopedASanAlloc<uint8> mem_src(this, kAllocSize);
  ASSERT_TRUE(mem_src.get() != NULL);
  ScopedASanAlloc<uint8> mem_dst(this, kAllocSize);
  ASSERT_TRUE(mem_dst.get() != NULL);
  // Fill the array with value going from 0 to kAllocSize;
  for (size_t i = 0; i < kAllocSize; ++i) {
    mem_src[i] = i;
    mem_dst[i] = ~i;
  }

  SetCallBackFunction(&AsanErrorCallback);
  EXPECT_EQ(mem_dst.get(),
            memcpyFunction(mem_dst.get(), mem_src.get(), kAllocSize));
  for (size_t i = 0; i < kAllocSize; ++i)
    EXPECT_EQ(mem_dst[i], mem_src[i]);

  memcpyFunctionFailing(mem_dst.get(), mem_src.get(), kAllocSize + 1);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferOverFlow));
  ResetLog();

  memcpyFunctionFailing(mem_dst.get(), mem_src.get() - 1, kAllocSize);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferUnderFlow));
  ResetLog();
}

TEST_F(CrtInterceptorsTest, DISABLED_AsanCheckStrcspn) {
  // TODO(sebmarchand): Reactivate this unittest once the implementation of
  //     this interceptor has been fixed.
  const char* str_value = "abc1";
  ScopedASanAlloc<char> str(this, ::strlen(str_value) + 1, str_value);
  ASSERT_TRUE(str.get() != NULL);

  const char* str_value_2 = "abc";
  ScopedASanAlloc<char> str2(this, ::strlen(str_value_2) + 1, str_value_2);
  ASSERT_TRUE(str2.get() != NULL);

  // This should contain at least one value present in |str| but none present
  // in |str2|.
  const char* keys_value = "12";
  EXPECT_NE(::strlen(str_value), ::strcspn(str_value, keys_value));
  EXPECT_EQ(::strlen(str_value_2), ::strcspn(str_value_2, keys_value));
  ScopedASanAlloc<char> keys(this, ::strlen(keys_value) + 1, keys_value);
  ASSERT_TRUE(keys.get() != NULL);

  SetCallBackFunction(&AsanErrorCallback);
  EXPECT_EQ(::strcspn(str.get(), keys.get()),
            strcspnFunction(str.get(), keys.get()));

  strcspnFunctionFailing(str.get() - 1, keys.get());
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferUnderFlow));
  ResetLog();

  // The key set should be null terminated, otherwise an overflow should be
  // detected.
  size_t keys_len = ::strlen(keys.get());
  keys[keys_len] = 'a';
  strcspnFunctionFailing(str.get(), keys.get());
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferOverFlow));
  keys[keys_len] = 0;
  ResetLog();

  // The implementation allows a non null terminated input string if it contains
  // at least one of the keys, otherwise it'll overflow.

  size_t str_len = ::strlen(str.get());
  str[str_len] = 'a';
  EXPECT_EQ(::strcspn(str.get(), keys.get()),
            strcspnFunction(str.get(), keys.get()));
  str[str_len] = 0;
  ResetLog();

  size_t str2_len = ::strlen(str2.get());
  str2[str2_len] = 'a';
  strcspnFunctionFailing(str2.get(), keys.get());
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferOverFlow));
  str2[str2_len] = 0;
  ResetLog();
}

TEST_F(CrtInterceptorsTest, DISABLED_AsanStrcspnImpl) {
  // TODO(sebmarchand): Reactivate this unittest once the implementation of
  //     this interceptor has been fixed.
  EXPECT_EQ(5, asan_strcspn("abcde", "fgh"));
  EXPECT_EQ(5, asan_strcspn("abcde", ""));
  EXPECT_EQ(0, asan_strcspn("abcde", "abcde"));
  EXPECT_EQ(0U, asan_strcspn("abcde", "edcba"));
  EXPECT_EQ(3, asan_strcspn("abcde", "ed"));
  EXPECT_EQ(2, asan_strcspn("abcde", "c"));
  EXPECT_EQ(0U, asan_strcspn("", ""));
  EXPECT_EQ(0U, asan_strcspn("", "abcde"));
}

TEST_F(CrtInterceptorsTest, AsanCheckStrlen) {
  const char* str_value = "test_strlen";
  ScopedASanAlloc<char> str(this, ::strlen(str_value) + 1, str_value);
  ASSERT_TRUE(str != NULL);

  SetCallBackFunction(&AsanErrorCallback);
  EXPECT_EQ(::strlen(str.get()), strlenFunction(str.get()));

  strlenFunctionFailing(str.get() - 1);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferUnderFlow));
  ResetLog();

  size_t str_len = ::strlen(str.get());
  str[str_len] = 'a';
  strlenFunctionFailing(str.get());
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferOverFlow));
  ResetLog();
}

TEST_F(CrtInterceptorsTest, AsanCheckStrrchr) {
  const char* str_value = "test_strrchr";
  ScopedASanAlloc<char> str(this, ::strlen(str_value) + 1, str_value);
  ASSERT_TRUE(str != NULL);

  SetCallBackFunction(&AsanErrorCallback);
  EXPECT_EQ(::strrchr(str.get(), 'c'), strrchrFunction(str.get(), 'c'));
  EXPECT_EQ(::strrchr(str.get(), 'z'), strrchrFunction(str.get(), 'z'));

  strrchrFunctionFailing(str.get() - 1, 'c');
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferUnderFlow));
  ResetLog();

  size_t str_len = ::strlen(str.get());
  str[str_len] = 'a';
  strrchrFunctionFailing(str.get(), 'c');
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferOverFlow));
  ResetLog();
}

TEST_F(CrtInterceptorsTest, AsanCheckWcsrchr) {
  const wchar_t* wstr_value = L"test_wcsrchr";
  ScopedASanAlloc<wchar_t> wstr(this, ::wcslen(wstr_value) + 1);
  ASSERT_TRUE(wstr != NULL);
  wcscpy(wstr.get(), wstr_value);

  SetCallBackFunction(&AsanErrorCallback);
  EXPECT_EQ(::wcsrchr(wstr.get(), L'c'), wcsrchrFunction(wstr.get(), L'c'));
  EXPECT_EQ(::wcsrchr(wstr.get(), 'z'), wcsrchrFunction(wstr.get(), 'z'));

  wcsrchrFunctionFailing(wstr.get() - 1, L'c');
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferUnderFlow));
  ResetLog();

  size_t str_len = ::wcslen(wstr_value);
  wstr[str_len] = L'a';
  wcsrchrFunctionFailing(wstr.get(), L'c');
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferOverFlow));
  ResetLog();
}

TEST_F(CrtInterceptorsTest, DISABLED_AsanCheckStrcmp) {
  // TODO(sebmarchand): Reactivate this unittest once the implementation of
  //     this interceptor has been fixed.
  const char* str_value = "test_strcmp";
  ScopedASanAlloc<char> str(this, ::strlen(str_value) + 1, str_value);
  ASSERT_TRUE(str.get() != NULL);

  const char* keys_value = "strcmp";
  ScopedASanAlloc<char> keys(this, ::strlen(keys_value) + 1, keys_value);
  ASSERT_TRUE(keys.get() != NULL);

  SetCallBackFunction(&AsanErrorCallback);
  EXPECT_EQ(::strcmp(str.get(), keys.get()),
            strcmpFunction(str.get(), keys.get()));

  strcmpFunctionFailing(str.get() - 1, keys.get());
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferUnderFlow));
  ResetLog();

  size_t keys_len = ::strlen(keys.get());
  keys[keys_len] = 'a';
  strcmpFunctionFailing(str.get(), keys.get());
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferOverFlow));
  keys[keys_len] = 0;
  ResetLog();
}

TEST_F(CrtInterceptorsTest, DISABLED_AsanCheckStrpbrk) {
  // TODO(sebmarchand): Reactivate this unittest once the implementation of
  //     this interceptor has been fixed.
  const char* str_value = "abc1";
  ScopedASanAlloc<char> str(this, ::strlen(str_value) + 1, str_value);
  ASSERT_TRUE(str.get() != NULL);

  const char* str_value_2 = "abc";
  ScopedASanAlloc<char> str2(this, ::strlen(str_value_2) + 1, str_value_2);
  ASSERT_TRUE(str2.get() != NULL);

  // This should contain at least one value present in |str| but none present
  // in |str2|.
  const char* keys_value = "12";
  EXPECT_NE(::strlen(str_value), ::strcspn(str_value, keys_value));
  EXPECT_EQ(::strlen(str_value_2), ::strcspn(str_value_2, keys_value));
  ScopedASanAlloc<char> keys(this, ::strlen(keys_value) + 1, keys_value);
  ASSERT_TRUE(keys.get() != NULL);

  SetCallBackFunction(&AsanErrorCallback);
  EXPECT_EQ(::strpbrk(str.get(), keys.get()),
            strpbrkFunction(str.get(), keys.get()));

  strpbrkFunctionFailing(str.get() - 1, keys.get());
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferUnderFlow));
  ResetLog();

  size_t keys_len = ::strlen(keys.get());
  keys[keys_len] = 'a';
  strpbrkFunctionFailing(str.get(), keys.get());
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferOverFlow));
  keys[keys_len] = 0;
  ResetLog();

  // The implementation allows a non null terminated input string if it contains
  // at least one of the keys, otherwise it'll overflow.

  size_t str_len = ::strlen(str.get());
  str[str_len] = 'a';
  EXPECT_EQ(::strpbrk(str.get(), keys.get()),
            strpbrkFunction(str.get(), keys.get()));
  str[str_len] = 0;
  ResetLog();

  size_t str2_len = ::strlen(str2.get());
  str2[str2_len] = 'a';
  strpbrkFunctionFailing(str2.get(), keys.get());
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferOverFlow));
  str2[str2_len] = 0;
  ResetLog();
}

TEST_F(CrtInterceptorsTest, DISABLED_AsanStrpbrkImpl) {
  // TODO(sebmarchand): Reactivate this unittest once the implementation of
  //     this interceptor has been fixed.
  const char* abcde = "abcde";
  const char* empty_string = "";
  EXPECT_EQ(strpbrk(abcde, abcde), asan_strpbrk(abcde, abcde));
  EXPECT_EQ(strpbrk(abcde, "fgh"), asan_strpbrk(abcde, "fgh"));
  EXPECT_EQ(strpbrk(abcde, ""), asan_strpbrk(abcde, ""));
  EXPECT_EQ(strpbrk(abcde, "edcba"), asan_strpbrk(abcde, "edcba"));
  EXPECT_EQ(strpbrk(abcde, "ed"), asan_strpbrk(abcde, "ed"));
  EXPECT_EQ(strpbrk(abcde, "c"), asan_strpbrk(abcde, "c"));
  EXPECT_EQ(strpbrk(empty_string, ""), asan_strpbrk(empty_string, ""));
  EXPECT_EQ(strpbrk(empty_string, abcde), asan_strpbrk(empty_string, abcde));
}

TEST_F(CrtInterceptorsTest, DISABLED_AsanCheckStrstr) {
  // TODO(sebmarchand): Reactivate this unittest once the implementation of
  //     this interceptor has been fixed.
  const char* str_value = "test_strstr";
  ScopedASanAlloc<char> str(this, ::strlen(str_value) + 1, str_value);
  ASSERT_TRUE(str != NULL);

  const char* keys_value = "strstr";
  ScopedASanAlloc<char> keys(this, ::strlen(keys_value) + 1, keys_value);
  ASSERT_TRUE(keys.get() != NULL);

  SetCallBackFunction(&AsanErrorCallback);
  EXPECT_EQ(::strstr(str.get(), keys.get()),
            strstrFunction(str.get(), keys.get()));

  strstrFunctionFailing(str.get() - 1, keys.get());
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferUnderFlow));
  ResetLog();

  size_t keys_len = ::strlen(keys.get());
  keys[keys_len] = 'a';
  strstrFunctionFailing(str.get(), keys.get());
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferOverFlow));
  keys[keys_len] = 0;
  ResetLog();
}

TEST_F(CrtInterceptorsTest, DISABLED_AsanCheckStrspn) {
  // TODO(sebmarchand): Reactivate this unittest once the implementation of
  //     this interceptor has been fixed.
  const char* str_value = "123_abc";
  ScopedASanAlloc<char> str(this, ::strlen(str_value) + 1, str_value);
  ASSERT_TRUE(str.get() != NULL);

  const char* keys_value = "123";
  EXPECT_EQ(::strlen(keys_value), ::strspn(str_value, keys_value));
  ScopedASanAlloc<char> keys(this, ::strlen(keys_value) + 1, keys_value);
  ASSERT_TRUE(keys.get() != NULL);

  // The second test string should only contains values present in the keys.
  const char* str_value_2 = "12321";
  ScopedASanAlloc<char> str2(this, ::strlen(str_value_2) + 1, str_value_2);
  EXPECT_EQ(::strlen(str_value_2), ::strspn(str_value_2, keys_value));
  ASSERT_TRUE(str2.get() != NULL);

  SetCallBackFunction(&AsanErrorCallback);
  EXPECT_EQ(::strspn(str.get(), keys.get()),
            strspnFunction(str.get(), keys.get()));

  strspnFunctionFailing(str.get() - 1, keys.get());
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferUnderFlow));
  ResetLog();

  size_t keys_len = ::strlen(keys.get());
  keys[keys_len] = 'a';
  strspnFunctionFailing(str.get(), keys.get());
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferOverFlow));
  keys[keys_len] = 0;
  ResetLog();

  // The implementation allows a non null terminated input string if it doesn't
  // start with a value contained in the keys, otherwise it'll overflow.

  size_t str_len = ::strlen(str.get());
  str[str_len] = 'a';
  EXPECT_EQ(::strspn(str.get(), keys.get()),
            strspnFunction(str.get(), keys.get()));
  str[str_len] = 0;
  ResetLog();

  size_t str2_len = ::strlen(str2.get());
  str2[str2_len] = keys[0];
  strspnFunctionFailing(str2.get(), keys.get());
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferOverFlow));
  str2[str2_len] = 0;
  ResetLog();
}

TEST_F(CrtInterceptorsTest, DISABLED_AsanStrspnImpl) {
  // TODO(sebmarchand): Reactivate this unittest once the implementation of
  //     this interceptor has been fixed.
  EXPECT_EQ(5, asan_strspn("abcde", "abcde"));
  EXPECT_EQ(5, asan_strspn("abcde", "edcba"));
  EXPECT_EQ(0U, asan_strspn("abcde", ""));
  EXPECT_EQ(2, asan_strspn("abcde", "ab"));
  EXPECT_EQ(4, asan_strspn("abccde", "abc"));
  EXPECT_EQ(2, asan_strspn("abcde", "fghab"));
  EXPECT_EQ(3, asan_strspn("abcde", "fagbhc"));
  EXPECT_EQ(1, asan_strspn("abcde", "aaa"));
  EXPECT_EQ(0U, asan_strspn("abcde", "fgh"));
  EXPECT_EQ(0U, asan_strspn("", ""));
  EXPECT_EQ(0U, asan_strspn("", "abcde"));
}

TEST_F(CrtInterceptorsTest, AsanCheckStrncpy) {
  const char* str_value = "test_strncpy";
  ScopedASanAlloc<char> source(this, ::strlen(str_value) + 1, str_value);
  ASSERT_TRUE(source != NULL);

  const char* long_str_value = "test_strncpy_long_source";
  ScopedASanAlloc<char> long_source(this, ::strlen(long_str_value) + 1,
      long_str_value);
  ASSERT_TRUE(long_source.get() != NULL);

  ScopedASanAlloc<char> destination(this, ::strlen(str_value) + 1);
  ASSERT_TRUE(destination != NULL);

  SetCallBackFunction(&AsanErrorCallback);
  EXPECT_EQ(destination.get(),
            strncpyFunction(destination.get(),
                            source.get(),
                            ::strlen(str_value)));

  // Test an underflow on the source.
  strncpyFunctionFailing(destination.get(),
                         source.get() - 1,
                         ::strlen(str_value));
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferUnderFlow));
  ResetLog();

  // Test an underflow on the destination.
  strncpyFunctionFailing(destination.get() - 1,
                         source.get(),
                         ::strlen(str_value));
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferUnderFlow));
  ResetLog();

  // Test an overflow on the destination.
  std::vector<uint8> original_data(::strlen(long_str_value));
  memcpy(&original_data[0], destination.get(), ::strlen(long_str_value));
  strncpyFunctionFailing(destination.get(),
                         long_source.get(),
                         ::strlen(long_str_value));
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferOverFlow));
  ResetLog();

  // Another overflow on the destination.
  strncpyFunctionFailing(destination.get(),
                         source.get(),
                         ::strlen(str_value) + 2);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferOverFlow));
  ResetLog();

  // Test an overflow on the source.
  size_t source_len = ::strlen(source.get());
  source[source_len] = 'a';
  strncpyFunctionFailing(destination.get(),
                         source.get(),
                         ::strlen(source.get()) + 1);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferOverFlow));
  source[source_len] = 0;
  ResetLog();
}

TEST_F(CrtInterceptorsTest, AsanCheckStrncat) {
  const char* prefix_value = "test_";
  const char* suffix_value = "strncat";
  char buffer[64];

  ScopedASanAlloc<char> mem(this,
      ::strlen(prefix_value) + ::strlen(suffix_value) + 1, prefix_value);
  ASSERT_TRUE(mem != NULL);
  ::strcpy(buffer, prefix_value);

  ScopedASanAlloc<char> suffix(this, ::strlen(suffix_value) + 1, suffix_value);
  ASSERT_TRUE(mem.get() != NULL);

  SetCallBackFunction(&AsanErrorCallback);
  EXPECT_EQ(mem.get(),
      strncatFunction(mem.get(), suffix.get(), ::strlen(suffix_value)));
  EXPECT_STRCASEEQ(
      ::strncat(buffer, suffix.get(), ::strlen(suffix_value)), mem.get());

  // Test an underflow on the suffix.
  ::strcpy(mem.get(), prefix_value);
  ::strcpy(buffer, prefix_value);
  strncatFunctionFailing(mem.get(), suffix.get() - 1, ::strlen(suffix_value));
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferUnderFlow));
  ResetLog();

  // Test an underflow on the destination.
  ::strcpy(mem.get(), prefix_value);
  ::strcpy(buffer, prefix_value);
  strncatFunctionFailing(mem.get() - 1, suffix.get(), ::strlen(suffix_value));
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferUnderFlow));
  ResetLog();

  // Test an overflow on the suffix.
  size_t suffix_len = ::strlen(suffix.get());
  suffix[suffix_len] = 'a';
  ::strcpy(mem.get(), prefix_value);
  ::strcpy(buffer, prefix_value);
  strncatFunctionFailing(mem.get(), suffix.get(), ::strlen(suffix.get()) + 1);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferOverFlow));
  suffix[suffix_len] = 0;
  ResetLog();

  // Test an overflow on the destination.
  ::strcpy(mem.get(), prefix_value);
  ::strcpy(buffer, prefix_value);
  size_t prefix_len = ::strlen(prefix_value);
  mem[prefix_len] = 'a';
  buffer[prefix_len] = 'a';
  strncatFunctionFailing(mem.get(), suffix.get(), ::strlen(suffix.get()));
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferOverFlow));
  mem[prefix_len] = 0;
  buffer[prefix_len] = 0;
  ResetLog();
}

}  // namespace asan
}  // namespace agent
