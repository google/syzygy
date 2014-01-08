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

#include <windows.h>

#include "base/bind.h"
#include "gtest/gtest.h"
#include "syzygy/agent/asan/unittest_util.h"

namespace agent {
namespace asan {

namespace {

using testing::ScopedASanAlloc;

typedef testing::TestAsanRtl CrtInterceptorsTest;

// A flag used in asan callback to ensure that a memory error has been detected.
bool memory_error_detected = false;
// An arbitrary size for the buffer we allocate in the different unittests.
const size_t kAllocSize = 13;

void AsanErrorCallback(AsanErrorInfo* error_info) {
  memory_error_detected = true;
}

}  // namespace

TEST_F(CrtInterceptorsTest, AsanCheckMemset) {
  const size_t kAllocSize = 13;
  ScopedASanAlloc<uint8> mem(this, kAllocSize);
  ASSERT_TRUE(mem.get() != NULL);
  memory_error_detected = false;

  SetCallBackFunction(&AsanErrorCallback);
  EXPECT_EQ(mem.get(), memsetFunction(mem.GetAs<void*>(), 0xAA, kAllocSize));
  EXPECT_FALSE(memory_error_detected);
  for (size_t i = 0; i < kAllocSize; ++i)
    EXPECT_EQ(0xAA, mem[i]);

  // mem[-1] points to the block header, we need to make sure that it doesn't
  // contain the value we're looking for.
  uint8 last_block_header_byte = mem[-1];
  mem[-1] = 0;
  EXPECT_EQ(mem.get() - 1, memsetFunction(mem.get() - 1, 0xBB, kAllocSize));
  EXPECT_TRUE(memory_error_detected);
  for (size_t i = 0; i < kAllocSize; ++i)
    EXPECT_EQ(0xBB, mem[i - 1]);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferUnderFlow));
  mem[-1] = last_block_header_byte;
  ResetLog();

  memory_error_detected = false;
  EXPECT_EQ(mem.get(), memsetFunction(mem.get(), 0xCC, kAllocSize + 1));
  for (size_t i = 0; i < kAllocSize + 1; ++i)
    EXPECT_EQ(0xCC, mem[i]);
  EXPECT_TRUE(memory_error_detected);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferOverFlow));
  ResetLog();
}

TEST_F(CrtInterceptorsTest, AsanCheckMemchr) {
  const size_t kAllocSize = 13;
  ScopedASanAlloc<uint8> mem(this, kAllocSize);
  ASSERT_TRUE(mem.get() != NULL);
  ::memset(mem.get(), 0, kAllocSize);
  mem[4] = 0xAA;
  memory_error_detected = false;

  SetCallBackFunction(&AsanErrorCallback);
  EXPECT_EQ(mem.get() + 4, memchrFunction(mem.get(), mem[4], kAllocSize));
  EXPECT_EQ(NULL, memchrFunction(mem.get(), mem[4] + 1, kAllocSize));
  EXPECT_FALSE(memory_error_detected);

  // mem[-1] points to the block header, we need to make sure that it doesn't
  // contain the value we're looking for.
  uint8 last_block_header_byte = mem[-1];
  mem[-1] = 0;
  EXPECT_EQ(mem.get() + 4, memchrFunction(mem.get() - 1, mem[4], kAllocSize));
  EXPECT_TRUE(memory_error_detected);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferUnderFlow));
  mem[-1] = last_block_header_byte;
  ResetLog();

  memory_error_detected = false;
  EXPECT_EQ(mem.get() + 4, memchrFunction(mem.get() + 1, mem[4], kAllocSize));
  EXPECT_TRUE(memory_error_detected);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferOverFlow));
  ResetLog();
}

TEST_F(CrtInterceptorsTest, AsanCheckMemmove) {
  const size_t kAllocSize = 13;
  ScopedASanAlloc<uint8> mem_src(this, kAllocSize);
  ASSERT_TRUE(mem_src.get() != NULL);
  memory_error_detected = false;
  // Fill the array with value going from 0 to kAllocSize;
  for (size_t i = 0; i < kAllocSize; ++i)
    mem_src[i] = i;

  SetCallBackFunction(&AsanErrorCallback);
  // Shift all the value from one index to the right.
  EXPECT_EQ(mem_src.get() + 1,
            memmoveFunction(mem_src.get() + 1, mem_src.get(), kAllocSize - 1));
  EXPECT_FALSE(memory_error_detected);
  EXPECT_EQ(0, mem_src[0]);
  for (size_t i = 1; i < kAllocSize; ++i)
    EXPECT_EQ(i - 1, mem_src[i]);

  // Re-shift them to the left.
  EXPECT_EQ(mem_src.get(),
            memmoveFunction(mem_src.get(), mem_src.get() + 1, kAllocSize));
  EXPECT_TRUE(memory_error_detected);
  for (size_t i = 0; i < kAllocSize - 1; ++i)
    EXPECT_EQ(i, mem_src[i]);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferOverFlow));
  ResetLog();

  memory_error_detected = false;
  // Shift them to the left one more time.

  // mem_src[-1] points to the block header, we need to make sure that it
  // doesn't contain the value we're looking for.
  uint8 last_block_header_byte = mem_src[-1];
  mem_src[-1] = 0;
  EXPECT_EQ(mem_src.get() - 1,
            memmoveFunction(mem_src.get() - 1, mem_src.get(), kAllocSize));
  EXPECT_TRUE(memory_error_detected);
  for (int i = -1; i < static_cast<int>(kAllocSize) - 2; ++i)
    EXPECT_EQ(i + 1, mem_src[i]);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferUnderFlow));
  mem_src[-1] = last_block_header_byte;
  ResetLog();
}

TEST_F(CrtInterceptorsTest, AsanCheckMemcpy) {
  const size_t kAllocSize = 13;
  ScopedASanAlloc<uint8> mem_src(this, kAllocSize);
  ASSERT_TRUE(mem_src.get() != NULL);
  ScopedASanAlloc<uint8> mem_dst(this, kAllocSize);
  ASSERT_TRUE(mem_dst.get() != NULL);
  memory_error_detected = false;
  // Fill the array with value going from 0 to kAllocSize;
  for (size_t i = 0; i < kAllocSize; ++i) {
    mem_src[i] = i;
    mem_dst[i] = ~i;
  }

  SetCallBackFunction(&AsanErrorCallback);
  EXPECT_EQ(mem_dst.get(),
            memcpyFunction(mem_dst.get(), mem_src.get(), kAllocSize));
  EXPECT_FALSE(memory_error_detected);
  for (size_t i = 0; i < kAllocSize; ++i)
    EXPECT_EQ(mem_dst[i], mem_src[i]);

  EXPECT_EQ(mem_dst.get(),
            memcpyFunction(mem_dst.get(), mem_src.get(), kAllocSize + 1));
  EXPECT_TRUE(memory_error_detected);
  for (size_t i = 0; i < kAllocSize + 1; ++i)
    EXPECT_EQ(mem_dst[i], mem_src[i]);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferOverFlow));
  ResetLog();

  memory_error_detected = false;
  uint8 last_block_header_byte = mem_dst[-1];
  mem_dst[-1] = 0;
  EXPECT_EQ(mem_dst.get(),
            memcpyFunction(mem_dst.get(), mem_src.get() - 1, kAllocSize));
  EXPECT_TRUE(memory_error_detected);
  for (int i = -1; i < static_cast<int>(kAllocSize) - 1; ++i)
    EXPECT_EQ(mem_dst[i + 1], mem_src[i]);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferUnderFlow));
  mem_dst[-1] = last_block_header_byte;
  ResetLog();
}

TEST_F(CrtInterceptorsTest, AsanCheckStrcspn) {
  const char* str_value = "abc1";
  ScopedASanAlloc<char> str(this, ::strlen(str_value) + 1);
  ASSERT_TRUE(str.get() != NULL);
  ::strcpy(str.get(), str_value);

  const char* keys_value = "12";
  ScopedASanAlloc<char> keys(this, ::strlen(keys_value) + 1);
  ASSERT_TRUE(keys.get() != NULL);
  ::strcpy(keys.get(), keys_value);

  SetCallBackFunction(&AsanErrorCallback);
  memory_error_detected = false;

  EXPECT_EQ(strcspn(str.get(), keys.get()),
            strcspnFunction(str.get(), keys.get()));
  EXPECT_FALSE(memory_error_detected);

  // str[-1] points to the block header, we need to make sure that it doesn't
  // contain the value \0.
  uint8 last_block_header_byte = str[-1];
  str[-1] = 'a';
  EXPECT_EQ(strcspn(str.get() - 1, keys.get()),
            strcspnFunction(str.get() - 1, keys.get()));
  EXPECT_TRUE(memory_error_detected);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferUnderFlow));
  str[-1] = last_block_header_byte;
  ResetLog();

  memory_error_detected = false;
  size_t keys_len = ::strlen(keys.get());
  keys[keys_len] = 'a';
  keys[keys_len + 1] = 0;
  EXPECT_EQ(strcspn(str.get(), keys.get()),
            strcspnFunction(str.get(), keys.get()));
  EXPECT_TRUE(memory_error_detected);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferOverFlow));
  ResetLog();
}

TEST_F(CrtInterceptorsTest, AsanCheckStrlen) {
  const char* str_value = "test_strlen";
  ScopedASanAlloc<char> str(this, ::strlen(str_value) + 1);
  ASSERT_TRUE(str != NULL);
  ::strcpy(str.get(), str_value);

  SetCallBackFunction(&AsanErrorCallback);
  memory_error_detected = false;

  EXPECT_EQ(::strlen(str.get()), strlenFunction(str.get()));
  EXPECT_FALSE(memory_error_detected);

  // str[-1] points to the block header, we need to make sure that it doesn't
  // contain the value \0.
  uint8 last_block_header_byte = str[-1];
  str[-1] = 'a';
  EXPECT_EQ(::strlen(str.get() - 1), strlenFunction(str.get() - 1));
  EXPECT_TRUE(memory_error_detected);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferUnderFlow));
  str[-1] = last_block_header_byte;
  ResetLog();

  memory_error_detected = false;
  size_t str_len = ::strlen(str.get());
  str[str_len] = 'a';
  str[str_len + 1] = 0;
  EXPECT_EQ(::strlen(str.get()), strlenFunction(str.get()));
  EXPECT_TRUE(memory_error_detected);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferOverFlow));
  ResetLog();
}

TEST_F(CrtInterceptorsTest, AsanCheckStrrchr) {
  const char* str_value = "test_strrchr";
  ScopedASanAlloc<char> str(this, ::strlen(str_value) + 1);
  ASSERT_TRUE(str != NULL);
  ::strcpy(str.get(), str_value);

  SetCallBackFunction(&AsanErrorCallback);
  memory_error_detected = false;

  EXPECT_EQ(::strrchr(str.get(), 'c'), strrchrFunction(str.get(), 'c'));
  EXPECT_FALSE(memory_error_detected);
  EXPECT_EQ(::strrchr(str.get(), 'z'), strrchrFunction(str.get(), 'z'));
  EXPECT_FALSE(memory_error_detected);

  // str[-1] points to the block header, we need to make sure that it doesn't
  // contain the value \0.
  uint8 last_block_header_byte = str[-1];
  str[-1] = 'a';
  EXPECT_EQ(::strrchr(str.get() - 1, 'c'), strrchrFunction(str.get() - 1, 'c'));
  EXPECT_TRUE(memory_error_detected);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferUnderFlow));
  str[-1] = last_block_header_byte;
  ResetLog();

  memory_error_detected = false;
  size_t str_len = ::strlen(str.get());
  str[str_len] = 'a';
  str[str_len + 1] = 0;
  EXPECT_EQ(::strrchr(str.get(), 'c'), strrchrFunction(str.get(), 'c'));
  EXPECT_TRUE(memory_error_detected);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferOverFlow));
  ResetLog();
}

TEST_F(CrtInterceptorsTest, AsanCheckWcsrchr) {
  const wchar_t* wstr_value = L"test_wcsrchr";
  ScopedASanAlloc<wchar_t> wstr(this, wcslen(wstr_value) + 1);
  ASSERT_TRUE(wstr != NULL);
  wcscpy(wstr.get(), wstr_value);

  SetCallBackFunction(&AsanErrorCallback);
  memory_error_detected = false;

  EXPECT_EQ(::wcsrchr(wstr.get(), L'c'), wcsrchrFunction(wstr.get(), L'c'));
  EXPECT_FALSE(memory_error_detected);
  EXPECT_EQ(::wcsrchr(wstr.get(), 'z'), wcsrchrFunction(wstr.get(), 'z'));
  EXPECT_FALSE(memory_error_detected);

  // wstr[-1] points to the block header, we need to make sure that it doesn't
  // contain the value \0.
  uint8 last_block_header_byte = wstr[-1];
  wstr[-1] = L'a';
  EXPECT_EQ(::wcsrchr(wstr.get() - 1, L'c'),
            wcsrchrFunction(wstr.get() - 1, L'c'));
  EXPECT_TRUE(memory_error_detected);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferUnderFlow));
  wstr[-1] = last_block_header_byte;
  ResetLog();

  memory_error_detected = false;
  size_t str_len = ::wcslen(wstr_value);
  wstr[str_len] = L'a';
  wstr[str_len + 1] = 0;
  EXPECT_EQ(::wcsrchr(wstr.get(), L'c'), wcsrchrFunction(wstr.get(), L'c'));
  EXPECT_TRUE(memory_error_detected);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferOverFlow));
  ResetLog();
}

TEST_F(CrtInterceptorsTest, AsanCheckStrcmp) {
  const char* str_value = "test_strcmp";
  ScopedASanAlloc<char> str(this, ::strlen(str_value) + 1);
  ASSERT_TRUE(str.get() != NULL);
  ::strcpy(str.get(), str_value);

  const char* keys_value = "strcmp";
  ScopedASanAlloc<char> keys(this, ::strlen(keys_value) + 1);
  ASSERT_TRUE(keys != NULL);
  ::strcpy(keys.get(), keys_value);

  SetCallBackFunction(&AsanErrorCallback);
  memory_error_detected = false;

  EXPECT_EQ(::strcmp(str.get(), keys.get()),
            strcmpFunction(str.get(), keys.get()));
  EXPECT_FALSE(memory_error_detected);

  // str[-1] points to the block header, we need to make sure that it doesn't
  // contain the value \0.
  uint8 last_block_header_byte = str[-1];
  str[-1] = 'a';
  EXPECT_EQ(::strcmp(str.get() - 1, keys.get()),
            strcmpFunction(str.get() - 1, keys.get()));
  EXPECT_TRUE(memory_error_detected);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferUnderFlow));
  str[-1] = last_block_header_byte;
  ResetLog();

  memory_error_detected = false;
  size_t keys_len = ::strlen(keys.get());
  keys[keys_len] = 'a';
  keys[keys_len + 1] = 0;
  EXPECT_EQ(::strcmp(str.get(), keys.get()),
            strcmpFunction(str.get(), keys.get()));
  EXPECT_TRUE(memory_error_detected);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferOverFlow));
  ResetLog();
}

TEST_F(CrtInterceptorsTest, AsanCheckStrpbrk) {
  const char* str_value = "test_strpbrk";
  ScopedASanAlloc<char> str(this, ::strlen(str_value) + 1);
  ASSERT_TRUE(str != NULL);
  ::strcpy(str.get(), str_value);

  const char* keys_value = "strpbrk";
  ScopedASanAlloc<char> keys(this, ::strlen(keys_value) + 1);
  ASSERT_TRUE(keys != NULL);
  ::strcpy(keys.get(), keys_value);

  SetCallBackFunction(&AsanErrorCallback);
  memory_error_detected = false;

  EXPECT_EQ(::strpbrk(str.get(), keys.get()),
            strpbrkFunction(str.get(), keys.get()));
  EXPECT_FALSE(memory_error_detected);

  // str[-1] points to the block header, we need to make sure that it doesn't
  // contain the value \0.
  uint8 last_block_header_byte = str[-1];
  str[-1] = 'a';
  EXPECT_EQ(::strpbrk(str.get() - 1, keys.get()),
            strpbrkFunction(str.get() - 1, keys.get()));
  EXPECT_TRUE(memory_error_detected);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferUnderFlow));
  str[-1] = last_block_header_byte;
  ResetLog();

  memory_error_detected = false;
  size_t keys_len = ::strlen(keys.get());
  keys[keys_len] = 'a';
  keys[keys_len + 1] = 0;
  EXPECT_EQ(::strpbrk(str.get(), keys.get()),
            strpbrkFunction(str.get(), keys.get()));
  EXPECT_TRUE(memory_error_detected);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferOverFlow));
  ResetLog();
}

TEST_F(CrtInterceptorsTest, AsanCheckStrstr) {
  const char* str_value = "test_strstr";
  ScopedASanAlloc<char> str(this, ::strlen(str_value) + 1);
  ASSERT_TRUE(str != NULL);
  ::strcpy(str.get(), str_value);

  const char* keys_value = "strstr";
  ScopedASanAlloc<char> keys(this, ::strlen(keys_value) + 1);
  ASSERT_TRUE(keys != NULL);
  ::strcpy(keys.get(), keys_value);

  SetCallBackFunction(&AsanErrorCallback);
  memory_error_detected = false;

  EXPECT_EQ(::strstr(str.get(), keys.get()),
            strstrFunction(str.get(), keys.get()));
  EXPECT_FALSE(memory_error_detected);

  // str[-1] points to the block header, we need to make sure that it doesn't
  // contain the value \0.
  uint8 last_block_header_byte = str[-1];
  str[-1] = 'a';
  EXPECT_EQ(::strstr(str.get() - 1, keys.get()),
            strstrFunction(str.get() - 1, keys.get()));
  EXPECT_TRUE(memory_error_detected);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferUnderFlow));
  str[-1] = last_block_header_byte;
  ResetLog();

  memory_error_detected = false;
  size_t keys_len = ::strlen(keys.get());
  keys[keys_len] = 'a';
  keys[keys_len + 1] = 0;
  EXPECT_EQ(::strstr(str.get(), keys.get()),
            strstrFunction(str.get(), keys.get()));
  EXPECT_TRUE(memory_error_detected);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferOverFlow));
  ResetLog();
}

TEST_F(CrtInterceptorsTest, AsanCheckStrspn) {
  const char* str_value = "test_strspn";
  ScopedASanAlloc<char> str(this, ::strlen(str_value) + 1);
  ASSERT_TRUE(str != NULL);
  ::strcpy(str.get(), str_value);

  const char* keys_value = "strspn";
  ScopedASanAlloc<char> keys(this, ::strlen(keys_value) + 1);
  ASSERT_TRUE(keys != NULL);
  ::strcpy(keys.get(), keys_value);

  SetCallBackFunction(&AsanErrorCallback);
  memory_error_detected = false;

  EXPECT_EQ(::strspn(str.get(), keys.get()),
            strspnFunction(str.get(), keys.get()));
  EXPECT_FALSE(memory_error_detected);

  // str[-1] points to the block header, we need to make sure that it doesn't
  // contain the value \0.
  uint8 last_block_header_byte = str[-1];
  str[-1] = 'a';
  EXPECT_EQ(::strspn(str.get() - 1, keys.get()),
            strspnFunction(str.get() - 1, keys.get()));
  EXPECT_TRUE(memory_error_detected);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferUnderFlow));
  str[-1] = last_block_header_byte;
  ResetLog();

  memory_error_detected = false;
  size_t keys_len = ::strlen(keys.get());
  keys[keys_len] = 'a';
  keys[keys_len + 1] = 0;
  EXPECT_EQ(::strspn(str.get(), keys.get()),
            strspnFunction(str.get(), keys.get()));
  EXPECT_TRUE(memory_error_detected);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferOverFlow));
  ResetLog();
}

TEST_F(CrtInterceptorsTest, AsanCheckStrncpy) {
  const char* str_value = "test_strncpy";
  ScopedASanAlloc<char> source(this, ::strlen(str_value) + 1);
  ASSERT_TRUE(source != NULL);
  ::strcpy(source.get(), str_value);

  const char* long_str_value = "test_strncpy_long_source";
  ScopedASanAlloc<char> long_source(this, ::strlen(long_str_value) + 1);
  ASSERT_TRUE(long_source.get() != NULL);
  ::strcpy(long_source.get(), long_str_value);

  ScopedASanAlloc<char> destination(this, ::strlen(str_value) + 1);
  ASSERT_TRUE(destination != NULL);

  SetCallBackFunction(&AsanErrorCallback);
  memory_error_detected = false;

  EXPECT_EQ(destination.get(),
            strncpyFunction(destination.get(),
                            source.get(),
                            ::strlen(str_value)));
  EXPECT_FALSE(memory_error_detected);

  // Test an underflow on the source.
  uint8 last_block_header_byte = source[-1];
  source[-1] = 'a';
  EXPECT_EQ(destination.get(),
            strncpyFunction(destination.get(),
                            source.get() - 1,
                            ::strlen(str_value)));
  EXPECT_TRUE(memory_error_detected);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferUnderFlow));
  source[-1] = last_block_header_byte;
  ResetLog();

  // Test an underflow on the destination.
  memory_error_detected = false;
  last_block_header_byte = destination[-1];
  destination[-1] = 'a';
  EXPECT_EQ(destination.get() - 1,
            strncpyFunction(destination.get() - 1,
                            source.get(),
                            ::strlen(str_value)));
  EXPECT_TRUE(memory_error_detected);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferUnderFlow));
  destination[-1] = last_block_header_byte;
  ResetLog();

  // Test an overflow on the destination.
  memory_error_detected = false;
  EXPECT_EQ(destination.get(),
            strncpyFunction(destination.get(),
                            long_source.get(),
                            ::strlen(long_str_value)));
  EXPECT_TRUE(memory_error_detected);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferOverFlow));
  ResetLog();

  // Another overflow on the destination.
  memory_error_detected = false;
  EXPECT_EQ(destination,
            strncpyFunction(destination.get(),
                            source.get(),
                            ::strlen(str_value) + 2));
  EXPECT_TRUE(memory_error_detected);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferOverFlow));
  ResetLog();

  // Test an overflow on the source.
  size_t source_len = ::strlen(source.get());
  source[source_len] = 'a';
  source[source_len + 1] = 0;
  memory_error_detected = false;
  EXPECT_EQ(destination.get(), strncpyFunction(destination.get(),
                                               source.get(),
                                               ::strlen(source.get()) + 1));
  EXPECT_TRUE(memory_error_detected);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferOverFlow));
  ResetLog();

  memory_error_detected = false;
  EXPECT_EQ(destination.get(), strncpyFunction(destination.get(),
                                               source.get(),
                                               ::strlen(source.get())));
  EXPECT_FALSE(memory_error_detected);
  ResetLog();
}

TEST_F(CrtInterceptorsTest, AsanCheckStrncat) {
  const char* prefix_value = "test_";
  const char* suffix_value = "strncat";
  char buffer[64];

  ScopedASanAlloc<char> mem(this,
      ::strlen(prefix_value) + ::strlen(suffix_value) + 1);
  ASSERT_TRUE(mem != NULL);
  ::strcpy(mem.get(), prefix_value);
  ::strcpy(buffer, prefix_value);

  ScopedASanAlloc<char> suffix(this, ::strlen(suffix_value) + 1);
  ASSERT_TRUE(mem.get() != NULL);
  ::strcpy(suffix.get(), suffix_value);

  SetCallBackFunction(&AsanErrorCallback);
  memory_error_detected = false;

  EXPECT_EQ(mem.get(),
      strncatFunction(mem.get(), suffix.get(), ::strlen(suffix_value)));
  EXPECT_FALSE(memory_error_detected);
  EXPECT_STRCASEEQ(
      ::strncat(buffer, suffix.get(), ::strlen(suffix_value)), mem.get());

  // Test an underflow on the suffix.
  uint8 last_block_header_byte = suffix[-1];
  suffix[-1] = 'a';
  ::strcpy(mem.get(), prefix_value);
  ::strcpy(buffer, prefix_value);
  EXPECT_EQ(mem.get(),
      strncatFunction(mem.get(), suffix.get() - 1, ::strlen(suffix_value)));
  EXPECT_TRUE(memory_error_detected);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferUnderFlow));
  EXPECT_STRCASEEQ(
      ::strncat(buffer, suffix.get() - 1, ::strlen(suffix_value)), mem.get());
  suffix[-1] = last_block_header_byte;
  ResetLog();

  // Test an underflow on the destination.
  memory_error_detected = false;
  last_block_header_byte = mem[-1];
  mem[-1] = 'a';
  ::strcpy(mem.get(), prefix_value);
  ::strcpy(buffer, prefix_value);
  EXPECT_EQ(mem.get() - 1,
      strncatFunction(mem.get() - 1, suffix.get(), ::strlen(suffix_value)));
  EXPECT_TRUE(memory_error_detected);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferUnderFlow));
  EXPECT_STRCASEEQ(
      ::strncat(buffer, suffix.get(), ::strlen(suffix_value)), mem.get());
  mem[-1] = last_block_header_byte;
  ResetLog();

  // Test an overflow on the suffix.
  size_t suffix_len = ::strlen(suffix.get());
  suffix[suffix_len] = 'a';
  suffix[suffix_len + 1] = 0;
  memory_error_detected = false;
  ::strcpy(mem.get(), prefix_value);
  ::strcpy(buffer, prefix_value);
  EXPECT_EQ(mem.get(),
      strncatFunction(mem.get(), suffix.get(), ::strlen(suffix.get()) + 1));
  EXPECT_TRUE(memory_error_detected);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferOverFlow));
  EXPECT_STRCASEEQ(
      ::strncat(buffer, suffix.get(), ::strlen(suffix.get())), mem.get());
  ResetLog();
  suffix[suffix_len] = 0;

  // Test an overflow on the destination.
  memory_error_detected = false;
  ::strcpy(mem.get(), prefix_value);
  ::strcpy(buffer, prefix_value);
  size_t prefix_len = ::strlen(prefix_value);
  mem[prefix_len] = 'a';
  mem[prefix_len + 1] = 0;
  buffer[prefix_len] = 'a';
  buffer[prefix_len + 1] = 0;
  EXPECT_EQ(mem.get(),
      strncatFunction(mem.get(), suffix.get(), ::strlen(suffix.get())));
  EXPECT_TRUE(memory_error_detected);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferOverFlow));
  EXPECT_STRCASEEQ(
      ::strncat(buffer, suffix.get(), ::strlen(suffix.get())), mem.get());
  ResetLog();
}

}  // namespace asan
}  // namespace agent
