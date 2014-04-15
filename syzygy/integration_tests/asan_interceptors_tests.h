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
// This file declares some functions used to do the integration tests of the
// Asan interceptor functions.
#ifndef SYZYGY_INTEGRATION_TESTS_ASAN_INTERCEPTORS_TESTS_H_
#define SYZYGY_INTEGRATION_TESTS_ASAN_INTERCEPTORS_TESTS_H_

#include <windows.h>  // NOLINT

#include "syzygy/integration_tests/asan_check_tests.h"

namespace testing {

// Disable the intrinsic version of the intercepted function.
#pragma function(memset, memcpy, strlen, strcmp)

// Helper function to make sure that a memory read access didn't get
// instrumented.
// @tparam type The type of the value to be read.
// @param location The location where to read from.
// @returns the value at |location|
template<typename type>
type NonInterceptedRead(type* location) {
  // The try-except statement prevents the function from being instrumented.
  __try {
    return *location;
  } __except(EXCEPTION_CONTINUE_SEARCH) {
    // Nothing to do here.
  }
  return static_cast<type>(0);
}

// Helper function to do non instrumented reads from an array.
// @tparam type The type of the values to be read.
// @param src The array where to read from.
// @param size The size of the array.
// @param dst The destination array.
template<typename type>
void NonInterceptedReads(type* src, size_t size, type* dst) {
  for (size_t i = 0; i < size; ++i)
    *dst++ = NonInterceptedRead(src + i);
}

// Helper function to make sure that a memory write access didn't get
// instrumented.
// @tparam type The type of the value to be written.
// @param location The location where to write to.
// @param val The value to write.
template<typename type>
void NonInterceptedWrite(type* location, type val) {
  // The try-except statement prevents the function from being instrumented.
  __try {
    *location = val;
  } __except(EXCEPTION_CONTINUE_SEARCH) {
    // Nothing to do here.
  }
}

// Helper function to do non instrumented writes from an array.
// @tparam type The type of the values to be written.
// @param src The array where to read from.
// @param size The size of the array.
// @param dst The address where to write to.
template<typename type>
void NonInterceptedWrites(type* src, size_t size, type* dst) {
  for (size_t i = 0; i < size; ++i)
    NonInterceptedWrite(dst++, src[i]);
}

template<typename type>
static type AsanMemsetOverflow() {
  const size_t kArraySize = 10;
  type* ptr = new type[kArraySize];
  type first_trailer_val = NonInterceptedRead(ptr + kArraySize);
  TryInvalidCall3(&::memset, static_cast<void*>(ptr), 0xFF,
      kArraySize * sizeof(type) + 1);
  NonInterceptedWrite(ptr + kArraySize, first_trailer_val);
  delete[] ptr;
  return 0;
}

template<typename type>
static type AsanMemsetUnderflow() {
  const size_t kArraySize = 10;
  type* ptr = new type[kArraySize];
  type last_header_val = NonInterceptedRead(ptr - 1);
  uint8* underflow_address = reinterpret_cast<uint8*>(ptr) - 1;
  TryInvalidCall3(&::memset, static_cast<void*>(underflow_address), 0xFF,
      kArraySize * sizeof(type));
  NonInterceptedWrite(ptr - 1, last_header_val);
  delete[] ptr;
  return 0;
}

template<typename type>
static type AsanMemsetUseAfterFree() {
  const size_t kArraySize = 10;
  type* ptr = new type[kArraySize];
  delete[] ptr;
  TryInvalidCall3(&::memset, static_cast<void*>(ptr), 0xFF,
      kArraySize * sizeof(type));
  return 0;
}

template<typename type>
static type AsanMemchrOverflow() {
  const size_t kArraySize = 10;
  type* ptr = new type[kArraySize];
  ::memset(ptr, 0xAA, kArraySize * sizeof(type));
  TryInvalidCall3(static_cast<void* (*)(void*, int, size_t)>(&::memchr),
                  static_cast<void*>(ptr),
                  0xFF,
                  kArraySize * sizeof(type) + 1);
  delete[] ptr;
  return 0;
}

template<typename type>
static type AsanMemchrUnderflow() {
  const size_t kArraySize = 10;
  type* ptr = new type[kArraySize];
  ::memset(ptr, 0xAA, kArraySize * sizeof(type));
  uint8* underflow_address = reinterpret_cast<uint8*>(ptr) - 1;
  TryInvalidCall3(static_cast<void* (*)(void*, int, size_t)>(&::memchr),
                  static_cast<void*>(underflow_address),
                  0xFF,
                  kArraySize * sizeof(type));
  delete[] ptr;
  return 0;
}

template<typename type>
static type AsanMemchrUseAfterFree() {
  const size_t kArraySize = 10;
  type* ptr = new type[kArraySize];
  ::memset(ptr, 0xAA, kArraySize * sizeof(type));
  delete[] ptr;
  TryInvalidCall3(static_cast<void* (*)(void*, int, size_t)>(&::memchr),
                  static_cast<void*>(ptr), 0xFF,
                  kArraySize * sizeof(type));
  return 0;
}

template<typename type>
static type AsanMemmoveWriteOverflow() {
  const size_t kArraySize = 10;
  type* ptr = new type[kArraySize];
  type first_trailer_val = NonInterceptedRead(ptr + kArraySize);
  ::memset(ptr, 0xAA, kArraySize * sizeof(type));
  uint8* dst = reinterpret_cast<uint8*>(ptr) + 1;
  TryInvalidCall3(&::memmove,
                  static_cast<void*>(dst),
                  static_cast<const void*>(ptr),
                  kArraySize * sizeof(type));
  NonInterceptedWrite(ptr + kArraySize, first_trailer_val);
  delete[] ptr;
  return 0;
}

template<typename type>
static type AsanMemmoveWriteUnderflow() {
  const size_t kArraySize = 10;
  type* ptr = new type[kArraySize];
  type last_header_val = NonInterceptedRead(ptr - 1);
  ::memset(ptr, 0xAA, kArraySize * sizeof(type));
  uint8* underflow_address = reinterpret_cast<uint8*>(ptr) - 1;
  TryInvalidCall3(&::memmove,
                  static_cast<void*>(underflow_address),
                  static_cast<const void*>(ptr),
                  kArraySize * sizeof(type));
  NonInterceptedWrite(ptr - 1, last_header_val);
  delete[] ptr;
  return 0;
}

template<typename type>
static type AsanMemmoveReadOverflow() {
  const size_t kArraySize = 10;
  type* ptr = new type[kArraySize];
  ::memset(ptr, 0xAA, kArraySize * sizeof(type));
  uint8* src = reinterpret_cast<uint8*>(ptr) + 1;
  TryInvalidCall3(&::memmove,
                  static_cast<void*>(ptr),
                  static_cast<const void*>(src),
                  kArraySize * sizeof(type));
  delete[] ptr;
  return 0;
}

template<typename type>
static type AsanMemmoveReadUnderflow() {
  const size_t kArraySize = 10;
  type* ptr = new type[kArraySize];
  ::memset(ptr, 0xAA, kArraySize * sizeof(type));
  uint8* underflow_address = reinterpret_cast<uint8*>(ptr) - 1;
  TryInvalidCall3(&memmove,
                  static_cast<void*>(ptr),
                  static_cast<const void*>(underflow_address),
                  kArraySize * sizeof(type));
  delete[] ptr;
  return 0;
}

template<typename type>
static type AsanMemmoveUseAfterFree() {
  const size_t kArraySize = 10;
  type* ptr = new type[kArraySize];
  ::memset(ptr, 0xAA, kArraySize * sizeof(type));
  delete[] ptr;
  TryInvalidCall3(&::memmove,
                  static_cast<void*>(ptr),
                  static_cast<const void*>(ptr),
                  kArraySize * sizeof(type));
  return 0;
}

template<typename type>
static type AsanMemcpyWriteOverflow() {
  const size_t kArraySize = 10;
  type* src = new type[kArraySize];
  type* dst = new type[kArraySize];
  type first_trailer_val = NonInterceptedRead(dst + kArraySize);
  ::memset(src, 0xAA, kArraySize * sizeof(type));
  uint8* overflow_dst = reinterpret_cast<uint8*>(dst) + 1;
  TryInvalidCall3(&::memcpy,
                  static_cast<void*>(overflow_dst),
                  static_cast<const void*>(src),
                  kArraySize * sizeof(type));
  NonInterceptedWrite(dst + kArraySize, first_trailer_val);
  delete[] src;
  delete[] dst;
  return 0;
}

template<typename type>
static type AsanMemcpyWriteUnderflow() {
  const size_t kArraySize = 10;
  type* src = new type[kArraySize];
  type* dst = new type[kArraySize];
  type last_header_val = NonInterceptedRead(dst - 1);
  ::memset(src, 0xAA, kArraySize * sizeof(type));
  uint8* underflow_dst = reinterpret_cast<uint8*>(dst) - 1;
  TryInvalidCall3(&::memcpy,
                  static_cast<void*>(underflow_dst),
                  static_cast<const void*>(src),
                  kArraySize * sizeof(type));
  NonInterceptedWrite(dst - 1, last_header_val);
  delete[] src;
  delete[] dst;
  return 0;
}

template<typename type>
static type AsanMemcpyReadOverflow() {
  const size_t kArraySize = 10;
  type* src = new type[kArraySize];
  type* dst = new type[kArraySize];
  ::memset(src, 0xAA, kArraySize * sizeof(type));
  uint8* overflow_src = reinterpret_cast<uint8*>(src) + 1;
  TryInvalidCall3(&::memcpy,
                  static_cast<void*>(dst),
                  static_cast<const void*>(overflow_src),
                  kArraySize * sizeof(type));
  delete[] src;
  delete[] dst;
  return 0;
}

template<typename type>
static type AsanMemcpyReadUnderflow() {
  const size_t kArraySize = 10;
  type* src = new type[kArraySize];
  type* dst = new type[kArraySize];
  ::memset(src, 0xAA, kArraySize * sizeof(type));
  uint8* underflow_src = reinterpret_cast<uint8*>(src) - 1;
  TryInvalidCall3(&::memcpy,
                  static_cast<void*>(dst),
                  static_cast<const void*>(underflow_src),
                  kArraySize * sizeof(type));
  delete[] src;
  delete[] dst;
  return 0;
}

template<typename type>
static type AsanMemcpyUseAfterFree() {
  const size_t kArraySize = 10;
  type* src = new type[kArraySize];
  type* dst = new type[kArraySize];
  ::memset(src, 0xAA, kArraySize * sizeof(type));
  delete[] src;
  TryInvalidCall3(&::memcpy,
                  static_cast<void*>(dst),
                  static_cast<const void*>(src),
                  kArraySize * sizeof(type));
  delete[] dst;
  return 0;
}

size_t AsanStrcspnKeysOverflow();

size_t AsanStrcspnKeysUnderflow();

size_t AsanStrcspnKeysUseAfterFree();

size_t AsanStrcspnSrcOverflow();

size_t AsanStrcspnSrcUnderflow();

size_t AsanStrcspnSrcUseAfterFree();

size_t AsanStrlenOverflow();

size_t AsanStrlenUnderflow();

size_t AsanStrlenUseAfterFree();

size_t AsanStrrchrOverflow();

size_t AsanStrrchrUnderflow();

size_t AsanStrrchrUseAfterFree();

size_t AsanWcsrchrOverflow();

size_t AsanWcsrchrUnderflow();

size_t AsanWcsrchrUseAfterFree();

size_t AsanStrcmpSrc1Overflow();

size_t AsanStrcmpSrc1Underflow();

size_t AsanStrcmpSrc1UseAfterFree();

size_t AsanStrcmpSrc2Overflow();

size_t AsanStrcmpSrc2Underflow();

size_t AsanStrcmpSrc2UseAfterFree();

size_t AsanStrpbrkKeysOverflow();

size_t AsanStrpbrkKeysUnderflow();

size_t AsanStrpbrkKeysUseAfterFree();

size_t AsanStrpbrkSrcOverflow();

size_t AsanStrpbrkSrcUnderflow();

size_t AsanStrpbrkSrcUseAfterFree();

size_t AsanStrstrSrc1Overflow();

size_t AsanStrstrSrc1Underflow();

size_t AsanStrstrSrc1UseAfterFree();

size_t AsanStrstrSrc2Overflow();

size_t AsanStrstrSrc2Underflow();

size_t AsanStrstrSrc2UseAfterFree();

size_t AsanStrspnKeysOverflow();

size_t AsanStrspnKeysUnderflow();

size_t AsanStrspnKeysUseAfterFree();

size_t AsanStrspnSrcOverflow();

size_t AsanStrspnSrcUnderflow();

size_t AsanStrspnSrcUseAfterFree();

size_t AsanStrncpySrcOverflow();

size_t AsanStrncpySrcUnderflow();

size_t AsanStrncpySrcUseAfterFree();

size_t AsanStrncpyDstOverflow();

size_t AsanStrncpyDstUnderflow();

size_t AsanStrncpyDstUseAfterFree();

size_t AsanStrncatSuffixOverflow();

size_t AsanStrncatSuffixUnderflow();

size_t AsanStrncatSuffixUseAfterFree();

size_t AsanStrncatDstOverflow();

size_t AsanStrncatDstUnderflow();

size_t AsanStrncatDstUseAfterFree();

size_t AsanReadFileOverflow();

size_t AsanReadFileUseAfterFree();

size_t AsanWriteFileOverflow();

size_t AsanWriteFileUseAfterFree();

size_t AsanCorruptedBlock();

size_t AsanCorruptedBlockInQuarantine();

}  // namespace testing

#endif  // SYZYGY_INTEGRATION_TESTS_ASAN_INTERCEPTORS_TESTS_H_
