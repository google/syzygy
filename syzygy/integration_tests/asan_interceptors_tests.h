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
  ::memset(ptr, 0xFF, kArraySize * sizeof(type) + 1);
  type result = ptr[0];
  NonInterceptedWrite(ptr + kArraySize, first_trailer_val);
  delete[] ptr;
  return result;
}

template<typename type>
static type AsanMemsetUnderflow() {
  const size_t kArraySize = 10;
  type* ptr = new type[kArraySize];
  type last_header_val = NonInterceptedRead(ptr - 1);
  ::memset(reinterpret_cast<uint8*>(ptr) - 1, 0xFF, kArraySize * sizeof(type));
  type result = ptr[0];
  NonInterceptedWrite(ptr - 1, last_header_val);
  delete[] ptr;
  return result;
}

template<typename type>
static type AsanMemsetUseAfterFree() {
  const size_t kArraySize = 10;
  type* ptr = new type[kArraySize];
  type result = ptr[0];
  delete[] ptr;
  ::memset(reinterpret_cast<uint8*>(ptr), 0xFF, kArraySize * sizeof(type));
  return result;
}

template<typename type>
static type AsanMemchrOverflow() {
  const size_t kArraySize = 10;
  type* ptr = new type[kArraySize];
  ::memset(ptr, 0xAA, kArraySize * sizeof(type));
  ::memchr(ptr, 0xFF, kArraySize * sizeof(type) + 1);
  type result = ptr[0];
  delete[] ptr;
  return result;
}

template<typename type>
static type AsanMemchrUnderflow() {
  const size_t kArraySize = 10;
  type* ptr = new type[kArraySize];
  ::memset(ptr, 0xAA, kArraySize * sizeof(type));
  ::memchr(reinterpret_cast<uint8*>(ptr) - 1, 0xFF, kArraySize * sizeof(type));
  type result = ptr[0];
  delete[] ptr;
  return result;
}

template<typename type>
static type AsanMemchrUseAfterFree() {
  const size_t kArraySize = 10;
  type* ptr = new type[kArraySize];
  ::memset(ptr, 0xAA, kArraySize * sizeof(type));
  type result = ptr[0];
  delete[] ptr;
  ::memchr(ptr, 0xFF, kArraySize * sizeof(type));
  return result;
}

template<typename type>
static type AsanMemmoveWriteOverflow() {
  const size_t kArraySize = 10;
  type* ptr = new type[kArraySize];
  type first_trailer_val = NonInterceptedRead(ptr + kArraySize);
  ::memset(ptr, 0xAA, kArraySize * sizeof(type));
  ::memmove(reinterpret_cast<uint8*>(ptr) + 1, ptr, kArraySize * sizeof(type));
  type result = ptr[0];
  NonInterceptedWrite(ptr + kArraySize, first_trailer_val);
  delete[] ptr;
  return result;
}

template<typename type>
static type AsanMemmoveWriteUnderflow() {
  const size_t kArraySize = 10;
  type* ptr = new type[kArraySize];
  type last_header_val = NonInterceptedRead(ptr - 1);
  ::memset(ptr, 0xAA, kArraySize * sizeof(type));
  ::memmove(reinterpret_cast<uint8*>(ptr) - 1, ptr, kArraySize * sizeof(type));
  type result = ptr[0];
  NonInterceptedWrite(ptr - 1, last_header_val);
  delete[] ptr;
  return result;
}

template<typename type>
static type AsanMemmoveReadOverflow() {
  const size_t kArraySize = 10;
  type* ptr = new type[kArraySize];
  ::memset(ptr, 0xAA, kArraySize * sizeof(type));
  ::memmove(ptr, reinterpret_cast<uint8*>(ptr) + 1, kArraySize * sizeof(type));
  type result = ptr[0];
  delete[] ptr;
  return result;
}

template<typename type>
static type AsanMemmoveReadUnderflow() {
  const size_t kArraySize = 10;
  type* ptr = new type[kArraySize];
  ::memset(ptr, 0xAA, kArraySize * sizeof(type));
  ::memmove(ptr, reinterpret_cast<uint8*>(ptr) - 1, kArraySize * sizeof(type));
  type result = ptr[0];
  delete[] ptr;
  return result;
}

template<typename type>
static type AsanMemmoveUseAfterFree() {
  const size_t kArraySize = 10;
  type* ptr = new type[kArraySize];
  ::memset(ptr, 0xAA, kArraySize * sizeof(type));
  type result = ptr[0];
  delete[] ptr;
  ::memmove(ptr, ptr, kArraySize * sizeof(type));
  return result;
}

template<typename type>
static type AsanMemcpyWriteOverflow() {
  const size_t kArraySize = 10;
  type* src = new type[kArraySize];
  type* dst = new type[kArraySize];
  type first_trailer_val = NonInterceptedRead(dst + kArraySize);
  ::memset(src, 0xAA, kArraySize * sizeof(type));
  ::memcpy(reinterpret_cast<uint8*>(dst) + 1, src, kArraySize * sizeof(type));
  type result = src[0];
  NonInterceptedWrite(dst + kArraySize, first_trailer_val);
  delete[] src;
  delete[] dst;
  return result;
}

template<typename type>
static type AsanMemcpyWriteUnderflow() {
  const size_t kArraySize = 10;
  type* src = new type[kArraySize];
  type* dst = new type[kArraySize];
  type last_header_val = NonInterceptedRead(dst - 1);
  ::memset(src, 0xAA, kArraySize * sizeof(type));
  ::memcpy(reinterpret_cast<uint8*>(dst) - 1, src, kArraySize * sizeof(type));
  type result = src[0];
  NonInterceptedWrite(dst - 1, last_header_val);
  delete[] src;
  delete[] dst;
  return result;
}

template<typename type>
static type AsanMemcpyReadOverflow() {
  const size_t kArraySize = 10;
  type* src = new type[kArraySize];
  type* dst = new type[kArraySize];
  ::memset(src, 0xAA, kArraySize * sizeof(type));
  ::memcpy(dst, reinterpret_cast<uint8*>(src) + 1, kArraySize * sizeof(type));
  type result = src[0];
  delete[] src;
  delete[] dst;
  return result;
}

template<typename type>
static type AsanMemcpyReadUnderflow() {
  const size_t kArraySize = 10;
  type* src = new type[kArraySize];
  type* dst = new type[kArraySize];
  ::memset(src, 0xAA, kArraySize * sizeof(type));
  ::memcpy(dst, reinterpret_cast<uint8*>(src) - 1, kArraySize * sizeof(type));
  type result = src[0];
  delete[] src;
  delete[] dst;
  return result;
}

template<typename type>
static type AsanMemcpyUseAfterFree() {
  const size_t kArraySize = 10;
  type* src = new type[kArraySize];
  type* dst = new type[kArraySize];
  ::memset(src, 0xAA, kArraySize * sizeof(type));
  type result = src[0];
  delete[] src;
  ::memcpy(dst, src, kArraySize * sizeof(type));
  delete[] dst;
  return result;
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

}  // namespace testing

#endif  // SYZYGY_INTEGRATION_TESTS_ASAN_INTERCEPTORS_TESTS_H_
