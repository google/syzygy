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
#pragma function(memset)

template<typename type>
static type AsanMemsetOverflow() {
  const size_t kArraySize = 10;
  type* ptr = new type[kArraySize];
  memset(ptr, 0xFF, kArraySize * sizeof(type) + 1);
  type result = ptr[0];
  delete[] ptr;
  return result;
}

template<typename type>
static type AsanMemsetUnderflow() {
  const size_t kArraySize = 10;
  type* ptr = new type[kArraySize];
  memset(reinterpret_cast<uint8*>(ptr) - 1, 0xFF, kArraySize * sizeof(type));
  type result = ptr[0];
  delete[] ptr;
  return result;
}

template<typename type>
static type AsanMemchrOverflow() {
  const size_t kArraySize = 10;
  type* ptr = new type[kArraySize];
  memset(ptr, 0xAA, kArraySize * sizeof(type));
  type result = reinterpret_cast<type>(
      memchr(ptr, 0xFF, kArraySize * sizeof(type) + 1));
  delete[] ptr;
  return result;
}

template<typename type>
static type AsanMemchrUnderflow() {
  const size_t kArraySize = 10;
  type* ptr = new type[kArraySize];
  memset(ptr, 0xAA, kArraySize * sizeof(type));
  type result = reinterpret_cast<type>(
      memchr(reinterpret_cast<uint8*>(ptr) - 1, 0xFF,
             kArraySize * sizeof(type)));
  delete[] ptr;
  return result;
}

}  // namespace testing

#endif  // SYZYGY_INTEGRATION_TESTS_ASAN_INTERCEPTORS_TESTS_H_
