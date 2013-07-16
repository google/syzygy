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
// Asan check functions.
#ifndef SYZYGY_INTEGRATION_TESTS_ASAN_CHECK_TESTS_H_
#define SYZYGY_INTEGRATION_TESTS_ASAN_CHECK_TESTS_H_

namespace testing {

namespace {

// NOTE: This is used to fool compiler aliasing analysis. Do not make it static
//    nor const.
int kOffsetMinusOne = -1;
int kOffetZero = 0;
int kOffetOne = 1;

}  // namespace

template<typename type>
static type AsanWriteBufferOverflow() {
  // Produce an ASAN error by writing one after the buffer.
  type* ptr = new type[1];
  ptr[kOffetZero] = static_cast<type>(1);
  ptr[kOffetOne] = static_cast<type>(2);
  type result = ptr[kOffetZero];
  delete[] ptr;
  return result;
}

template<typename type>
static type AsanWriteBufferUnderflow() {
  // Produce an ASAN error by writing one before the buffer.
  type* ptr = new type[1];
  ptr[kOffsetMinusOne] = static_cast<type>(1);
  ptr[kOffetZero] = static_cast<type>(2);
  type result = ptr[kOffetZero];
  delete[] ptr;
  return result;
}

template<typename type>
static type AsanReadBufferOverflow() {
  // Produce an ASAN error by reading one after the buffer.
  type* ptr = new type[1];
  *ptr = static_cast<type>(42);
  type result = ptr[kOffetZero] + ptr[kOffetOne];
  delete[] ptr;
  return result;
}

template<typename type>
static type AsanReadBufferUnderflow() {
  // Produce an ASAN error by reading one before the buffer.
  type* ptr = new type[1];
  *ptr = static_cast<type>(42);
  type result = ptr[kOffetZero] + ptr[kOffsetMinusOne];
  delete[] ptr;
  return result;
}

template<typename type>
static type AsanReadUseAfterFree() {
  // Produce an ASAN error by reading memory after deleting it.
  type* ptr = new type[1];
  *ptr = static_cast<type>(42);
  delete[] ptr;
  type result = ptr[kOffetZero];
  return result;
}

template<typename type>
static type AsanWriteUseAfterFree() {
  // Produce an ASAN error by writing memory after deleting it.
  type* ptr = new type[1];
  *ptr = static_cast<type>(42);
  type result = *ptr;
  delete[] ptr;
  ptr[kOffetZero] = static_cast<type>(12);
  return result;
}

}  // namespace testing

#endif  // SYZYGY_INTEGRATION_TESTS_ASAN_CHECK_TESTS_H_
