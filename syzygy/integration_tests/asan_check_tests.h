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

// We need to turn off the compiler optimizations if we want these tests to be
// run as expected.
#pragma optimize( "", off )

namespace {

// NOTE: This is used to fool compiler aliasing analysis. Do not make it static
//    nor const.
int kOffsetMinusOne = -1;
int kOffsetZero = 0;
int kOffsetOne = 1;

enum InvalidAccessType {
  INVALID_READ,
  INVALID_WRITE,
};

template<typename type>
type InvalidReadFromLocation(type* location) {
  type value = (*location);
  // The access should trigger an exception and we should never hit the return
  // statement.
  ::RaiseException(EXCEPTION_NONCONTINUABLE_EXCEPTION, 0, 0, NULL);
  return static_cast<type>(0);
}

template<typename type>
void InvalidWriteToLocation(type* location, type value) {
  (*location) = value;
  // The access should trigger an exception and we should never hit this line.
  ::RaiseException(EXCEPTION_NONCONTINUABLE_EXCEPTION, 0, 0, NULL);
}

// Try to do an invalid access to a given location. This is encapsulated into a
// try-catch statement so we can catch the exception triggered by the ASan error
// handler.
template<typename type>
bool TryInvalidAccessToLocation(InvalidAccessType access_type, type* location) {
  __try {
    switch (access_type) {
      case INVALID_READ:
        InvalidReadFromLocation(location);
        break;
      case INVALID_WRITE:
        InvalidWriteToLocation(location, static_cast<type>(42));
        break;
      default:
        break;
    }
    // This should never happen.
    ::RaiseException(EXCEPTION_NONCONTINUABLE_EXCEPTION, 0, 0, NULL);
  } __except (GetExceptionCode() == EXCEPTION_ARRAY_BOUNDS_EXCEEDED ?
      EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
    return true;
  }
  return false;
}

}  // namespace

template<typename type>
static type AsanWriteBufferOverflow() {
  // Produce an ASAN error by writing one after the buffer.
  type* ptr = new type[1];
  ptr[kOffsetZero] = static_cast<type>(1);
  TryInvalidAccessToLocation<type>(INVALID_WRITE, &ptr[kOffsetOne]);
  type result = ptr[kOffsetZero];
  delete[] ptr;
  return result;
}

template<typename type>
static type AsanWriteBufferUnderflow() {
  // Produce an ASAN error by writing one before the buffer.
  type* ptr = new type[1];
  TryInvalidAccessToLocation<type>(INVALID_WRITE, &ptr[kOffsetMinusOne]);
  ptr[kOffsetZero] = static_cast<type>(2);
  type result = ptr[kOffsetZero];
  delete[] ptr;
  return result;
}

template<typename type>
static type AsanReadBufferOverflow() {
  // Produce an ASAN error by reading one after the buffer.
  type* ptr = new type[1];
  *ptr = static_cast<type>(42);
  TryInvalidAccessToLocation<type>(INVALID_READ, &ptr[kOffsetOne]);
  type result = ptr[kOffsetZero];
  delete[] ptr;
  return result;
}

template<typename type>
static type AsanReadBufferUnderflow() {
  // Produce an ASAN error by reading one before the buffer.
  type* ptr = new type[1];
  *ptr = static_cast<type>(42);
  TryInvalidAccessToLocation<type>(INVALID_READ, &ptr[kOffsetMinusOne]);
  type result = ptr[kOffsetZero];
  delete[] ptr;
  return result;
}

template<typename type>
static type AsanReadUseAfterFree() {
  // Produce an ASAN error by reading memory after deleting it.
  type* ptr = new type[1];
  *ptr = static_cast<type>(42);
  type result = ptr[kOffsetZero];
  delete[] ptr;
  TryInvalidAccessToLocation<type>(INVALID_READ, &ptr[kOffsetZero]);
  return result;
}

template<typename type>
static type AsanWriteUseAfterFree() {
  // Produce an ASAN error by writing memory after deleting it.
  type* ptr = new type[1];
  *ptr = static_cast<type>(42);
  type result = *ptr;
  delete[] ptr;
  TryInvalidAccessToLocation<type>(INVALID_WRITE, &ptr[kOffsetZero]);
  return result;
}

}  // namespace testing

#endif  // SYZYGY_INTEGRATION_TESTS_ASAN_CHECK_TESTS_H_
