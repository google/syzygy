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

#include "syzygy/integration_tests/asan_page_protection_tests.h"

#include <stdlib.h>
#include "base/basictypes.h"
#include "syzygy/integration_tests/asan_interceptors_tests.h"

namespace testing {

namespace {

const size_t kLargeAllocationSize = 1 * 1024 * 1024;  // 1 MB.
const size_t kPageHeapAllocationSize = 256;

}  // namespace

size_t AsanReadLargeAllocationTrailerBeforeFree() {
  char* alloc = new char [kLargeAllocationSize];
  ::memset(alloc, 0, kLargeAllocationSize);

  // Read from the trailer while the allocation is still valid. This should be
  // caught immediately.
  int* trailer = reinterpret_cast<int*>(alloc + kLargeAllocationSize);
  int value = NonInterceptedRead<int>(trailer);

  // Delete the allocation.
  delete[] alloc;

  return 0;
}

size_t AsanReadLargeAllocationBodyAfterFree() {
  char* alloc = new char [kLargeAllocationSize];
  ::memset(alloc, 0, kLargeAllocationSize);

  // Delete the allocation.
  delete[] alloc;

  // Read from the body while the allocation is in the quarantine. This should
  // be caught immediately.
  char value = NonInterceptedRead<char>(alloc + 10);

  return 0;
}

size_t AsanReadPageAllocationTrailerBeforeFree() {
  char* alloc = reinterpret_cast<char*>(::calloc(kPageHeapAllocationSize, 1));

  // Read from the trailer while the allocation is still valid. This should be
  // caught immediately.
  int* trailer = reinterpret_cast<int*>(alloc + kPageHeapAllocationSize);
  int value = NonInterceptedRead<int>(trailer);

  // Free the allocation.
  ::free(alloc);

  return 0;
}

size_t AsanWritePageAllocationBodyAfterFree() {
  char* alloc = reinterpret_cast<char*>(::calloc(kPageHeapAllocationSize, 1));

  // Free the allocation.
  ::free(alloc);

  // Write to the body while the allocation is in the quarantine. This should
  // be caught immediately.
  NonInterceptedWrite<char>(alloc + 10, 'c');

  return 0;
}

}  // namespace testing
