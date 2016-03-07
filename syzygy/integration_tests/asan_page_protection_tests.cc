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
#include <windows.h>

#include "syzygy/integration_tests/asan_interceptors_tests.h"

namespace testing {

namespace {

const size_t kLargeAllocationSize = 1 * 1024 * 1024;  // 1 MB.
const size_t kPageHeapAllocationSize = 256;

}  // namespace

size_t AsanReadLargeAllocationTrailerBeforeFree() {
  char* alloc = reinterpret_cast<char*>(::calloc(kLargeAllocationSize, 1));

  // Read from the trailer while the allocation is still valid. This should be
  // caught immediately.
  int* trailer = reinterpret_cast<int*>(alloc + kLargeAllocationSize);
  int value = NonInterceptedRead<int>(trailer);

  // Delete the allocation.
  delete[] alloc;

  return 0;
}

size_t AsanReadLargeAllocationBodyAfterFree() {
  char* alloc = reinterpret_cast<char*>(::calloc(kLargeAllocationSize, 1));

  // Delete the allocation.
  delete[] alloc;

  // Read from the body while the allocation is in the quarantine. This should
  // be caught immediately. We need to read at least a page into the block to
  // ensure that its at an address where page protections are guaranteed to be
  // active.
  char value = NonInterceptedRead<char>(alloc + 4096);

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

size_t AsanCorruptBlockWithPageProtections() {
  // Do a large allocation and make sure that it gets corrupt (by an
  // uninstrumented use after free), then generate an error on another memory
  // allocation to make sure that the error handling code doesn't crash because
  // of the page protection set on the large block.
  char* large_alloc =
      reinterpret_cast<char*>(::calloc(kPageHeapAllocationSize, 1));
  char* small_alloc =
      reinterpret_cast<char*>(::calloc(10, 1));

  // Free the large allocation.
  ::free(large_alloc);

  // Corrupt the large allocation.
  DWORD old_protection = 0;
  ::VirtualProtect(large_alloc, 0, PAGE_READWRITE, &old_protection);
  NonInterceptedWrite<char>(large_alloc + 10, 'c');
  ::VirtualProtect(large_alloc, 0, old_protection, &old_protection);

  // Do an invalid access on the small allocation.
  ::free(small_alloc);
  TryInvalidAccessToLocation(INVALID_READ, &small_alloc[0]);

  return 0;
}

}  // namespace testing
