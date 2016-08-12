// Copyright 2015 Google Inc. All Rights Reserved.
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

#include "syzygy/testing/laa.h"

#include <windows.h>
#include "base/logging.h"
#include "gtest/gtest.h"
#include "syzygy/common/align.h"

namespace testing {

size_t GetAddressSpaceSize() {
  MEMORYSTATUSEX mem_status = {};
  mem_status.dwLength = sizeof(mem_status);
  CHECK(::GlobalMemoryStatusEx(&mem_status));

  // Because of the way the interceptors work we only support 2GB or 4GB
  // virtual memory sizes, even if the actual is 3GB (32-bit windows, LAA,
  // and 4GT kernel option enabled).
  static const uint64_t k1GB = 1UL << 30;
  uint64_t mem_size = ::common::AlignUp64(mem_status.ullTotalVirtual, 2 * k1GB);
  mem_size /= k1GB;
  return static_cast<size_t>(mem_size);
}

bool ShouldSkipTest(size_t required_address_space_size) {
  if (GetAddressSpaceSize() == required_address_space_size)
    return false;
  const ::testing::TestInfo* const test_info =
      ::testing::UnitTest::GetInstance()->current_test_info();
  fprintf(stderr, "WARNING: %s.%s requires %zu GB memory model, skipping.\n",
          test_info->test_case_name(), test_info->name(),
          required_address_space_size);
  return true;
}

}  // namespace testing
