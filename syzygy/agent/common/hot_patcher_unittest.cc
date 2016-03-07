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

#include "syzygy/agent/common/hot_patcher.h"

#include <stdint.h>
#include <windows.h>

#include "gtest/gtest.h"

namespace agent {
namespace common {

namespace {

// A function pointer type that with a simple calling convention: it takes no
// parameters and returns the result in EAX.
typedef int (__stdcall *TestFunctionPtr)();

// Padding bytes and a simple function that can be called via a TestFunctionPtr
// function pointer and always returns 1. If we copy this function to a 2-byte
// aligned location, this function fulfills all requirements of HotPacher.
const uint8_t kTestFunction[] = {
    // Padding bytes. We use six padding bytes so the function will be 2-aligned
    // when we write it to the beginning of a page or at an even offset.
    // |kNumberOfPaddingBytesInTestFunction| must contain the number of padding
    // 0xCC bytes.
    0xCC,
    0xCC,
    0xCC,
    0xCC,
    0xCC,
    0xCC,
    // MOV EAX, 1
    0xB8,
    0x01,
    0x00,
    0x00,
    0x00,
    // RET
    0xC3,
};

// The number of padding 0xCCs in kTestFunction.
const size_t kNumberOfPaddingBytesInTestFunction = 6U;

// A simple function that can be called via a TestFunctionPtr function pointer.
// @returns 42. (It is deliberately different from the return value of the
//     function in kTestFunction)
int __stdcall NewFunction() {
  return 42;
}

class HotPatcherTest : public ::testing::Test {
 public:
  // We initialize the page size.
  HotPatcherTest() {
    SYSTEM_INFO system_info = {};
    ::GetSystemInfo(&system_info);
    page_size_ = system_info.dwPageSize;
  }

  // Runs the hot patcher tests.
  // @param virtual_memory_size The size of virtual memory that we allocate
  //     for the test using VirtualAlloc.
  // @param offset We lay out |kTestFunction| to this offset in the allocated
  //     virtual memory.
  void RunTest(size_t virtual_memory_size, size_t offset) {
    // Sanity check that we have enough memory to write the test function at
    // the given offset.
    ASSERT_GT(virtual_memory_size, offset + sizeof(kTestFunction));

    // Allocate virtual memory with write access.
    LPVOID virtual_memory = ::VirtualAlloc(nullptr,
                                           virtual_memory_size,
                                           MEM_COMMIT,
                                           PAGE_READWRITE);
    ASSERT_NE(nullptr, virtual_memory);

    // We use this location in the virtual memory.
    uint8_t* virtual_memory_cursor =
        static_cast<uint8_t*>(virtual_memory) + offset;

    // We check that the newly allocated virtual memory is 2-byte aligned.
    // (The underlying virtual page itself should have a much higher alignment.)
    ASSERT_EQ(0, reinterpret_cast<int32_t>(virtual_memory_cursor) % 2);

    // Copy the test function into the virtual memory.
    ::memcpy(virtual_memory_cursor, kTestFunction, sizeof(kTestFunction));

    // Remove write permission and add executable permission to the page.
    DWORD old_protection;
    ASSERT_TRUE(::VirtualProtect(virtual_memory,
                                 virtual_memory_size,
                                 PAGE_EXECUTE_READ,
                                 &old_protection));

  TestFunctionPtr test_function =
        reinterpret_cast<TestFunctionPtr>(virtual_memory_cursor +
                                          kNumberOfPaddingBytesInTestFunction);

    // Call test function.
    ASSERT_EQ(1, test_function());

    // Hot patch test function.
    HotPatcher hot_patcher;
    hot_patcher.Patch(test_function, &NewFunction);

    // Call the same function. It is now hot patched so it should return a
    // different value.
    ASSERT_EQ(42, test_function());

    // Check that the protection is kept.
    MEMORY_BASIC_INFORMATION meminfo;
    ASSERT_NE(0U,
              ::VirtualQuery(virtual_memory, &meminfo, virtual_memory_size));
    if (virtual_memory_size > page_size_) {
      // If we allocate more bytes we have to restore the protection for both.
      ASSERT_EQ(page_size_ * 2, meminfo.RegionSize);
    }
    ASSERT_EQ(PAGE_EXECUTE_READ, meminfo.Protect);
  }

  size_t page_size_;
};

}  // namespace

TEST_F(HotPatcherTest, Test) {
  ASSERT_NO_FATAL_FAILURE(RunTest(256U, 0U));
}

TEST_F(HotPatcherTest, TestPageBoundary) {
  // The hot patching will happen at a page boundary.
  ASSERT_NO_FATAL_FAILURE(RunTest(page_size_ * 2, page_size_ - 2));
  ASSERT_NO_FATAL_FAILURE(RunTest(page_size_ * 2, page_size_ - 4));
}

}  // namespace common
}  // namespace agent
