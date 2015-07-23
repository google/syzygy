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
//
// Declares a helper class for use in performing hot-patching operations.
// The class takes care of modifying page protections as the patcher works.

#include "syzygy/agent/asan/scoped_page_protections.h"

#include <cstdint>
#include "base/logging.h"
#include "gtest/gtest.h"
#include "syzygy/agent/asan/constants.h"

namespace agent {
namespace asan {

namespace {

class ScopedPageProtectionsTest : public testing::Test {
 public:
  static const size_t kPageCount = 3;

  ScopedPageProtectionsTest() : page_start_(nullptr), page_end_(nullptr) {}

  void SetUp() override {
    page_start_ = reinterpret_cast<uint8_t*>(::VirtualAlloc(
        nullptr, GetPageSize() * kPageCount, MEM_COMMIT, PAGE_READONLY));
    ASSERT_TRUE(page_start_);
    page_end_ = page_start_ + kPageCount * GetPageSize();
  }

  void TearDown() override {
    ASSERT_TRUE(::VirtualFree(page_start_, 0, MEM_DECOMMIT));
    page_start_ = nullptr;
    page_end_ = nullptr;
  }

  // Returns the base address of the page with a given index.
  uint8_t* BaseOfPage(size_t index) {
    CHECK_LE(index, kPageCount);
    return page_start_ + index * GetPageSize();
  }

  // Sets the given protection on the given page.
  void SetProtection(size_t index, DWORD protection) {
    CHECK_LT(index, kPageCount);
    DWORD old_protection_unused = 0;
    ::VirtualProtect(BaseOfPage(index), GetPageSize(), protection,
                     &old_protection_unused);
  }

  // Returns the protection associated with the given page.
  DWORD GetProtection(size_t index) {
    CHECK_LT(index, kPageCount);
    MEMORY_BASIC_INFORMATION mem_info = {};
    CHECK_EQ(sizeof(mem_info),
             ::VirtualQuery(BaseOfPage(index), &mem_info, sizeof(mem_info)));
    return mem_info.Protect;
  }

  // An allocation with multiple pages. This is initially allocated read-only.
  uint8_t* page_start_;
  uint8_t* page_end_;
};

}  // namespace

TEST_F(ScopedPageProtectionsTest, ReadOnlyBecomesReadWrite) {
  ScopedPageProtections spp;

  // The fixture should guarantee this.
  ASSERT_EQ(PAGE_READONLY, GetProtection(0));

  EXPECT_TRUE(spp.EnsureContainingPagesWritable(BaseOfPage(0), 1));
  EXPECT_EQ(PAGE_READWRITE, GetProtection(0));
  spp.RestorePageProtections();
  EXPECT_EQ(PAGE_READONLY, GetProtection(0));
}

TEST_F(ScopedPageProtectionsTest, ExecReadOnlyBecomesExecReadWrite) {
  ScopedPageProtections spp;

  // The fixture should guarantee these assertions.
  ASSERT_EQ(PAGE_READONLY, GetProtection(0));
  SetProtection(0, PAGE_EXECUTE_READ);
  ASSERT_EQ(PAGE_EXECUTE_READ, GetProtection(0));

  EXPECT_TRUE(spp.EnsureContainingPagesWritable(BaseOfPage(0), 1));
  EXPECT_EQ(PAGE_EXECUTE_READWRITE, GetProtection(0));
  spp.RestorePageProtections();
  EXPECT_EQ(PAGE_EXECUTE_READ, GetProtection(0));
}

TEST_F(ScopedPageProtectionsTest, SpanMultiplePages) {
  ScopedPageProtections spp;

  // The fixture should guarantee these assertions.
  ASSERT_EQ(PAGE_READONLY, GetProtection(0));
  ASSERT_EQ(PAGE_READONLY, GetProtection(1));
  ASSERT_EQ(PAGE_READONLY, GetProtection(2));
  SetProtection(1, PAGE_EXECUTE_READ);
  ASSERT_EQ(PAGE_READONLY, GetProtection(0));
  ASSERT_EQ(PAGE_EXECUTE_READ, GetProtection(1));
  ASSERT_EQ(PAGE_READONLY, GetProtection(2));

  uint8_t* begin = BaseOfPage(0) + 13;
  uint8_t* end = BaseOfPage(3) - 100;
  EXPECT_TRUE(spp.EnsureContainingPagesWritable(begin, end - begin));
  EXPECT_EQ(PAGE_READWRITE, GetProtection(0));
  EXPECT_EQ(PAGE_EXECUTE_READWRITE, GetProtection(1));
  EXPECT_EQ(PAGE_READWRITE, GetProtection(2));

  spp.RestorePageProtections();
  EXPECT_EQ(PAGE_READONLY, GetProtection(0));
  EXPECT_EQ(PAGE_EXECUTE_READ, GetProtection(1));
  EXPECT_EQ(PAGE_READONLY, GetProtection(2));
}

TEST_F(ScopedPageProtectionsTest, RestoresProtectionsInDestructor) {
  // The fixture should guarantee this.
  ASSERT_EQ(PAGE_READONLY, GetProtection(0));

  {
    ScopedPageProtections spp;
    EXPECT_TRUE(spp.EnsureContainingPagesWritable(BaseOfPage(0), 1));
    EXPECT_EQ(PAGE_READWRITE, GetProtection(0));
  }

  EXPECT_EQ(PAGE_READONLY, GetProtection(0));
}

}  // namespace asan
}  // namespace agent
