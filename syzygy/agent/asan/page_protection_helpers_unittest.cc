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

#include "syzygy/agent/asan/page_protection_helpers.h"

#include "gtest/gtest.h"
#include "syzygy/agent/asan/unittest_util.h"

namespace agent {
namespace asan {

namespace {

// Use the unittest fixture with an OnExceptionCallback.
class PageProtectionHelpersTest : public testing::OnExceptionCallbackTest {
 public:
  using Super = testing::OnExceptionCallbackTest;

  enum Protection {
    kProtectNone,
    kProtectRedzones,
    kProtectAll,
  };

  void SetUp() override {
    Super::SetUp();
    shadow_.SetUp();
  }

  void TearDown() override {
    shadow_.TearDown();
    Super::TearDown();
  }

  // Wrapper to testing::IsAccessible that also checks the shadow memory page
  // protection bits.
  bool IsAccessible(void* addr) {
    if (!testing::IsAccessible(addr))
      return false;
    if (shadow_.PageIsProtected(addr))
      return false;
    return true;
  }

  // Wrapper to testing::IsNotAccessible that also checks the shadow memory page
  // protection bits.
  bool IsNotAccessible(void* addr) {
    if (!testing::IsNotAccessible(addr))
      return false;
    if (!shadow_.PageIsProtected(addr))
      return false;
    return true;
  }

  void TestAccessUnderProtection(const BlockInfo& block_info,
                                 Protection protection) {
    // Grab a set of points to sample for access, scattered across the various
    // components of the block.
    std::set<void*> samples;
    samples.insert(block_info.RawHeader());
    samples.insert(block_info.RawHeaderPadding() - 1);
    samples.insert(block_info.header_padding);
    samples.insert(block_info.RawHeaderPadding() +
                   block_info.header_padding_size / 2);
    samples.insert(block_info.RawHeaderPadding() +
                   block_info.header_padding_size - 1);
    samples.insert(block_info.RawBody());
    samples.insert(block_info.RawBody() + block_info.body_size / 2);
    samples.insert(block_info.RawBody() + block_info.body_size - 1);
    samples.insert(block_info.RawTrailerPadding());
    samples.insert(block_info.RawTrailerPadding() +
                   block_info.trailer_padding_size / 2);
    samples.insert(block_info.RawTrailerPadding() +
                   block_info.trailer_padding_size - 1);
    samples.insert(block_info.RawTrailer());
    samples.insert(block_info.RawTrailer());
    samples.insert(block_info.RawBlock() + block_info.block_size - 1);

    // Also sample at points at the edges of the pages in the redzones.
    if (block_info.left_redzone_pages_size > 0) {
      if (block_info.RawBlock() < block_info.left_redzone_pages)
        samples.insert(block_info.left_redzone_pages - 1);
      samples.insert(block_info.left_redzone_pages);
      samples.insert(block_info.left_redzone_pages +
                     block_info.left_redzone_pages_size - 1);
      samples.insert(block_info.left_redzone_pages +
                     block_info.left_redzone_pages_size);
    }
    if (block_info.right_redzone_pages_size > 0) {
      samples.insert(block_info.right_redzone_pages - 1);
      samples.insert(block_info.right_redzone_pages);
      samples.insert(block_info.right_redzone_pages +
                     block_info.right_redzone_pages_size - 1);
      uint8_t* past_end =
          block_info.right_redzone_pages + block_info.right_redzone_pages_size;
      if (past_end < block_info.RawBlock() + block_info.block_size)
        samples.insert(past_end);
    }

    uint8_t* left_end =
        block_info.left_redzone_pages + block_info.left_redzone_pages_size;
    uint8_t* right_end =
        block_info.right_redzone_pages + block_info.right_redzone_pages_size;
    uint8_t* block_end = block_info.block_pages + block_info.block_pages_size;

    std::set<void*>::const_iterator it = samples.begin();
    for (; it != samples.end(); ++it) {
      if ((*it >= block_info.left_redzone_pages && *it < left_end) ||
          (*it >= block_info.right_redzone_pages && *it < right_end)) {
        // In the left or right guard pages.
        if (protection == kProtectNone) {
          EXPECT_TRUE(IsAccessible(*it));
        } else {
          EXPECT_TRUE(IsNotAccessible(*it));
        }
      } else if (*it >= block_info.block_pages && *it < block_end) {
        // In the block pages, but not a left or right guard page.
        if (protection == kProtectAll) {
          EXPECT_TRUE(IsNotAccessible(*it));
        } else {
          EXPECT_TRUE(IsAccessible(*it));
        }
      } else {
        // In the block, but in a page that is only partially covered.
        EXPECT_TRUE(IsAccessible(*it));
      }
    }
  }

  // Tests that the page protections are as expected after calling
  // BlockProtectNone.
  void TestProtectNone(const BlockInfo& block_info) {
    BlockProtectNone(block_info, &shadow_);
    EXPECT_NO_FATAL_FAILURE(
        TestAccessUnderProtection(block_info, kProtectNone));
  }

  // Tests that the page protections are as expected after calling
  // BlockProtectRedzones.
  void TestProtectRedzones(const BlockInfo& block_info) {
    BlockProtectRedzones(block_info, &shadow_);
    EXPECT_NO_FATAL_FAILURE(
        TestAccessUnderProtection(block_info, kProtectRedzones));
  }

  // Tests that the page protections are as expected after calling
  // BlockProtectAll.
  void TestProtectAll(const BlockInfo& block_info) {
    BlockProtectAll(block_info, &shadow_);
    EXPECT_NO_FATAL_FAILURE(TestAccessUnderProtection(block_info, kProtectAll));
  }

  // Tests that all page protection transitions work.
  void TestAllProtectionTransitions(uint32_t chunk_size,
                                    uint32_t alignment,
                                    uint32_t size,
                                    uint32_t min_left_redzone_size,
                                    uint32_t min_right_redzone_size) {
    // Create and initialize the given block.
    BlockLayout layout = {};
    EXPECT_TRUE(BlockPlanLayout(chunk_size, alignment, size,
                                min_left_redzone_size, min_right_redzone_size,
                                &layout));
    void* alloc =
        ::VirtualAlloc(NULL, layout.block_size, MEM_COMMIT, PAGE_READWRITE);
    ASSERT_TRUE(alloc != NULL);
    BlockInfo block_info = {};
    BlockInitialize(layout, alloc, &block_info);

    // By default the protections should be disabled for a fresh allocation.
    EXPECT_NO_FATAL_FAILURE(
        TestAccessUnderProtection(block_info, kProtectNone));

    // Try a full cycle of page protections. This tests all possible
    // transitions, including self transitions.
    EXPECT_NO_FATAL_FAILURE(TestProtectNone(block_info));
    EXPECT_NO_FATAL_FAILURE(TestProtectNone(block_info));
    EXPECT_NO_FATAL_FAILURE(TestProtectRedzones(block_info));
    EXPECT_NO_FATAL_FAILURE(TestProtectRedzones(block_info));
    EXPECT_NO_FATAL_FAILURE(TestProtectAll(block_info));
    EXPECT_NO_FATAL_FAILURE(TestProtectAll(block_info));
    EXPECT_NO_FATAL_FAILURE(TestProtectNone(block_info));
    EXPECT_NO_FATAL_FAILURE(TestProtectAll(block_info));
    EXPECT_NO_FATAL_FAILURE(TestProtectRedzones(block_info));
    EXPECT_NO_FATAL_FAILURE(TestProtectNone(block_info));

    ASSERT_EQ(TRUE, ::VirtualFree(alloc, 0, MEM_RELEASE));
  }

  Shadow shadow_;
};

using testing::_;

}  // namespace

TEST_F(PageProtectionHelpersTest, GetBlockInfo) {
  // Plan a layout that is subject to page protections.
  BlockLayout layout = {};
  BlockPlanLayout(4096, 4096, 4096, 4096, 4096, &layout);

  void* alloc = ::VirtualAlloc(
      nullptr, layout.block_size, MEM_COMMIT, PAGE_READWRITE);
  ASSERT_TRUE(alloc != nullptr);
  ::memset(alloc, 0, layout.block_size);

  // Initialize the block in both memory and the shadow memory.
  BlockInfo info = {};
  BlockInitialize(layout, alloc, &info);
  shadow_.PoisonAllocatedBlock(info);

  // Try recovering in the usual case.
  BlockInfo info_recovered = {};
  EXPECT_TRUE(BlockInfoFromMemory(info.header, &info_recovered));
  EXPECT_TRUE(GetBlockInfo(&shadow_, info.body, &info_recovered));
  EXPECT_EQ(0, ::memcmp(&info, &info_recovered, sizeof(info)));

  // Muck up the header and try again.
  info.header->magic++;
  EXPECT_FALSE(BlockInfoFromMemory(info.header, &info_recovered));
  EXPECT_TRUE(GetBlockInfo(&shadow_, info.body, &info_recovered));
  EXPECT_EQ(0, ::memcmp(&info, &info_recovered, sizeof(info)));
  info.header->magic--;
  EXPECT_TRUE(BlockInfoFromMemory(info.header, &info_recovered));

  // Set page protections and try again.
  BlockProtectRedzones(info, &shadow_);
  EXPECT_CALL(*this, OnExceptionCallback(_));
  EXPECT_FALSE(BlockInfoFromMemory(info.header, &info_recovered));
  testing::Mock::VerifyAndClearExpectations(this);
  EXPECT_TRUE(GetBlockInfo(&shadow_, info.body, &info_recovered));
  EXPECT_EQ(0, ::memcmp(&info, &info_recovered, sizeof(info)));
  BlockProtectNone(info, &shadow_);
  EXPECT_TRUE(BlockInfoFromMemory(info.header, &info_recovered));

  // Clean up.
  shadow_.Unpoison(info.header, info.block_size);
  ::VirtualFree(alloc, layout.block_size, MEM_RELEASE);
}

TEST_F(PageProtectionHelpersTest, ProtectionTransitions) {
  // Left and right guard pages, everything page aligned.
  EXPECT_NO_FATAL_FAILURE(TestAllProtectionTransitions(
      4096, 4096, 4096, 4096, 4096));

  // Left and right guard pages will contain entire pages, but
  // not be entirely covered by pages.
  EXPECT_NO_FATAL_FAILURE(TestAllProtectionTransitions(
      8, 8, 128, 4100, 8200));

  // An allocation that will contain no pages whatsoever.
  EXPECT_NO_FATAL_FAILURE(TestAllProtectionTransitions(
      8, 8, 67, 0, 0));

  // An allocation with redzones containing no pages, but that covers an
  // entire page.
  EXPECT_NO_FATAL_FAILURE(TestAllProtectionTransitions(
      4096, 8, 67, 0, 0));
}

TEST_F(PageProtectionHelpersTest, BlockProtectAuto) {
  BlockLayout layout = {};
  const uint32_t kPageSize = static_cast<uint32_t>(GetPageSize());
  EXPECT_TRUE(BlockPlanLayout(kPageSize, kPageSize, kPageSize, kPageSize,
                              kPageSize, &layout));
  void* alloc = ::VirtualAlloc(NULL, layout.block_size, MEM_COMMIT,
                               PAGE_READWRITE);
  ASSERT_TRUE(alloc != NULL);

  BlockInfo block_info = {};
  BlockInitialize(layout, alloc, &block_info);
  TestAccessUnderProtection(block_info, kProtectNone);

  block_info.header->state = ALLOCATED_BLOCK;
  BlockProtectAuto(block_info, &shadow_);
  TestAccessUnderProtection(block_info, kProtectRedzones);
  BlockProtectNone(block_info, &shadow_);

  block_info.header->state = QUARANTINED_BLOCK;
  BlockProtectAuto(block_info, &shadow_);
  TestAccessUnderProtection(block_info, kProtectAll);
  BlockProtectNone(block_info, &shadow_);

  block_info.header->state = QUARANTINED_FLOODED_BLOCK;
  BlockProtectAuto(block_info, &shadow_);
  TestAccessUnderProtection(block_info, kProtectAll);
  BlockProtectNone(block_info, &shadow_);

  block_info.header->state = FREED_BLOCK;
  BlockProtectAuto(block_info, &shadow_);
  TestAccessUnderProtection(block_info, kProtectAll);
  BlockProtectNone(block_info, &shadow_);

  ASSERT_EQ(TRUE, ::VirtualFree(alloc, 0, MEM_RELEASE));
}

}  // namespace asan
}  // namespace agent
