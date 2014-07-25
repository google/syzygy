// Copyright 2012 Google Inc. All Rights Reserved.
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

#include "syzygy/agent/asan/shadow.h"

#include "base/rand_util.h"
#include "gtest/gtest.h"
#include "syzygy/common/align.h"

namespace agent {
namespace asan {

namespace {

// A derived class to expose protected members for unit-testing.
class TestShadow : public Shadow {
 public:
  using Shadow::Reset;
  using Shadow::ScanLeftForBracketingBlockStart;
  using Shadow::ScanRightForBracketingBlockEnd;
  using Shadow::kShadowSize;
  using Shadow::shadow_;
};

}  // namespace

TEST(ShadowTest, PoisonUnpoisonAccess) {
  // Reset the shadow memory.
  TestShadow::Reset();
  for (size_t count = 0; count < 100; ++count) {
    // Use a random 8-byte aligned end address.
    const size_t size = base::RandInt(1, 16384);
    const uint8* end_addr =
        reinterpret_cast<const uint8*>(base::RandInt(65536, 10*1024*1024) * 8);
    const uint8* start_addr = end_addr - size;

    for (size_t i = 0; i < size; ++i)
      EXPECT_TRUE(Shadow::IsAccessible(start_addr + i));

    Shadow::Poison(start_addr, size, Shadow::kHeapNonAccessibleByteMask);
    for (size_t i = 0; i < size; ++i)
      EXPECT_FALSE(Shadow::IsAccessible(start_addr + i));
    EXPECT_TRUE(Shadow::IsAccessible(start_addr - 1));
    EXPECT_TRUE(Shadow::IsAccessible(start_addr + size));

    const size_t aligned_size = common::AlignUp(size,
                                                kShadowRatio);
    const uint8* aligned_start_addr = end_addr - aligned_size;
    Shadow::Unpoison(aligned_start_addr, aligned_size);
    for (size_t i = 0; i < size; ++i)
      EXPECT_TRUE(Shadow::IsAccessible(start_addr + i));
  }
}

TEST(ShadowTest, SetUpAndTearDown) {
  // Reset the shadow memory.
  TestShadow::Reset();

  // Don't check all the shadow bytes otherwise this test will take too much
  // time.
  const size_t kLookupInterval = 25;

  intptr_t shadow_array_start = reinterpret_cast<intptr_t>(TestShadow::shadow_);
  size_t shadow_start = shadow_array_start >> 3;
  size_t shadow_end = shadow_start + (TestShadow::kShadowSize >> 3);

  const size_t non_addressable_memory_end = (0x10000 >> 3);

  Shadow::SetUp();
  for (size_t i = shadow_start; i < shadow_end; i += kLookupInterval)
    ASSERT_EQ(Shadow::kAsanMemoryByte, TestShadow::shadow_[i]);

  for (size_t i = 0; i < non_addressable_memory_end; i += kLookupInterval)
    ASSERT_EQ(Shadow::kInvalidAddress, TestShadow::shadow_[i]);

  Shadow::TearDown();
  for (size_t i = shadow_start; i < shadow_end; i += kLookupInterval)
    ASSERT_EQ(Shadow::kHeapAddressableByte, TestShadow::shadow_[i]);

  for (size_t i = 0; i < non_addressable_memory_end; i += kLookupInterval)
    ASSERT_EQ(Shadow::kHeapAddressableByte, TestShadow::shadow_[i]);
}

TEST(ShadowTest, GetNullTerminatedArraySize) {
  // Reset the shadow memory.
  TestShadow::Reset();
  const size_t kArrayLength = 100;
  const uint8 kMarkerValue = 0xAA;

  uint8 test_array[kArrayLength];
  uint8* aligned_test_array = reinterpret_cast<uint8*>(
      common::AlignUp(reinterpret_cast<size_t>(test_array),
                      kShadowRatio));
  size_t aligned_array_length = common::AlignDown(kArrayLength -
      (aligned_test_array - test_array), kShadowRatio);

  ::memset(aligned_test_array, kMarkerValue, aligned_array_length);
  Shadow::Poison(aligned_test_array, aligned_array_length,
      Shadow::kHeapNonAccessibleByteMask);

  size_t sizes_to_test[] = { 4, 7, 12, 15, 21, 87, 88 };

  for (size_t i = 0; i < arraysize(sizes_to_test); ++i) {
    Shadow::Unpoison(aligned_test_array, sizes_to_test[i]);
    size_t size = 0;

    // Put a null byte at the end of the array and call the
    // GetNullTerminatedArraySize function with a 1-byte template argument. This
    // simulates the use of this function for a null terminated string.
    aligned_test_array[sizes_to_test[i] - 1] = 0;
    EXPECT_TRUE(Shadow::GetNullTerminatedArraySize<uint8>(aligned_test_array,
                                                          0U,
                                                          &size));
    EXPECT_EQ(sizes_to_test[i], size);

    if (sizes_to_test[i] % sizeof(uint16) == 0) {
      // Call the GetNullTerminatedArraySize with a 2-byte template argument.
      // As there is only one null byte at the end of the array we expect the
      // function to return false.
      EXPECT_FALSE(Shadow::GetNullTerminatedArraySize<uint16>(
          aligned_test_array, 0U, &size));
      EXPECT_EQ(sizes_to_test[i], size);
      // Put a second null byte at the end of the array and call the function
      // again, this time we expect the function to succeed.
      aligned_test_array[sizes_to_test[i] - sizeof(uint16)] = 0;
      EXPECT_TRUE(Shadow::GetNullTerminatedArraySize<uint16>(
          aligned_test_array, 0U, &size));
      EXPECT_EQ(sizes_to_test[i], size);
      aligned_test_array[sizes_to_test[i] - sizeof(uint16)] = kMarkerValue;
    }
    aligned_test_array[sizes_to_test[i] - 1] = kMarkerValue;

    aligned_test_array[sizes_to_test[i]] = kMarkerValue;
    EXPECT_FALSE(Shadow::GetNullTerminatedArraySize<uint8>(aligned_test_array,
                                                           0U,
                                                           &size));
    EXPECT_EQ(sizes_to_test[i], size);
    EXPECT_TRUE(Shadow::GetNullTerminatedArraySize<uint8>(aligned_test_array,
                                                          sizes_to_test[i],
                                                          &size));

    Shadow::Poison(aligned_test_array, common::AlignUp(sizes_to_test[i],
       kShadowRatio), Shadow::kHeapNonAccessibleByteMask);
  }
  Shadow::Unpoison(aligned_test_array, aligned_array_length);
}

TEST(ShadowTest, MarkAsFreed) {
  BlockLayout l0 = {}, l1 = {};
  BlockPlanLayout(kShadowRatio, kShadowRatio, 16, 30, 30, &l1);
  BlockPlanLayout(kShadowRatio, kShadowRatio, l1.block_size + 2 * kShadowRatio,
                  30, 30, &l0);

  uint8* data = new uint8[l0.block_size];

  uint8* d0 = data;
  BlockInfo i0 = {};
  BlockInitialize(l0, d0, false, &i0);
  Shadow::PoisonAllocatedBlock(i0);

  uint8* d1 = i0.body + kShadowRatio;
  BlockInfo i1 = {};
  BlockInitialize(l1, d1, true, &i1);
  Shadow::PoisonAllocatedBlock(i1);

  Shadow::MarkAsFreed(i0.body, i0.body_size);
  for (uint8* p = i0.block; p < i0.block + i0.block_size; ++p) {
    if (p >= i0.block && p < i0.body) {
      EXPECT_TRUE(Shadow::IsLeftRedzone(p));
    } else if (p >= i0.body && p < i0.trailer_padding) {
      if (p >= i1.block && p < i1.body) {
        EXPECT_TRUE(Shadow::IsLeftRedzone(p));
      } else if (p >= i1.body && p < i1.trailer_padding) {
        EXPECT_EQ(Shadow::kHeapFreedByte,
                  Shadow::GetShadowMarkerForAddress(p));
      } else if (p >= i1.trailer_padding && p < i1.block + i1.block_size) {
        EXPECT_TRUE(Shadow::IsRightRedzone(p));
      } else {
        EXPECT_EQ(Shadow::kHeapFreedByte,
                  Shadow::GetShadowMarkerForAddress(p));
      }
    } else if (p >= i0.trailer_padding && p < i0.block + i0.block_size) {
      EXPECT_TRUE(Shadow::IsRightRedzone(p));
    }
  }

  Shadow::Unpoison(data, l0.block_size);
  delete [] data;
}

TEST(ShadowTest, PoisonAllocatedBlock) {
  BlockLayout layout = {};
  BlockPlanLayout(kShadowRatio, kShadowRatio, 15, 22, 0, &layout);

  uint8* data = new uint8[layout.block_size];
  BlockInfo info = {};
  BlockInitialize(layout, data, false, &info);

  Shadow::PoisonAllocatedBlock(info);
  EXPECT_EQ(Shadow::GetShadowMarkerForAddress(data + 0 * 8),
            Shadow::kHeapBlockStartByte0 | 7);
  EXPECT_EQ(Shadow::GetShadowMarkerForAddress(data + 1 * 8),
            Shadow::kHeapLeftRedzone);
  EXPECT_EQ(Shadow::GetShadowMarkerForAddress(data + 2 * 8),
            Shadow::kHeapLeftRedzone);
  EXPECT_EQ(Shadow::GetShadowMarkerForAddress(data + 3 * 8),
            0);
  EXPECT_EQ(Shadow::GetShadowMarkerForAddress(data + 4 * 8),
            7);
  EXPECT_EQ(Shadow::GetShadowMarkerForAddress(data + 5 * 8),
            Shadow::kHeapRightRedzone);
  EXPECT_EQ(Shadow::GetShadowMarkerForAddress(data + 6 * 8),
            Shadow::kHeapRightRedzone);
  EXPECT_EQ(Shadow::GetShadowMarkerForAddress(data + 7 * 8),
            Shadow::kHeapBlockEndByte);
  Shadow::Unpoison(info.block, info.block_size);

  delete [] data;
}

TEST(ShadowTest, ScanLeftAndRight) {
  size_t offset = Shadow::kShadowSize / 2;
  size_t l = 0;
  TestShadow::shadow_[offset + 0] = Shadow::kHeapBlockStartByte0;
  TestShadow::shadow_[offset + 1] = Shadow::kHeapNestedBlockStartByte0;
  TestShadow::shadow_[offset + 2] = Shadow::kHeapAddressableByte;
  TestShadow::shadow_[offset + 3] = Shadow::kHeapNestedBlockEndByte;
  TestShadow::shadow_[offset + 4] = Shadow::kHeapBlockEndByte;

  EXPECT_TRUE(TestShadow::ScanLeftForBracketingBlockStart(0, offset + 0, &l));
  EXPECT_EQ(offset, l);
  EXPECT_TRUE(TestShadow::ScanLeftForBracketingBlockStart(0, offset + 1, &l));
  EXPECT_EQ(offset + 1, l);
  EXPECT_TRUE(TestShadow::ScanLeftForBracketingBlockStart(0, offset + 2, &l));
  EXPECT_EQ(offset + 1, l);
  EXPECT_TRUE(TestShadow::ScanLeftForBracketingBlockStart(0, offset + 3, &l));
  EXPECT_EQ(offset + 1, l);
  EXPECT_TRUE(TestShadow::ScanLeftForBracketingBlockStart(0, offset + 4, &l));
  EXPECT_EQ(offset, l);

  EXPECT_FALSE(TestShadow::ScanLeftForBracketingBlockStart(1, offset + 0, &l));
  EXPECT_TRUE(TestShadow::ScanLeftForBracketingBlockStart(1, offset + 1, &l));
  EXPECT_EQ(offset, l);
  EXPECT_TRUE(TestShadow::ScanLeftForBracketingBlockStart(1, offset + 2, &l));
  EXPECT_EQ(offset, l);
  EXPECT_TRUE(TestShadow::ScanLeftForBracketingBlockStart(1, offset + 3, &l));
  EXPECT_EQ(offset, l);
  EXPECT_FALSE(TestShadow::ScanLeftForBracketingBlockStart(1, offset + 4, &l));

  EXPECT_FALSE(TestShadow::ScanLeftForBracketingBlockStart(2, offset + 0, &l));
  EXPECT_FALSE(TestShadow::ScanLeftForBracketingBlockStart(2, offset + 1, &l));
  EXPECT_FALSE(TestShadow::ScanLeftForBracketingBlockStart(2, offset + 2, &l));
  EXPECT_FALSE(TestShadow::ScanLeftForBracketingBlockStart(2, offset + 3, &l));
  EXPECT_FALSE(TestShadow::ScanLeftForBracketingBlockStart(2, offset + 4, &l));

  EXPECT_TRUE(TestShadow::ScanRightForBracketingBlockEnd(0, offset + 0, &l));
  EXPECT_EQ(offset + 4, l);
  EXPECT_TRUE(TestShadow::ScanRightForBracketingBlockEnd(0, offset + 1, &l));
  EXPECT_EQ(offset + 3, l);
  EXPECT_TRUE(TestShadow::ScanRightForBracketingBlockEnd(0, offset + 2, &l));
  EXPECT_EQ(offset + 3, l);
  EXPECT_TRUE(TestShadow::ScanRightForBracketingBlockEnd(0, offset + 3, &l));
  EXPECT_EQ(offset + 3, l);
  EXPECT_TRUE(TestShadow::ScanRightForBracketingBlockEnd(0, offset + 4, &l));
  EXPECT_EQ(offset + 4, l);

  EXPECT_FALSE(TestShadow::ScanRightForBracketingBlockEnd(1, offset + 0, &l));
  EXPECT_TRUE(TestShadow::ScanRightForBracketingBlockEnd(1, offset + 1, &l));
  EXPECT_EQ(offset + 4, l);
  EXPECT_TRUE(TestShadow::ScanRightForBracketingBlockEnd(1, offset + 2, &l));
  EXPECT_EQ(offset + 4, l);
  EXPECT_TRUE(TestShadow::ScanRightForBracketingBlockEnd(1, offset + 3, &l));
  EXPECT_EQ(offset + 4, l);
  EXPECT_FALSE(TestShadow::ScanRightForBracketingBlockEnd(1, offset + 4, &l));

  EXPECT_FALSE(TestShadow::ScanRightForBracketingBlockEnd(2, offset + 0, &l));
  EXPECT_FALSE(TestShadow::ScanRightForBracketingBlockEnd(2, offset + 1, &l));
  EXPECT_FALSE(TestShadow::ScanRightForBracketingBlockEnd(2, offset + 2, &l));
  EXPECT_FALSE(TestShadow::ScanRightForBracketingBlockEnd(2, offset + 3, &l));
  EXPECT_FALSE(TestShadow::ScanRightForBracketingBlockEnd(2, offset + 4, &l));

  ::memset(TestShadow::shadow_ + offset, 0, 5);
}

namespace {

void TestBlockInfoFromShadow(const BlockLayout& outer,
                             const BlockLayout& nested) {
  ASSERT_LE(nested.block_size, outer.body_size);

  uint8* data = new uint8[outer.block_size];

  // Try recovering the block from every position within it when no nested
  // block exists. Expect finding a nested block to fail.
  BlockInfo info = {};
  BlockInitialize(outer, data, false, &info);
  Shadow::PoisonAllocatedBlock(info);
  BlockInfo info_recovered = {};
  for (size_t i = 0; i < info.block_size; ++i) {
    EXPECT_TRUE(Shadow::BlockInfoFromShadow(info.block + i, &info_recovered));
    EXPECT_EQ(0, ::memcmp(&info, &info_recovered, sizeof(info)));

    // This block should have no parent block as its not nested.
    EXPECT_FALSE(Shadow::ParentBlockInfoFromShadow(
        info, &info_recovered));
  }

  // Place a nested block and try the recovery from every position again.
  size_t padding = common::AlignDown(info.body_size - nested.block_size,
                                     kShadowRatio * 2);
  uint8* nested_begin = info.body + padding / 2;
  uint8* nested_end = nested_begin + nested.block_size;
  BlockInfo nested_info = {};
  BlockInitialize(nested, nested_begin, true, &nested_info);
  nested_info.header->is_nested = true;
  Shadow::PoisonAllocatedBlock(nested_info);
  for (size_t i = 0; i < info.block_size; ++i) {
    uint8* pos = info.block + i;
    EXPECT_TRUE(Shadow::BlockInfoFromShadow(pos, &info_recovered));

    BlockInfo parent_info = {};
    bool found_parent = Shadow::ParentBlockInfoFromShadow(
        info_recovered, &parent_info);

    if (pos >= nested_begin && pos < nested_end) {
      EXPECT_EQ(0, ::memcmp(&nested_info, &info_recovered,
                            sizeof(nested_info)));
      EXPECT_TRUE(found_parent);
      EXPECT_EQ(0, ::memcmp(&info, &parent_info, sizeof(info)));
    } else {
      EXPECT_EQ(0, ::memcmp(&info, &info_recovered, sizeof(info)));
      EXPECT_FALSE(found_parent);
    }
  }
  Shadow::Unpoison(info.block, info.block_size);

  delete [] data;
}

}  // namespace

TEST(ShadowTest, BlockInfoFromShadow) {
  // This is a simple layout that will be nested inside of another block.
  BlockLayout layout0 = {};
  BlockPlanLayout(kShadowRatio, kShadowRatio, 6, 0, 0, &layout0);

  // Plan two layouts, one with padding and another with none. The first has
  // exactly enough space for the nested block, while the second has room to
  // spare.
  BlockLayout layout1 = {};
  BlockLayout layout2 = {};
  BlockPlanLayout(kShadowRatio, kShadowRatio,
                  common::AlignUp(layout0.block_size, kShadowRatio) + 4, 0, 0,
                  &layout1);
  ASSERT_EQ(0u, layout1.header_padding_size);
  ASSERT_EQ(0u, layout1.trailer_padding_size);
  BlockPlanLayout(kShadowRatio, kShadowRatio,
                  layout0.block_size + 2 * kShadowRatio, 32, 13, &layout2);
  ASSERT_LT(0u, layout2.header_padding_size);
  ASSERT_LT(0u, layout2.trailer_padding_size);

  EXPECT_NO_FATAL_FAILURE(TestBlockInfoFromShadow(layout1, layout0));
  EXPECT_NO_FATAL_FAILURE(TestBlockInfoFromShadow(layout2, layout0));
}

TEST(ShadowWalkerTest, WalksNonNestedBlocks) {
  BlockLayout l = {};
  BlockPlanLayout(kShadowRatio, kShadowRatio, 7, 0, 0, &l);

  size_t data_size = l.block_size * 3 + kShadowRatio;
  uint8* data = new uint8[data_size];
  uint8* data0 = data;
  uint8* data1 = data0 + l.block_size + kShadowRatio;
  uint8* data2 = data1 + l.block_size;

  BlockInfo i0 = {}, i1 = {}, i2 = {};
  BlockInitialize(l, data0, false, &i0);
  BlockInitialize(l, data1, false, &i1);
  BlockInitialize(l, data2, false, &i2);

  Shadow::PoisonAllocatedBlock(i0);
  Shadow::PoisonAllocatedBlock(i1);
  Shadow::PoisonAllocatedBlock(i2);

  i2.header->state = QUARANTINED_BLOCK;
  Shadow::MarkAsFreed(i2.body, i2.body_size);

  // Do a non-recursive walk through the shadow.
  BlockInfo i = {};
  ShadowWalker w0(false, data, data + data_size);
  EXPECT_EQ(-1, w0.nesting_depth());
  EXPECT_TRUE(w0.Next(&i));
  EXPECT_EQ(0, w0.nesting_depth());
  EXPECT_TRUE(w0.Next(&i));
  EXPECT_EQ(0, w0.nesting_depth());
  EXPECT_TRUE(w0.Next(&i));
  EXPECT_EQ(0, w0.nesting_depth());
  EXPECT_FALSE(w0.Next(&i));
  EXPECT_EQ(-1, w0.nesting_depth());

  // Walk recursively through the shadow and expect the same results.
  ShadowWalker w1(true, data, data + data_size);
  EXPECT_EQ(-1, w1.nesting_depth());
  EXPECT_TRUE(w1.Next(&i));
  EXPECT_EQ(0, w1.nesting_depth());
  EXPECT_EQ(0, ::memcmp(&i, &i0, sizeof(i)));
  EXPECT_TRUE(w1.Next(&i));
  EXPECT_EQ(0, w1.nesting_depth());
  EXPECT_EQ(0, ::memcmp(&i, &i1, sizeof(i)));
  EXPECT_TRUE(w1.Next(&i));
  EXPECT_EQ(0, w1.nesting_depth());
  EXPECT_EQ(0, ::memcmp(&i, &i2, sizeof(i)));
  EXPECT_FALSE(w1.Next(&i));
  EXPECT_EQ(-1, w1.nesting_depth());

  Shadow::Unpoison(data, data_size);
  delete [] data;
}

TEST(ShadowWalkerTest, WalksNestedBlocks) {
  BlockLayout b0 = {}, b1 = {}, b2 = {}, b00 = {}, b01 = {}, b10 = {},
      b100 = {};
  BlockPlanLayout(kShadowRatio, kShadowRatio, 15, 30, 30, &b00);
  BlockPlanLayout(kShadowRatio, kShadowRatio, 7, 0, 0, &b01);
  BlockPlanLayout(kShadowRatio, kShadowRatio,
                  b00.block_size + b01.block_size + kShadowRatio, 0, 0, &b0);
  BlockPlanLayout(kShadowRatio, kShadowRatio, 7, 0, 0, &b100);
  BlockPlanLayout(kShadowRatio, kShadowRatio, b100.block_size, 0, 0, &b10);
  BlockPlanLayout(kShadowRatio, kShadowRatio, b10.block_size, 0, 0, &b1);
  BlockPlanLayout(kShadowRatio, kShadowRatio, 100, 0, 0, &b2);

  size_t data_size = b0.block_size + b1.block_size + kShadowRatio +
      b2.block_size;
  uint8* data = new uint8[data_size];

  // Initialize the depth 0 blocks.
  uint8* d0 = data;
  uint8* d1 = d0 + b0.block_size;
  uint8* d2 = d1 + b1.block_size + kShadowRatio;
  BlockInfo i0 = {}, i1 = {}, i2 = {};
  BlockInitialize(b0, d0, false, &i0);
  BlockInitialize(b1, d1, false, &i1);
  BlockInitialize(b2, d2, false, &i2);
  Shadow::PoisonAllocatedBlock(i0);
  Shadow::PoisonAllocatedBlock(i1);
  Shadow::PoisonAllocatedBlock(i2);

  // Initialize depth 1 blocks.
  uint8* d00 = i0.body;
  uint8* d01 = d00 + b00.block_size + kShadowRatio;
  uint8* d10 = i1.body;
  BlockInfo i00 = {}, i01 = {}, i10 = {};
  BlockInitialize(b00, d00, true, &i00);
  BlockInitialize(b01, d01, true, &i01);
  BlockInitialize(b10, d10, true, &i10);
  Shadow::PoisonAllocatedBlock(i00);
  Shadow::PoisonAllocatedBlock(i01);
  Shadow::PoisonAllocatedBlock(i10);

  // Initialize depth 2 blocks.
  uint8* d100 = i10.body;
  BlockInfo i100 = {};
  BlockInitialize(b100, d100, true, &i100);
  Shadow::PoisonAllocatedBlock(i100);
  i100.header->state = QUARANTINED_BLOCK;
  Shadow::MarkAsFreed(i100.body, i100.body_size);

  // Do a non-recursive walk through the shadow.
  BlockInfo i = {};
  ShadowWalker w0(false, data, data + data_size);
  EXPECT_EQ(-1, w0.nesting_depth());
  EXPECT_TRUE(w0.Next(&i));
  EXPECT_EQ(0, w0.nesting_depth());
  EXPECT_EQ(0, ::memcmp(&i, &i0, sizeof(i)));
  EXPECT_TRUE(w0.Next(&i));
  EXPECT_EQ(0, w0.nesting_depth());
  EXPECT_EQ(0, ::memcmp(&i, &i1, sizeof(i)));
  EXPECT_TRUE(w0.Next(&i));
  EXPECT_EQ(0, w0.nesting_depth());
  EXPECT_EQ(0, ::memcmp(&i, &i2, sizeof(i)));
  EXPECT_FALSE(w0.Next(&i));
  EXPECT_EQ(-1, w0.nesting_depth());

  // Walk recursively through the shadow.
  ShadowWalker w1(true, data, data + data_size);
  EXPECT_EQ(-1, w1.nesting_depth());
  EXPECT_TRUE(w1.Next(&i));
  EXPECT_EQ(0, w1.nesting_depth());
  EXPECT_EQ(0, ::memcmp(&i, &i0, sizeof(i)));
  EXPECT_TRUE(w1.Next(&i));
  EXPECT_EQ(1, w1.nesting_depth());
  EXPECT_EQ(0, ::memcmp(&i, &i00, sizeof(i)));
  EXPECT_TRUE(w1.Next(&i));
  EXPECT_EQ(1, w1.nesting_depth());
  EXPECT_EQ(0, ::memcmp(&i, &i01, sizeof(i)));
  EXPECT_TRUE(w1.Next(&i));
  EXPECT_EQ(0, w1.nesting_depth());
  EXPECT_EQ(0, ::memcmp(&i, &i1, sizeof(i)));
  EXPECT_TRUE(w1.Next(&i));
  EXPECT_EQ(1, w1.nesting_depth());
  EXPECT_EQ(0, ::memcmp(&i, &i10, sizeof(i)));
  EXPECT_TRUE(w1.Next(&i));
  EXPECT_EQ(2, w1.nesting_depth());
  EXPECT_EQ(0, ::memcmp(&i, &i100, sizeof(i)));
  EXPECT_TRUE(w1.Next(&i));
  EXPECT_EQ(0, w1.nesting_depth());
  EXPECT_EQ(0, ::memcmp(&i, &i2, sizeof(i)));
  EXPECT_FALSE(w1.Next(&i));
  EXPECT_EQ(-1, w1.nesting_depth());

  Shadow::Unpoison(data, data_size);
  delete [] data;
}

}  // namespace asan
}  // namespace agent
