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

    for (size_t i = 0; i < size; ++i) {
      EXPECT_TRUE(Shadow::IsAccessible(start_addr + i));
    }

    Shadow::Poison(start_addr, size, Shadow::kHeapNonAccessibleByteMask);
    for (size_t i = 0; i < size; ++i)
      EXPECT_FALSE(Shadow::IsAccessible(start_addr + i));
    EXPECT_TRUE(Shadow::IsAccessible(start_addr - 1));
    EXPECT_TRUE(Shadow::IsAccessible(start_addr + size));

    const size_t aligned_size = common::AlignUp(size,
                                                kShadowRatio);
    const uint8* aligned_start_addr = end_addr - aligned_size;
    Shadow::Unpoison(aligned_start_addr, aligned_size);
    for (size_t i = 0; i < size; ++i) {
      EXPECT_TRUE(Shadow::IsAccessible(start_addr + i));
    }
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
  for (size_t i = shadow_start; i < shadow_end; i += kLookupInterval) {
    ASSERT_EQ(Shadow::kAsanMemoryByte, TestShadow::shadow_[i]);
  }
  for (size_t i = 0; i < non_addressable_memory_end; i += kLookupInterval) {
    ASSERT_EQ(Shadow::kInvalidAddress, TestShadow::shadow_[i]);
  }
  Shadow::TearDown();
  for (size_t i = shadow_start; i < shadow_end; i += kLookupInterval) {
    ASSERT_EQ(Shadow::kHeapAddressableByte, TestShadow::shadow_[i]);
  }
  for (size_t i = 0; i < non_addressable_memory_end; i += kLookupInterval) {
    ASSERT_EQ(Shadow::kHeapAddressableByte, TestShadow::shadow_[i]);
  }
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

TEST(ShadowTest, PoisonAllocatedBlock) {
  BlockLayout layout = {};
  BlockPlanLayout(kShadowRatio, kShadowRatio, 15, 22, 0, &layout);

  uint8* data = new uint8[layout.block_size];
  BlockInfo info = {};
  BlockInitialize(layout, data, &info);

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

namespace {

void TestBlockInfoFromShadow(const BlockLayout& outer,
                             const BlockLayout& nested) {
  ASSERT_LE(nested.block_size, outer.body_size);

  uint8* data = new uint8[outer.block_size];

  // Try recovering the block from every position within it when no nested
  // block exists.
  BlockInfo info = {};
  BlockInitialize(outer, data, &info);
  Shadow::PoisonAllocatedBlock(info);
  BlockInfo info_recovered = {};
  for (size_t i = 0; i < info.block_size; ++i) {
    EXPECT_TRUE(Shadow::BlockInfoFromShadow(info.block + i, &info_recovered));
    EXPECT_EQ(0, ::memcmp(&info, &info_recovered, sizeof(info)));
  }

  // Place a nested block and try the recovery from every position again.
  size_t padding = common::AlignDown(info.body_size - nested.block_size,
                                     kShadowRatio * 2);
  uint8* nested_begin = info.body + padding / 2;
  uint8* nested_end = nested_begin + nested.block_size;
  BlockInfo nested_info = {};
  BlockInitialize(nested, nested_begin, &nested_info);
  Shadow::PoisonAllocatedBlock(nested_info);
  for (size_t i = 0; i < info.block_size; ++i) {
    uint8* pos = info.block + i;
    EXPECT_TRUE(Shadow::BlockInfoFromShadow(pos, &info_recovered));

    if (pos >= nested_begin && pos < nested_end) {
      EXPECT_EQ(0, ::memcmp(&nested_info, &info_recovered,
                            sizeof(nested_info)));
    } else {
      EXPECT_EQ(0, ::memcmp(&info, &info_recovered, sizeof(info)));
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

}  // namespace asan
}  // namespace agent
