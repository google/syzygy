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
#include "base/memory/scoped_ptr.h"
#include "base/strings/stringprintf.h"
#include "gtest/gtest.h"
#include "syzygy/common/align.h"
#include "syzygy/testing/metrics.h"

namespace agent {
namespace asan {

namespace {

template <typename AccessType>
void ShadowUtilPerfTest() {
  const size_t kBufSize = 10240;
  ALIGNAS(8) uint8_t buf[kBufSize] = {};
  uint8_t* end = buf + kBufSize;

  uint64_t tnet = 0;
  // Test all (mod 8) head and tail alignments.
  for (size_t i = 0; i < 8; ++i) {
    for (size_t j = 0; j < 8; ++j) {
      ::memset(buf, 0xCC, i);
      ::memset(buf + i, 0, kBufSize - i - j);
      ::memset(end - j, 0xCC, j);
      uint64_t t0 = ::__rdtsc();
      ASSERT_TRUE(internal::IsZeroBufferImpl<AccessType>(buf + i, end - j));
      uint64_t t1 = ::__rdtsc();
      tnet += t1 - t0;
    }
  }

  testing::EmitMetric(
      base::StringPrintf("Syzygy.Asan.Shadow.IsZeroBufferImpl.%i",
                         sizeof(AccessType)),
      tnet);
}

template <typename AccessType>
void ShadowUtilTest() {
  const size_t kBufSize = 128;
  ALIGNAS(8) uint8_t buf[kBufSize] = {};
  uint8_t* end = buf + kBufSize;

  // Test all (mod 8) head and tail alignments.
  for (size_t i = 0; i < 8; ++i) {
    for (size_t j = 0; j < 8; ++j) {
      ::memset(buf, 0xCC, i);
      ::memset(buf + i, 0, kBufSize - i - j);
      ::memset(end - j, 0xCC, j);

      // Test that a non-zero byte anywhere in the buffer is detected.
      for (size_t k = i; k < kBufSize - j; ++k) {
        buf[k] = 1;
        ASSERT_FALSE(internal::IsZeroBufferImpl<AccessType>(buf + i, end - j));
        buf[k] = 0;
      }
    }
  }
}

// A derived class to expose protected members for unit-testing.
class TestShadow : public Shadow {
 public:
  TestShadow() : Shadow(kTestShadowSize) {
  }

  // We'll simulate memory as being 1GB in size.
  static const size_t kTestShadowSize =
      (1 * 1024 * 1024 * 1024) >> kShadowRatioLog;

  // Protected functions that we want to unittest directly.
  using Shadow::Reset;
  using Shadow::ScanLeftForBracketingBlockStart;
  using Shadow::ScanRightForBracketingBlockEnd;
  using Shadow::shadow_;
};

// A fixture for shadow memory tests.
class ShadowTest : public testing::Test {
 public:
  TestShadow test_shadow;
};

}  // namespace

TEST_F(ShadowTest, IsZeroBufferImplTest) {
  ShadowUtilPerfTest<uint8_t>();
  ShadowUtilPerfTest<uint16_t>();
  ShadowUtilPerfTest<uint32_t>();
  ShadowUtilPerfTest<uint64_t>();

  ShadowUtilTest<uint8_t>();
  ShadowUtilTest<uint16_t>();
  ShadowUtilTest<uint32_t>();
  ShadowUtilTest<uint64_t>();
}

TEST_F(ShadowTest, PoisonUnpoisonAccess) {
  for (size_t count = 0; count < 100; ++count) {
    // Use a random 8-byte aligned end address.
    const size_t size = base::RandInt(1, 16384);
    const uint8_t* end_addr = reinterpret_cast<const uint8_t*>(
        base::RandInt(65536, 10 * 1024 * 1024) * 8);
    const uint8_t* start_addr = end_addr - size;

    for (size_t i = 0; i < size; ++i)
      EXPECT_TRUE(test_shadow.IsAccessible(start_addr + i));

    test_shadow.Poison(start_addr, size, kAsanReservedMarker);
    for (size_t i = 0; i < size; ++i)
      EXPECT_FALSE(test_shadow.IsAccessible(start_addr + i));
    EXPECT_TRUE(test_shadow.IsAccessible(start_addr - 1));
    EXPECT_TRUE(test_shadow.IsAccessible(start_addr + size));

    const size_t aligned_size = ::common::AlignUp(size,
                                                  kShadowRatio);
    const uint8_t* aligned_start_addr = end_addr - aligned_size;
    test_shadow.Unpoison(aligned_start_addr, aligned_size);
    for (size_t i = 0; i < size; ++i)
      EXPECT_TRUE(test_shadow.IsAccessible(start_addr + i));
  }
}

TEST_F(ShadowTest, SetUpAndTearDown) {
  // Don't check all the shadow bytes otherwise this test will take too much
  // time.
  const size_t kLookupInterval = 25;

  intptr_t shadow_array_start = reinterpret_cast<intptr_t>(test_shadow.shadow_);
  size_t shadow_start = shadow_array_start >> 3;
  size_t shadow_end = shadow_start + (test_shadow.length() >> 3);

  const size_t non_addressable_memory_end = (0x10000 >> 3);

  test_shadow.SetUp();
  for (size_t i = shadow_start; i < shadow_end; i += kLookupInterval)
    ASSERT_EQ(kAsanMemoryMarker, test_shadow.shadow_[i]);

  for (size_t i = 0; i < non_addressable_memory_end; i += kLookupInterval)
    ASSERT_EQ(kInvalidAddressMarker, test_shadow.shadow_[i]);

  test_shadow.TearDown();
  for (size_t i = shadow_start; i < shadow_end; i += kLookupInterval)
    ASSERT_EQ(kHeapAddressableMarker, test_shadow.shadow_[i]);

  for (size_t i = 0; i < non_addressable_memory_end; i += kLookupInterval)
    ASSERT_EQ(kHeapAddressableMarker, test_shadow.shadow_[i]);
}

namespace {

const size_t kSizesToTest[] = {4, 7, 12, 15, 21, 87, 88};

class ScopedAlignedArray {
 public:
  uint8_t* get_aligned_array() { return test_array_; }
  size_t get_aligned_length() { return kArrayLength; }

 private:
  static const size_t kArrayLength = 0x100;

  ALIGNAS(8) uint8_t test_array_[kArrayLength];
};

}  // namespace

TEST_F(ShadowTest, GetNullTerminatedArraySize) {
  ScopedAlignedArray test_array;
  uint8_t* aligned_test_array = test_array.get_aligned_array();
  size_t aligned_array_length = test_array.get_aligned_length();

  const uint8_t kMarkerValue = 0xAA;
  ::memset(aligned_test_array, kMarkerValue, aligned_array_length);
  test_shadow.Poison(
      aligned_test_array, aligned_array_length, kAsanReservedMarker);

  for (size_t size_to_test : kSizesToTest) {
    test_shadow.Unpoison(aligned_test_array, size_to_test);
    size_t size = 0;

    // Put a null byte at the end of the array and call the
    // GetNullTerminatedArraySize function with a 1-byte template argument. This
    // simulates the use of this function for a null terminated string.
    aligned_test_array[size_to_test - 1] = 0;
    EXPECT_TRUE(test_shadow.GetNullTerminatedArraySize<uint8_t>(
        aligned_test_array, 0U, &size));
    EXPECT_EQ(size_to_test, size);

    if (size_to_test % sizeof(uint16_t) == 0) {
      // Call the GetNullTerminatedArraySize with a 2-byte template argument.
      // As there is only one null byte at the end of the array we expect the
      // function to return false.
      EXPECT_FALSE(test_shadow.GetNullTerminatedArraySize<uint16_t>(
          aligned_test_array, 0U, &size));
      EXPECT_EQ(size_to_test, size);
      // Put a second null byte at the end of the array and call the function
      // again, this time we expect the function to succeed.
      aligned_test_array[size_to_test - sizeof(uint16_t)] = 0;
      EXPECT_TRUE(test_shadow.GetNullTerminatedArraySize<uint16_t>(
          aligned_test_array, 0U, &size));
      EXPECT_EQ(size_to_test, size);
      aligned_test_array[size_to_test - sizeof(uint16_t)] = kMarkerValue;
    }
    aligned_test_array[size_to_test - 1] = kMarkerValue;

    aligned_test_array[size_to_test] = kMarkerValue;
    EXPECT_FALSE(test_shadow.GetNullTerminatedArraySize<uint8_t>(
        aligned_test_array, 0U, &size));
    EXPECT_EQ(size_to_test, size);
    EXPECT_TRUE(test_shadow.GetNullTerminatedArraySize<uint8_t>(
        aligned_test_array, size_to_test, &size));

    test_shadow.Poison(aligned_test_array,
                       ::common::AlignUp(size_to_test, kShadowRatio),
                       kAsanReservedMarker);
  }
  test_shadow.Unpoison(aligned_test_array, aligned_array_length);
}

TEST_F(ShadowTest, IsAccessibleRange) {
  ScopedAlignedArray scoped_test_array;
  const uint8_t* aligned_test_array = scoped_test_array.get_aligned_array();
  size_t aligned_array_length = scoped_test_array.get_aligned_length();

  // Poison the aligned array.
  test_shadow.Poison(aligned_test_array, aligned_array_length,
                     kAsanReservedMarker);

  // Use a pointer into the array to allow for the header to be poisoned.
  const uint8_t* test_array = aligned_test_array + kShadowRatio;
  size_t test_array_length = aligned_array_length - kShadowRatio;
  // Zero-length range is always accessible.
  EXPECT_TRUE(test_shadow.IsRangeAccessible(test_array, 0U));

  for (size_t size : kSizesToTest) {
    ASSERT_GT(test_array_length, size);

    test_shadow.Unpoison(test_array, size);

    // An overflowing range is always inaccessible.
    EXPECT_FALSE(
        test_shadow.IsRangeAccessible(test_array + 3, static_cast<size_t>(-3)));

    for (size_t i = 0; i < size; ++i) {
      // Try valid ranges at every starting position inside the unpoisoned
      // range.
      EXPECT_TRUE(test_shadow.IsRangeAccessible(test_array + i, size - i));

      // Try valid ranges ending at every poisition inside the unpoisoned range.
      EXPECT_TRUE(test_shadow.IsRangeAccessible(test_array, size - i));
    }

    for (size_t i = 1; i < kShadowRatio; ++i) {
      // Try invalid ranges at starting positions outside the unpoisoned range.
      EXPECT_FALSE(test_shadow.IsRangeAccessible(test_array - i, size));

      // Try invalid ranges at ending positions outside the unpoisoned range.
      EXPECT_FALSE(test_shadow.IsRangeAccessible(test_array, size + i));
    }
  }
  test_shadow.Unpoison(aligned_test_array, aligned_array_length);
}

TEST_F(ShadowTest, FindFirstPoisonedByte) {
  ScopedAlignedArray scoped_test_array;
  const uint8_t* aligned_test_array = scoped_test_array.get_aligned_array();
  size_t aligned_array_length = scoped_test_array.get_aligned_length();

  // Poison the aligned array.
  test_shadow.Poison(aligned_test_array, aligned_array_length,
                     kAsanReservedMarker);

  // Use a pointer into the array to allow for the header to be poisoned.
  const uint8_t* test_array = aligned_test_array + kShadowRatio;
  size_t test_array_length = aligned_array_length - kShadowRatio;
  // Zero-length range is always accessible.
  EXPECT_EQ(nullptr, test_shadow.FindFirstPoisonedByte(test_array, 0U));

  for (size_t size : kSizesToTest) {
    ASSERT_GT(test_array_length, size);

    test_shadow.Unpoison(test_array, size);

    // An overflowing range is always inaccessible.
    EXPECT_EQ(test_array + 3, test_shadow.FindFirstPoisonedByte(
                                  test_array + 3, static_cast<size_t>(-3)));

    for (size_t i = 0; i < size; ++i) {
      // Try valid ranges at every starting position inside the unpoisoned
      // range.
      EXPECT_EQ(nullptr,
                test_shadow.FindFirstPoisonedByte(test_array + i, size - i));

      // Try valid ranges ending at every poisition inside the unpoisoned range.
      EXPECT_EQ(nullptr,
                test_shadow.FindFirstPoisonedByte(test_array, size - i));
    }

    for (size_t i = 1; i < kShadowRatio; ++i) {
      // Try invalid ranges at starting positions outside the unpoisoned range.
      EXPECT_EQ(test_array - i,
                test_shadow.FindFirstPoisonedByte(test_array - i, size));

      // Try invalid ranges at ending positions outside the unpoisoned range.
      EXPECT_EQ(test_array + size,
                test_shadow.FindFirstPoisonedByte(test_array, size + i));
    }
  }
  test_shadow.Unpoison(aligned_test_array, aligned_array_length);
}

TEST_F(ShadowTest, MarkAsFreed) {
  BlockLayout l0 = {}, l1 = {};
  EXPECT_TRUE(BlockPlanLayout(kShadowRatio, kShadowRatio, 16, 30, 30, &l1));
  EXPECT_TRUE(BlockPlanLayout(kShadowRatio, kShadowRatio,
                              l1.block_size + 2 * kShadowRatio, 30, 30, &l0));

  uint8_t* data = new uint8_t[l0.block_size];

  uint8_t* d0 = data;
  BlockInfo i0 = {};
  BlockInitialize(l0, d0, false, &i0);
  test_shadow.PoisonAllocatedBlock(i0);

  uint8_t* d1 = i0.RawBody() + kShadowRatio;
  BlockInfo i1 = {};
  BlockInitialize(l1, d1, true, &i1);
  test_shadow.PoisonAllocatedBlock(i1);

  test_shadow.MarkAsFreed(i0.body, i0.body_size);
  for (uint8_t* p = i0.RawBlock(); p < i0.RawBlock() + i0.block_size; ++p) {
    if (p >= i0.RawBlock() && p < i0.RawBody()) {
      EXPECT_TRUE(test_shadow.IsLeftRedzone(p));
    } else if (p >= i0.RawBody() &&
        p < i0.RawTrailerPadding()) {
      if (p >= i1.RawBlock() && p < i1.RawBody()) {
        EXPECT_TRUE(test_shadow.IsLeftRedzone(p));
      } else if (p >= i1.RawBody() && p < i1.RawTrailerPadding()) {
        EXPECT_EQ(kHeapFreedMarker,
                  test_shadow.GetShadowMarkerForAddress(p));
      } else if (p >= i1.RawTrailerPadding() &&
          p < i1.RawBlock() + i1.block_size) {
        EXPECT_TRUE(test_shadow.IsRightRedzone(p));
      } else {
        EXPECT_EQ(kHeapFreedMarker,
                  test_shadow.GetShadowMarkerForAddress(p));
      }
    } else if (p >= i0.RawTrailerPadding() &&
        p < i0.RawBlock() + i0.block_size) {
      EXPECT_TRUE(test_shadow.IsRightRedzone(p));
    }
  }

  test_shadow.Unpoison(data, l0.block_size);
  delete [] data;
}

TEST_F(ShadowTest, PoisonAllocatedBlock) {
  BlockLayout layout = {};
  EXPECT_TRUE(BlockPlanLayout(kShadowRatio, kShadowRatio, 15, 22, 0, &layout));

  uint8_t* data = new uint8_t[layout.block_size];
  BlockInfo info = {};
  BlockInitialize(layout, data, false, &info);

  test_shadow.PoisonAllocatedBlock(info);
  EXPECT_EQ(test_shadow.GetShadowMarkerForAddress(data + 0 * 8),
            kHeapBlockStartMarker0 | 7);
  EXPECT_EQ(test_shadow.GetShadowMarkerForAddress(data + 1 * 8),
            kHeapLeftPaddingMarker);
  EXPECT_EQ(test_shadow.GetShadowMarkerForAddress(data + 2 * 8),
            kHeapLeftPaddingMarker);
  EXPECT_EQ(test_shadow.GetShadowMarkerForAddress(data + 3 * 8),
            0);
  EXPECT_EQ(test_shadow.GetShadowMarkerForAddress(data + 4 * 8),
            7);
  EXPECT_EQ(test_shadow.GetShadowMarkerForAddress(data + 5 * 8),
            kHeapRightPaddingMarker);
  EXPECT_EQ(test_shadow.GetShadowMarkerForAddress(data + 6 * 8),
            kHeapRightPaddingMarker);
  EXPECT_EQ(test_shadow.GetShadowMarkerForAddress(data + 7 * 8),
            kHeapBlockEndMarker);

  uint8_t* cursor = info.RawHeader();
  for (; cursor < info.RawBody(); ++cursor)
    EXPECT_FALSE(test_shadow.IsAccessible(cursor));
  for (; cursor < info.RawBody() + info.body_size; ++cursor)
    EXPECT_TRUE(test_shadow.IsAccessible(cursor));
  for (; cursor < info.RawHeader() + info.block_size; ++cursor)
    EXPECT_FALSE(test_shadow.IsAccessible(cursor));
  test_shadow.Unpoison(info.RawBlock(), info.block_size);

  delete [] data;
}

TEST_F(ShadowTest, ScanLeftAndRight) {
  size_t offset = test_shadow.length() / 2;
  size_t l = 0;
  test_shadow.shadow_[offset + 0] = kHeapBlockStartMarker0;
  test_shadow.shadow_[offset + 1] = kHeapNestedBlockStartMarker0;
  test_shadow.shadow_[offset + 2] = kHeapAddressableMarker;
  test_shadow.shadow_[offset + 3] = kHeapNestedBlockEndMarker;
  test_shadow.shadow_[offset + 4] = kHeapBlockEndMarker;

  EXPECT_TRUE(test_shadow.ScanLeftForBracketingBlockStart(0, offset + 0, &l));
  EXPECT_EQ(offset, l);
  EXPECT_TRUE(test_shadow.ScanLeftForBracketingBlockStart(0, offset + 1, &l));
  EXPECT_EQ(offset + 1, l);
  EXPECT_TRUE(test_shadow.ScanLeftForBracketingBlockStart(0, offset + 2, &l));
  EXPECT_EQ(offset + 1, l);
  EXPECT_TRUE(test_shadow.ScanLeftForBracketingBlockStart(0, offset + 3, &l));
  EXPECT_EQ(offset + 1, l);
  EXPECT_TRUE(test_shadow.ScanLeftForBracketingBlockStart(0, offset + 4, &l));
  EXPECT_EQ(offset, l);

  EXPECT_FALSE(test_shadow.ScanLeftForBracketingBlockStart(1, offset + 0, &l));
  EXPECT_TRUE(test_shadow.ScanLeftForBracketingBlockStart(1, offset + 1, &l));
  EXPECT_EQ(offset, l);
  EXPECT_TRUE(test_shadow.ScanLeftForBracketingBlockStart(1, offset + 2, &l));
  EXPECT_EQ(offset, l);
  EXPECT_TRUE(test_shadow.ScanLeftForBracketingBlockStart(1, offset + 3, &l));
  EXPECT_EQ(offset, l);
  EXPECT_FALSE(test_shadow.ScanLeftForBracketingBlockStart(1, offset + 4, &l));

  EXPECT_FALSE(test_shadow.ScanLeftForBracketingBlockStart(2, offset + 0, &l));
  EXPECT_FALSE(test_shadow.ScanLeftForBracketingBlockStart(2, offset + 1, &l));
  EXPECT_FALSE(test_shadow.ScanLeftForBracketingBlockStart(2, offset + 2, &l));
  EXPECT_FALSE(test_shadow.ScanLeftForBracketingBlockStart(2, offset + 3, &l));
  EXPECT_FALSE(test_shadow.ScanLeftForBracketingBlockStart(2, offset + 4, &l));

  EXPECT_TRUE(test_shadow.ScanRightForBracketingBlockEnd(0, offset + 0, &l));
  EXPECT_EQ(offset + 4, l);
  EXPECT_TRUE(test_shadow.ScanRightForBracketingBlockEnd(0, offset + 1, &l));
  EXPECT_EQ(offset + 3, l);
  EXPECT_TRUE(test_shadow.ScanRightForBracketingBlockEnd(0, offset + 2, &l));
  EXPECT_EQ(offset + 3, l);
  EXPECT_TRUE(test_shadow.ScanRightForBracketingBlockEnd(0, offset + 3, &l));
  EXPECT_EQ(offset + 3, l);
  EXPECT_TRUE(test_shadow.ScanRightForBracketingBlockEnd(0, offset + 4, &l));
  EXPECT_EQ(offset + 4, l);

  EXPECT_FALSE(test_shadow.ScanRightForBracketingBlockEnd(1, offset + 0, &l));
  EXPECT_TRUE(test_shadow.ScanRightForBracketingBlockEnd(1, offset + 1, &l));
  EXPECT_EQ(offset + 4, l);
  EXPECT_TRUE(test_shadow.ScanRightForBracketingBlockEnd(1, offset + 2, &l));
  EXPECT_EQ(offset + 4, l);
  EXPECT_TRUE(test_shadow.ScanRightForBracketingBlockEnd(1, offset + 3, &l));
  EXPECT_EQ(offset + 4, l);
  EXPECT_FALSE(test_shadow.ScanRightForBracketingBlockEnd(1, offset + 4, &l));

  EXPECT_FALSE(test_shadow.ScanRightForBracketingBlockEnd(2, offset + 0, &l));
  EXPECT_FALSE(test_shadow.ScanRightForBracketingBlockEnd(2, offset + 1, &l));
  EXPECT_FALSE(test_shadow.ScanRightForBracketingBlockEnd(2, offset + 2, &l));
  EXPECT_FALSE(test_shadow.ScanRightForBracketingBlockEnd(2, offset + 3, &l));
  EXPECT_FALSE(test_shadow.ScanRightForBracketingBlockEnd(2, offset + 4, &l));

  ::memset(test_shadow.shadow_ + offset, 0, 5);
}

TEST_F(ShadowTest, ScanRightPerfTest) {
  size_t offset = test_shadow.length() / 2;
  size_t length = 1 * 1024 * 1024;

  ::memset(test_shadow.shadow_ + offset, 0, length);

  test_shadow.shadow_[offset + 0] = kHeapBlockStartMarker0;
  // A nested block with freed contents.
  test_shadow.shadow_[offset + 50] = kHeapNestedBlockStartMarker0;
  ::memset(test_shadow.shadow_ + offset + 51, kHeapFreedMarker, 8);
  test_shadow.shadow_[offset + 60] = kHeapNestedBlockEndMarker;
  // A nested block with a nested block.
  test_shadow.shadow_[offset + 100000] = kHeapNestedBlockStartMarker0;
  test_shadow.shadow_[offset + 100100] = kHeapNestedBlockStartMarker0;
  test_shadow.shadow_[offset + 100400] = kHeapNestedBlockEndMarker;
  test_shadow.shadow_[offset + 200000] = kHeapNestedBlockEndMarker;
  // The end of the outer block.
  test_shadow.shadow_[offset + length - 1] = kHeapBlockEndMarker;

  uint64_t tnet = 0;
  for (size_t i = 0; i < 100; ++i) {
    size_t l = 0;
    uint64_t t0 = ::__rdtsc();
    test_shadow.ScanRightForBracketingBlockEnd(0, offset + 1, &l);
    uint64_t t1 = ::__rdtsc();
    tnet += t1 - t0;
  }
  testing::EmitMetric("Syzygy.Asan.Shadow.ScanRightForBracketingBlockEnd",
                      tnet);

  // Reset the shadow memory.
  ::memset(test_shadow.shadow_ + offset, 0, length);
}

TEST_F(ShadowTest, IsLeftOrRightRedzone) {
  BlockLayout layout = {};
  const size_t kAllocSize = 15;
  ASSERT_NE(0U, kAllocSize % kShadowRatio);
  EXPECT_TRUE(BlockPlanLayout(kShadowRatio, kShadowRatio, kAllocSize, 0, 0,
                              &layout));

  scoped_ptr<uint8_t> data(new uint8_t[layout.block_size]);
  BlockInfo info = {};
  BlockInitialize(layout, data.get(), false, &info);

  test_shadow.PoisonAllocatedBlock(info);
  uint8_t* block = reinterpret_cast<uint8_t*>(info.header);
  uint8_t* cursor = block;

  for (; cursor < info.RawBody(); ++cursor) {
    EXPECT_TRUE(test_shadow.IsLeftRedzone(cursor));
    EXPECT_FALSE(test_shadow.IsRightRedzone(cursor));
  }
  for (; cursor < info.RawBody() + info.body_size; ++cursor) {
    EXPECT_FALSE(test_shadow.IsLeftRedzone(cursor));
    EXPECT_FALSE(test_shadow.IsRightRedzone(cursor));
  }
  for (; cursor < block + info.block_size; ++cursor) {
    EXPECT_FALSE(test_shadow.IsLeftRedzone(cursor));
    EXPECT_TRUE(test_shadow.IsRightRedzone(cursor));
  }

  test_shadow.Unpoison(block, info.block_size);
}

namespace {

void TestBlockInfoFromShadow(Shadow* shadow,
                             const BlockLayout& outer,
                             const BlockLayout& nested) {
  ASSERT_TRUE(shadow != nullptr);
  ASSERT_LE(nested.block_size, outer.body_size);

  uint8_t* data = new uint8_t[outer.block_size];

  // Try recovering the block from every position within it when no nested
  // block exists. Expect finding a nested block to fail.
  BlockInfo info = {};
  BlockInitialize(outer, data, false, &info);
  shadow->PoisonAllocatedBlock(info);
  BlockInfo info_recovered = {};
  for (size_t i = 0; i < info.block_size; ++i) {
    EXPECT_TRUE(shadow->BlockInfoFromShadow(
        info.RawBlock() + i, &info_recovered));
    EXPECT_EQ(0, ::memcmp(&info, &info_recovered, sizeof(info)));

    // This block should have no parent block as its not nested.
    EXPECT_FALSE(shadow->ParentBlockInfoFromShadow(
        info, &info_recovered));
  }

  // Place a nested block and try the recovery from every position again.
  size_t padding = ::common::AlignDown(info.body_size - nested.block_size,
                                       kShadowRatio * 2);
  uint8_t* nested_begin = info.RawBody() + padding / 2;
  uint8_t* nested_end = nested_begin + nested.block_size;
  BlockInfo nested_info = {};
  BlockInitialize(nested, nested_begin, true, &nested_info);
  nested_info.header->is_nested = true;
  shadow->PoisonAllocatedBlock(nested_info);
  for (size_t i = 0; i < info.block_size; ++i) {
    uint8_t* pos = info.RawBlock() + i;
    EXPECT_TRUE(shadow->BlockInfoFromShadow(pos, &info_recovered));

    BlockInfo parent_info = {};
    bool found_parent = shadow->ParentBlockInfoFromShadow(
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
  shadow->Unpoison(info.header, info.block_size);

  delete [] data;
}

}  // namespace

TEST_F(ShadowTest, BlockInfoFromShadow) {
  // This is a simple layout that will be nested inside of another block.
  BlockLayout layout0 = {};
  EXPECT_TRUE(BlockPlanLayout(kShadowRatio, kShadowRatio, 6, 0, 0, &layout0));

  // Plan two layouts, one with padding and another with none. The first has
  // exactly enough space for the nested block, while the second has room to
  // spare.
  BlockLayout layout1 = {};
  BlockLayout layout2 = {};
  EXPECT_TRUE(BlockPlanLayout(kShadowRatio, kShadowRatio,
      ::common::AlignUp(layout0.block_size, kShadowRatio) + 4, 0, 0,
      &layout1));
  ASSERT_EQ(0u, layout1.header_padding_size);
  ASSERT_EQ(0u, layout1.trailer_padding_size);
  EXPECT_TRUE(BlockPlanLayout(kShadowRatio, kShadowRatio,
      layout0.block_size + 2 * kShadowRatio, 32, 13, &layout2));
  ASSERT_LT(0u, layout2.header_padding_size);
  ASSERT_LT(0u, layout2.trailer_padding_size);

  EXPECT_NO_FATAL_FAILURE(TestBlockInfoFromShadow(
      &test_shadow, layout1, layout0));
  EXPECT_NO_FATAL_FAILURE(TestBlockInfoFromShadow(
      &test_shadow, layout2, layout0));
}

TEST_F(ShadowTest, IsBeginningOfBlockBody) {
  BlockLayout l = {};
  EXPECT_TRUE(BlockPlanLayout(kShadowRatio, kShadowRatio, 7, 0, 0, &l));

  size_t data_size = l.block_size;
  scoped_ptr<uint8_t> data(new uint8_t[data_size]);

  BlockInfo block_info = {};
  BlockInitialize(l, data.get(), false, &block_info);

  test_shadow.PoisonAllocatedBlock(block_info);

  EXPECT_TRUE(test_shadow.IsBeginningOfBlockBody(block_info.body));
  EXPECT_FALSE(test_shadow.IsBeginningOfBlockBody(data.get()));

  block_info.header->state = QUARANTINED_BLOCK;
  test_shadow.MarkAsFreed(block_info.body, block_info.body_size);

  EXPECT_TRUE(test_shadow.IsBeginningOfBlockBody(block_info.body));
  EXPECT_FALSE(test_shadow.IsBeginningOfBlockBody(data.get()));

  test_shadow.Unpoison(data.get(), data_size);
}

TEST_F(ShadowTest, IsBeginningOfBlockBodyForBlockOfSizeZero) {
  BlockLayout l = {};
  EXPECT_TRUE(BlockPlanLayout(kShadowRatio, kShadowRatio, 0, 0, 0, &l));

  size_t data_size = l.block_size;
  scoped_ptr<uint8_t> data(new uint8_t[data_size]);

  BlockInfo block_info = {};
  BlockInitialize(l, data.get(), false, &block_info);

  test_shadow.PoisonAllocatedBlock(block_info);

  EXPECT_TRUE(test_shadow.IsBeginningOfBlockBody(block_info.body));
  EXPECT_FALSE(test_shadow.IsBeginningOfBlockBody(data.get()));

  block_info.header->state = QUARANTINED_FLOODED_BLOCK;
  test_shadow.MarkAsFreed(block_info.body, block_info.body_size);

  EXPECT_TRUE(test_shadow.IsBeginningOfBlockBody(block_info.body));
  EXPECT_FALSE(test_shadow.IsBeginningOfBlockBody(data.get()));

  test_shadow.Unpoison(data.get(), data_size);
}

TEST_F(ShadowTest, MarkAsFreedPerfTest) {
  std::vector<uint8_t> buf;
  buf.resize(10 * 1024 * 1024, 0);

  uint64_t tnet = 0;
  for (size_t i = 0; i < 1000; ++i) {
    test_shadow.Unpoison(buf.data(), buf.size());
    uint64_t t0 = ::__rdtsc();
    test_shadow.MarkAsFreed(buf.data(), buf.size());
    uint64_t t1 = ::__rdtsc();
    tnet += t1 - t0;
    test_shadow.Unpoison(buf.data(), buf.size());
  }
  testing::EmitMetric("Syzygy.Asan.Shadow.MarkAsFreed", tnet);
}

TEST_F(ShadowTest, PageBits) {
  // Set an individual page.
  const uint8_t* addr = reinterpret_cast<const uint8_t*>(16 * 4096);
  EXPECT_FALSE(test_shadow.PageIsProtected(addr));
  test_shadow.MarkPageProtected(addr);
  EXPECT_TRUE(test_shadow.PageIsProtected(addr));
  test_shadow.MarkPageProtected(addr);
  EXPECT_TRUE(test_shadow.PageIsProtected(addr));
  test_shadow.MarkPageUnprotected(addr);
  EXPECT_FALSE(test_shadow.PageIsProtected(addr));
  test_shadow.MarkPageUnprotected(addr);
  EXPECT_FALSE(test_shadow.PageIsProtected(addr));

  // Set a range of pages at once.
  const uint8_t* addr2 = addr + 4096;
  EXPECT_FALSE(test_shadow.PageIsProtected(addr - 4096));
  EXPECT_FALSE(test_shadow.PageIsProtected(addr));
  EXPECT_FALSE(test_shadow.PageIsProtected(addr2));
  EXPECT_FALSE(test_shadow.PageIsProtected(addr2 + 4096));
  test_shadow.MarkPagesProtected(addr, 2 * 4096);
  EXPECT_FALSE(test_shadow.PageIsProtected(addr - 4096));
  EXPECT_TRUE(test_shadow.PageIsProtected(addr));
  EXPECT_TRUE(test_shadow.PageIsProtected(addr2));
  EXPECT_FALSE(test_shadow.PageIsProtected(addr2 + 4096));
  test_shadow.MarkPagesProtected(addr, 2 * 4096);
  EXPECT_FALSE(test_shadow.PageIsProtected(addr - 4096));
  EXPECT_TRUE(test_shadow.PageIsProtected(addr));
  EXPECT_TRUE(test_shadow.PageIsProtected(addr2));
  EXPECT_FALSE(test_shadow.PageIsProtected(addr2 + 4096));
  test_shadow.MarkPagesUnprotected(addr, 2 * 4096);
  EXPECT_FALSE(test_shadow.PageIsProtected(addr - 4096));
  EXPECT_FALSE(test_shadow.PageIsProtected(addr));
  EXPECT_FALSE(test_shadow.PageIsProtected(addr2));
  EXPECT_FALSE(test_shadow.PageIsProtected(addr2 + 4096));
  test_shadow.MarkPagesUnprotected(addr, 2 * 4096);
  EXPECT_FALSE(test_shadow.PageIsProtected(addr - 4096));
  EXPECT_FALSE(test_shadow.PageIsProtected(addr));
  EXPECT_FALSE(test_shadow.PageIsProtected(addr2));
  EXPECT_FALSE(test_shadow.PageIsProtected(addr2 + 4096));
}

namespace {

// A fixture for shadow walker tests.
class ShadowWalkerTest : public testing::Test {
 public:
  TestShadow test_shadow;
};

}  // namespace

TEST_F(ShadowWalkerTest, WalksNonNestedBlocks) {
  BlockLayout l = {};
  EXPECT_TRUE(BlockPlanLayout(kShadowRatio, kShadowRatio, 7, 0, 0, &l));

  size_t data_size = l.block_size * 3 + kShadowRatio;
  uint8_t* data = new uint8_t[data_size];
  uint8_t* data0 = data;
  uint8_t* data1 = data0 + l.block_size + kShadowRatio;
  uint8_t* data2 = data1 + l.block_size;

  BlockInfo i0 = {}, i1 = {}, i2 = {};
  BlockInitialize(l, data0, false, &i0);
  BlockInitialize(l, data1, false, &i1);
  BlockInitialize(l, data2, false, &i2);

  test_shadow.PoisonAllocatedBlock(i0);
  test_shadow.PoisonAllocatedBlock(i1);
  test_shadow.PoisonAllocatedBlock(i2);

  i2.header->state = QUARANTINED_BLOCK;
  test_shadow.MarkAsFreed(i2.body, i2.body_size);

  // Do a non-recursive walk through the shadow.
  BlockInfo i = {};
  ShadowWalker w0(&test_shadow, false, data, data + data_size);
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
  ShadowWalker w1(&test_shadow, true, data, data + data_size);
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

  test_shadow.Unpoison(data, data_size);
  delete [] data;
}

TEST_F(ShadowWalkerTest, WalksNestedBlocks) {
  BlockLayout b0 = {}, b1 = {}, b2 = {}, b00 = {}, b01 = {}, b10 = {},
      b100 = {};
  EXPECT_TRUE(BlockPlanLayout(kShadowRatio, kShadowRatio, 15, 30, 30, &b00));
  EXPECT_TRUE(BlockPlanLayout(kShadowRatio, kShadowRatio, 7, 0, 0, &b01));
  EXPECT_TRUE(BlockPlanLayout(kShadowRatio, kShadowRatio,
      b00.block_size + b01.block_size + kShadowRatio, 0, 0, &b0));
  EXPECT_TRUE(BlockPlanLayout(kShadowRatio, kShadowRatio, 7, 0, 0, &b100));
  EXPECT_TRUE(BlockPlanLayout(kShadowRatio, kShadowRatio, b100.block_size, 0, 0,
                              &b10));
  EXPECT_TRUE(BlockPlanLayout(kShadowRatio, kShadowRatio, b10.block_size, 0, 0,
                              &b1));
  EXPECT_TRUE(BlockPlanLayout(kShadowRatio, kShadowRatio, 100, 0, 0, &b2));

  size_t data_size = b0.block_size + b1.block_size + kShadowRatio +
      b2.block_size;
  uint8_t* data = new uint8_t[data_size];

  // Initialize the depth 0 blocks.
  uint8_t* d0 = data;
  uint8_t* d1 = d0 + b0.block_size;
  uint8_t* d2 = d1 + b1.block_size + kShadowRatio;
  BlockInfo i0 = {}, i1 = {}, i2 = {};
  BlockInitialize(b0, d0, false, &i0);
  BlockInitialize(b1, d1, false, &i1);
  BlockInitialize(b2, d2, false, &i2);
  test_shadow.PoisonAllocatedBlock(i0);
  test_shadow.PoisonAllocatedBlock(i1);
  test_shadow.PoisonAllocatedBlock(i2);

  // Initialize depth 1 blocks.
  uint8_t* d00 = i0.RawBody();
  uint8_t* d01 = d00 + b00.block_size + kShadowRatio;
  uint8_t* d10 = i1.RawBody();
  BlockInfo i00 = {}, i01 = {}, i10 = {};
  BlockInitialize(b00, d00, true, &i00);
  BlockInitialize(b01, d01, true, &i01);
  BlockInitialize(b10, d10, true, &i10);
  test_shadow.PoisonAllocatedBlock(i00);
  test_shadow.PoisonAllocatedBlock(i01);
  test_shadow.PoisonAllocatedBlock(i10);

  // Initialize depth 2 blocks.
  uint8_t* d100 = i10.RawBody();
  BlockInfo i100 = {};
  BlockInitialize(b100, d100, true, &i100);
  test_shadow.PoisonAllocatedBlock(i100);
  i100.header->state = QUARANTINED_FLOODED_BLOCK;
  test_shadow.MarkAsFreed(i100.body, i100.body_size);

  // Do a non-recursive walk through the shadow.
  BlockInfo i = {};
  ShadowWalker w0(&test_shadow, false, data, data + data_size);
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
  ShadowWalker w1(&test_shadow, true, data, data + data_size);
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

  test_shadow.Unpoison(data, data_size);
  delete [] data;
}

}  // namespace asan
}  // namespace agent
