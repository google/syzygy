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

#include <memory>

#include "base/rand_util.h"
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
  TestShadow() : Shadow() {}

  TestShadow(size_t digits, size_t power)
      : Shadow(digits << (power - kShadowRatioLog)) {
  }

  TestShadow(void* shadow, size_t length) : Shadow(shadow, length) {}

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

  const size_t non_addressable_memory_end = (0x10000 >> 3);

  test_shadow.SetUp();

// For large address spaces, the shadow memory is too large to be poisoned.
#ifndef _WIN64
  intptr_t shadow_array_start = reinterpret_cast<intptr_t>(test_shadow.shadow_);
  size_t shadow_start = shadow_array_start >> 3;
  size_t shadow_end = shadow_start + (test_shadow.length() >> 3);
  for (size_t i = shadow_start; i < shadow_end; i += kLookupInterval)
    ASSERT_EQ(kAsanMemoryMarker, test_shadow.shadow_[i]);
#endif

  for (size_t i = 0; i < non_addressable_memory_end; i += kLookupInterval)
    ASSERT_EQ(kInvalidAddressMarker, test_shadow.shadow_[i]);

  test_shadow.TearDown();

// For large address spaces, the shadow memory is too large to be poisoned.
#ifndef _WIN64
  for (size_t i = shadow_start; i < shadow_end; i += kLookupInterval)
    ASSERT_EQ(kHeapAddressableMarker, test_shadow.shadow_[i]);
#endif

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

      // Try valid ranges ending at every position inside the unpoisoned range.
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
  BlockInitialize(l0, d0, &i0);
  test_shadow.PoisonAllocatedBlock(i0);

  uint8_t* d1 = i0.RawBody() + kShadowRatio;
  BlockInfo i1 = {};
  BlockInitialize(l1, d1, &i1);
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
  BlockInitialize(layout, data, &info);

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
#ifndef _WIN64
  EXPECT_EQ(test_shadow.GetShadowMarkerForAddress(data + 7 * 8),
            kHeapBlockEndMarker);
#else
  EXPECT_EQ(test_shadow.GetShadowMarkerForAddress(data + 7 * 8),
            kHeapRightPaddingMarker);
  EXPECT_EQ(test_shadow.GetShadowMarkerForAddress(data + 8 * 8),
            kHeapBlockEndMarker);
#endif

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
  test_shadow.shadow_[offset + 1] = kHeapAddressableMarker;
  test_shadow.shadow_[offset + 2] = kHeapBlockEndMarker;

  EXPECT_TRUE(test_shadow.ScanLeftForBracketingBlockStart(offset + 0, &l));
  EXPECT_EQ(offset, l);
  EXPECT_TRUE(test_shadow.ScanLeftForBracketingBlockStart(offset + 1, &l));
  EXPECT_EQ(offset, l);
  EXPECT_TRUE(test_shadow.ScanLeftForBracketingBlockStart(offset + 2, &l));
  EXPECT_EQ(offset, l);

  EXPECT_TRUE(test_shadow.ScanRightForBracketingBlockEnd(offset + 0, &l));
  EXPECT_EQ(offset + 2, l);
  EXPECT_TRUE(test_shadow.ScanRightForBracketingBlockEnd(offset + 1, &l));
  EXPECT_EQ(offset + 2, l);
  EXPECT_TRUE(test_shadow.ScanRightForBracketingBlockEnd(offset + 2, &l));
  EXPECT_EQ(offset + 2, l);

  ::memset(test_shadow.shadow_ + offset, 0, 5);
}

TEST_F(ShadowTest, ScanRightPerfTest) {
  size_t offset = test_shadow.length() / 2;
  size_t length = 1 * 1024 * 1024;

  ::memset(test_shadow.shadow_ + offset, 0, length);

  test_shadow.shadow_[offset + 0] = kHeapBlockStartMarker0;
  // The end of the block.
  test_shadow.shadow_[offset + length - 1] = kHeapBlockEndMarker;

  uint64_t tnet = 0;
  for (size_t i = 0; i < 100; ++i) {
    size_t l = 0;
    uint64_t t0 = ::__rdtsc();
    test_shadow.ScanRightForBracketingBlockEnd(offset + 1, &l);
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

  std::unique_ptr<uint8_t[]> data(new uint8_t[layout.block_size]);
  BlockInfo info = {};
  BlockInitialize(layout, data.get(), &info);

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

void TestBlockInfoFromShadow(Shadow* shadow, const BlockLayout& block_layout) {
  ASSERT_TRUE(shadow != nullptr);

  uint8_t* data = new uint8_t[block_layout.block_size];

  BlockInfo info = {};
  BlockInitialize(block_layout, data, &info);
  shadow->PoisonAllocatedBlock(info);
  BlockInfo info_recovered = {};
  for (size_t i = 0; i < info.block_size; ++i) {
    EXPECT_TRUE(shadow->BlockInfoFromShadow(
        info.RawBlock() + i, &info_recovered));
    EXPECT_EQ(0, ::memcmp(&info, &info_recovered, sizeof(info)));
  }

  delete [] data;
}

}  // namespace

TEST_F(ShadowTest, BlockInfoFromShadow) {
  BlockLayout layout0 = {};
  EXPECT_TRUE(BlockPlanLayout(kShadowRatio, kShadowRatio, 6, 0, 0, &layout0));

  uint8_t* data = new uint8_t[layout0.block_size];

  BlockInfo info = {};
  BlockInitialize(layout0, data, &info);
  test_shadow.PoisonAllocatedBlock(info);
  BlockInfo info_recovered = {};
  for (size_t i = 0; i < info.block_size; ++i) {
    EXPECT_TRUE(
        test_shadow.BlockInfoFromShadow(info.RawBlock() + i, &info_recovered));
    EXPECT_EQ(0, ::memcmp(&info, &info_recovered, sizeof(info)));
  }
  delete[] data;
}

TEST_F(ShadowTest, IsBeginningOfBlockBody) {
  BlockLayout l = {};
  EXPECT_TRUE(BlockPlanLayout(kShadowRatio, kShadowRatio, 7, 0, 0, &l));

  size_t data_size = l.block_size;
  std::unique_ptr<uint8_t[]> data(new uint8_t[data_size]);

  BlockInfo block_info = {};
  BlockInitialize(l, data.get(), &block_info);

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
  std::unique_ptr<uint8_t[]> data(new uint8_t[data_size]);

  BlockInfo block_info = {};
  BlockInitialize(l, data.get(), &block_info);

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

TEST_F(ShadowWalkerTest, WalkEmptyRange) {
  ShadowWalker w(&test_shadow, &test_shadow, &test_shadow);
  BlockInfo i = {};
  EXPECT_FALSE(w.Next(&i));
}

TEST_F(ShadowWalkerTest, WalkRangeAtEndOfAddressSpace) {
  TestShadow ts1(4, 30);  // 4GB.
  ShadowWalker w(&ts1, reinterpret_cast<const void*>(ts1.memory_size() - 100),
                 reinterpret_cast<const void*>(ts1.memory_size()));
  BlockInfo i = {};
  EXPECT_FALSE(w.Next(&i));
}

TEST_F(ShadowWalkerTest, WalksBlocks) {
  BlockLayout l = {};
  EXPECT_TRUE(BlockPlanLayout(kShadowRatio, kShadowRatio, 7, 0, 0, &l));

  size_t data_size = l.block_size * 3 + kShadowRatio;
  uint8_t* data = new uint8_t[data_size];
  uint8_t* data0 = data;
  uint8_t* data1 = data0 + l.block_size + kShadowRatio;
  uint8_t* data2 = data1 + l.block_size;

  BlockInfo i0 = {}, i1 = {}, i2 = {};
  BlockInitialize(l, data0, &i0);
  BlockInitialize(l, data1, &i1);
  BlockInitialize(l, data2, &i2);

  test_shadow.PoisonAllocatedBlock(i0);
  test_shadow.PoisonAllocatedBlock(i1);
  test_shadow.PoisonAllocatedBlock(i2);

  i2.header->state = QUARANTINED_BLOCK;
  test_shadow.MarkAsFreed(i2.body, i2.body_size);

  // Do a non-recursive walk through the shadow.
  BlockInfo i = {};
  ShadowWalker w0(&test_shadow, data, data + data_size);
  EXPECT_TRUE(w0.Next(&i));
  EXPECT_TRUE(w0.Next(&i));
  EXPECT_TRUE(w0.Next(&i));
  EXPECT_FALSE(w0.Next(&i));

  test_shadow.Unpoison(data, data_size);
  delete [] data;
}

TEST_F(ShadowWalkerTest, WalkShadowWithUncommittedRanges) {
  // Create a 512k memory block.
  const size_t kMemorySize = 512 * 1024;
  uint8_t memory_block[kMemorySize];
  const size_t shadow_size = Shadow::RequiredLength();

#ifndef _WIN64
  DWORD shadow_allocation_type = MEM_COMMIT;
#else
  DWORD shadow_allocation_type = MEM_RESERVE;
#endif

  // Allocate the shadow memory, only reserve the memory.
  uint8_t* shadow_memory = static_cast<uint8_t*>(
      ::VirtualAlloc(nullptr, shadow_size, shadow_allocation_type,
                     PAGE_READWRITE));
  EXPECT_NE(nullptr, shadow_memory);

  uint8_t* memory_block_shadow_start =
      shadow_memory + reinterpret_cast<size_t>(memory_block) / kShadowRatio;

  TestShadow ts1(shadow_memory, Shadow::RequiredLength());

  std::vector<BlockInfo> block_info_vec;
  BlockLayout l = {};
  EXPECT_TRUE(BlockPlanLayout(kShadowRatio, kShadowRatio, 7, 0, 0, &l));
  EXPECT_LT(l.block_size, GetPageSize() * kShadowRatio);

  // Calculate the size of the shadow necessary to cover this block
  // as well as the number of pages in it.
  const size_t kBlockShadowSize = kMemorySize / kShadowRatio;
  size_t shadow_page_count = kBlockShadowSize / GetPageSize();

  // Allocate a block that will fit on every other pages of the shadow.
  for (size_t i = 0; i < shadow_page_count; ++i) {
    if (i % 2 == 0)
      continue;
    // Address of the shadow memory for this page.
    uint8_t* shadow_address = memory_block_shadow_start + i * GetPageSize();
    uint8_t* shadow_address_page_begin =
        ::common::AlignDown(shadow_address, GetPageSize());
    // Commit the shadow memory for this block.
    EXPECT_EQ(static_cast<void*>(shadow_address_page_begin),
              ::VirtualAlloc(shadow_address, GetPageSize(), MEM_COMMIT,
                             PAGE_READWRITE));

    // Address of the memory for this block.
    uint8_t* page_address = ::common::AlignUp(
        memory_block + i * GetPageSize() * kShadowRatio, kShadowRatio);
    BlockInfo block_info = {};
    BlockInitialize(l, page_address, &block_info);
    block_info_vec.push_back(block_info);

    // Poison the block.
    ts1.PoisonAllocatedBlock(block_info);
  }

  size_t block_count = 0;
  ShadowWalker w(&ts1, memory_block, memory_block + kMemorySize);
  BlockInfo i = {};
  while (w.Next(&i)) {
    EXPECT_LT(block_count, block_info_vec.size());
    EXPECT_EQ(block_info_vec[block_count].header, i.header);
    EXPECT_EQ(block_info_vec[block_count].body, i.body);
    EXPECT_EQ(block_info_vec[block_count].trailer, i.trailer);
    block_count++;
  }
  EXPECT_EQ(block_info_vec.size(), block_count);
  EXPECT_FALSE(w.Next(&i));

  EXPECT_GT(::VirtualFree(shadow_memory, 0, MEM_RELEASE), 0U);
}

}  // namespace asan
}  // namespace agent
