// Copyright 2011 Google Inc. All Rights Reserved.
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

#include "syzygy/common/align.h"
#include "gtest/gtest.h"

namespace common {

TEST(AlignTest, IsPowerOfTwo) {
  EXPECT_FALSE(IsPowerOfTwo(0));
  EXPECT_TRUE(IsPowerOfTwo(1));
  EXPECT_TRUE(IsPowerOfTwo(2));
  EXPECT_FALSE(IsPowerOfTwo(3));
  EXPECT_TRUE(IsPowerOfTwo(4));
  EXPECT_TRUE(IsPowerOfTwo(0x80000000));
  EXPECT_FALSE(IsPowerOfTwo(0x80000001U));
  EXPECT_TRUE(IsPowerOfTwo(reinterpret_cast<uint16*>(0x40000000U)));
  EXPECT_FALSE(IsPowerOfTwo(reinterpret_cast<uint16*>(0x40000001U)));
}

TEST(AlignTest, AlignUp) {
  // Try power of two alignments.
  EXPECT_EQ(0, AlignUp(0, 1));
  EXPECT_EQ(1, AlignUp(1, 1));

  EXPECT_EQ(0, AlignUp(0, 2));
  EXPECT_EQ(2, AlignUp(1, 2));

  EXPECT_EQ(0x8000000, AlignUp(3, 0x8000000));
  EXPECT_EQ(0x8000000, AlignUp(0x8000000, 0x8000000));

  EXPECT_EQ(reinterpret_cast<void*>(0x40000000U),
            AlignUp(reinterpret_cast<void*>(0x40000000U), 4));

  // And non-power of two alignments.
  EXPECT_EQ(0, AlignUp(0, 3));
  EXPECT_EQ(3, AlignUp(1, 3));

  EXPECT_EQ(0, AlignUp(0, 7));
  EXPECT_EQ(7, AlignUp(1, 7));

  EXPECT_EQ(0, AlignUp(0, 0x8000123));
  EXPECT_EQ(0x8000123, AlignUp(3, 0x8000123));

  EXPECT_EQ(reinterpret_cast<void*>(0x40000008U),
            AlignUp(reinterpret_cast<void*>(0x40000001U), 8));
}

TEST(AlignTest, AlignDown) {
  // Try power of two alignments.
  EXPECT_EQ(0, AlignDown(0, 1));
  EXPECT_EQ(1, AlignDown(1, 1));

  EXPECT_EQ(0, AlignDown(0, 2));
  EXPECT_EQ(0, AlignDown(1, 2));

  EXPECT_EQ(0x8000000, AlignDown(0x8000000, 0x8000000));
  EXPECT_EQ(0x8000000, AlignDown(0x8000003, 0x8000000));

  EXPECT_EQ(reinterpret_cast<int32*>(0x40000000U),
            AlignUp(reinterpret_cast<int32*>(0x40000000U), 4));

  // And non-power of two alignments.
  EXPECT_EQ(0, AlignDown(0, 3));
  EXPECT_EQ(0, AlignDown(1, 3));
  EXPECT_EQ(6, AlignDown(7, 3));

  EXPECT_EQ(0, AlignDown(0, 7));
  EXPECT_EQ(14, AlignDown(14, 7));

  EXPECT_EQ(0, AlignDown(1234, 0x8000123));
  EXPECT_EQ(0x8000123, AlignDown(0x8000123, 0x8000123));
  EXPECT_EQ(0x8000123, AlignDown(0x8000124, 0x8000123));

  EXPECT_EQ(reinterpret_cast<int32*>(0x40000010U),
            AlignUp(reinterpret_cast<int32*>(0x40000001U), 16));
}

TEST(AlignTest, IsAligned) {
  // Try power of two alignments.
  EXPECT_TRUE(IsAligned(0, 1));
  EXPECT_TRUE(IsAligned(1, 1));

  EXPECT_TRUE(IsAligned(0, 2));
  EXPECT_FALSE(IsAligned(1, 2));

  EXPECT_TRUE(IsAligned(0x8000000, 0x8000000));
  EXPECT_FALSE(IsAligned(0x8000003, 0x8000000));

  EXPECT_TRUE(IsAligned(reinterpret_cast<const char*>(0x40000000U), 4));

  // And non-power of two alignments.
  EXPECT_TRUE(IsAligned(0, 3));
  EXPECT_FALSE(IsAligned(1, 3));
  EXPECT_FALSE(IsAligned(7, 3));
  EXPECT_TRUE(IsAligned(3, 3));

  EXPECT_TRUE(IsAligned(0, 7));
  EXPECT_TRUE(IsAligned(14, 7));
  EXPECT_FALSE(IsAligned(13, 7));

  EXPECT_FALSE(IsAligned(1234, 0x8000123));
  EXPECT_TRUE(IsAligned(0x8000123, 0x8000123));
  EXPECT_FALSE(IsAligned(0x8000124, 0x8000123));

  EXPECT_FALSE(IsAligned(reinterpret_cast<const char*>(0x40000001U), 4));
}

TEST(AlignTest, GetAlignment) {
  const size_t max_alignment = 0x80000000;

  EXPECT_EQ(max_alignment, GetAlignment(0));

  // Try power of 2 values.
  for (uint32 i = 1; i < max_alignment; i <<= 1)
    EXPECT_EQ(i, GetAlignment(i));

  EXPECT_EQ(max_alignment, GetAlignment(max_alignment));

  // Try non-power of 2 values.
  EXPECT_EQ(16, GetAlignment(0x3210));
  EXPECT_EQ(8, GetAlignment(0xFFF8));
  EXPECT_EQ(4, GetAlignment(0xF0F4));
  EXPECT_EQ(2, GetAlignment(0xF122));
  EXPECT_EQ(1, GetAlignment(0xF123));
}

TEST(AlignTest, IsPowerOfTwo64) {
  EXPECT_FALSE(IsPowerOfTwo64(0));
  EXPECT_TRUE(IsPowerOfTwo64(1));
  EXPECT_TRUE(IsPowerOfTwo64(2));
  EXPECT_FALSE(IsPowerOfTwo64(3));
  EXPECT_TRUE(IsPowerOfTwo64(4));
  EXPECT_TRUE(IsPowerOfTwo64(0x80000000ULL));
  EXPECT_FALSE(IsPowerOfTwo64(0x80000001ULL));
  EXPECT_FALSE(IsPowerOfTwo64(0x123000000000ULL));
  EXPECT_FALSE(IsPowerOfTwo64(0x123000000001ULL));
  EXPECT_TRUE(IsPowerOfTwo64(0x100000000000ULL));
  EXPECT_TRUE(IsPowerOfTwo64(0x200000000000ULL));
  EXPECT_FALSE(IsPowerOfTwo64(0x100000000001ULL));
  EXPECT_FALSE(IsPowerOfTwo64(0x200000000002ULL));
  EXPECT_TRUE(IsPowerOfTwo64(0x8000000000000000ULL));
  EXPECT_FALSE(IsPowerOfTwo64(0x8000000000000001ULL));
}

TEST(AlignTest, AlignUp64) {
  // Try power of two alignments.
  EXPECT_EQ(0, AlignUp64(0, 1));
  EXPECT_EQ(1, AlignUp64(1, 1));

  EXPECT_EQ(0, AlignUp64(0, 2));
  EXPECT_EQ(2, AlignUp64(1, 2));

  EXPECT_EQ(0x8000000, AlignUp64(3, 0x8000000));
  EXPECT_EQ(0x8000000, AlignUp64(0x8000000, 0x8000000));

  // And non-power of two alignments.
  EXPECT_EQ(0, AlignUp64(0, 3));
  EXPECT_EQ(3, AlignUp64(1, 3));

  EXPECT_EQ(0, AlignUp64(0, 7));
  EXPECT_EQ(7, AlignUp64(1, 7));

  EXPECT_EQ(0, AlignUp64(0, 0x8000123));
  EXPECT_EQ(0x8000123, AlignUp64(3, 0x8000123));

  // Try alignments of huge values.
  EXPECT_EQ(0x1000000004ULL, AlignUp64(0x1000000001ULL, 4));
  EXPECT_EQ(0x1000000002ULL, AlignUp64(0x1000000001ULL, 2));
  EXPECT_EQ(0x1000000001ULL, AlignUp64(0x1000000001ULL, 1));
  EXPECT_EQ(0xCCCCCCCCABCDABD0ULL, AlignUp64(0xCCCCCCCCABCDABCDULL, 16));
}

TEST(AlignTest, AlignDown64) {
  // Try power of two alignments.
  EXPECT_EQ(0, AlignDown64(0, 1));
  EXPECT_EQ(1, AlignDown64(1, 1));

  EXPECT_EQ(0, AlignDown64(0, 2));
  EXPECT_EQ(0, AlignDown64(1, 2));

  EXPECT_EQ(0x8000000, AlignDown64(0x8000000, 0x8000000));
  EXPECT_EQ(0x8000000, AlignDown64(0x8000003, 0x8000000));

  // And non-power of two alignments.
  EXPECT_EQ(0, AlignDown64(0, 3));
  EXPECT_EQ(0, AlignDown64(1, 3));
  EXPECT_EQ(6, AlignDown64(7, 3));

  EXPECT_EQ(0, AlignDown64(0, 7));
  EXPECT_EQ(14, AlignDown64(14, 7));

  EXPECT_EQ(0, AlignDown64(1234, 0x8000123));
  EXPECT_EQ(0x8000123, AlignDown64(0x8000123, 0x8000123));
  EXPECT_EQ(0x8000123, AlignDown64(0x8000124, 0x8000123));

  // Try alignments of huge values.
  EXPECT_EQ(0x1000000000ULL, AlignDown64(0x1000000001ULL, 4));
  EXPECT_EQ(0x1000000000ULL, AlignDown64(0x1000000001ULL, 2));
  EXPECT_EQ(0x1000000001ULL, AlignDown64(0x1000000001ULL, 1));
  EXPECT_EQ(0xCCCCCCCCABCDABC0ULL, AlignDown64(0xCCCCCCCCABCDABCDULL, 16));
}

TEST(AlignTest, IsAligned64) {
  // Try power of two alignments.
  EXPECT_TRUE(IsAligned64(0, 1));
  EXPECT_TRUE(IsAligned64(1, 1));

  EXPECT_TRUE(IsAligned64(0, 2));
  EXPECT_FALSE(IsAligned64(1, 2));

  EXPECT_TRUE(IsAligned64(0x8000000, 0x8000000));
  EXPECT_FALSE(IsAligned64(0x8000003, 0x8000000));

  // And non-power of two alignments.
  EXPECT_TRUE(IsAligned64(0, 3));
  EXPECT_FALSE(IsAligned64(1, 3));
  EXPECT_FALSE(IsAligned64(7, 3));
  EXPECT_TRUE(IsAligned64(3, 3));

  EXPECT_TRUE(IsAligned64(0, 7));
  EXPECT_TRUE(IsAligned64(14, 7));
  EXPECT_FALSE(IsAligned64(13, 7));

  EXPECT_FALSE(IsAligned64(1234, 0x8000123));
  EXPECT_TRUE(IsAligned64(0x8000123, 0x8000123));
  EXPECT_FALSE(IsAligned64(0x8000124, 0x8000123));

  // Try alignments of huge values.
  EXPECT_FALSE(IsAligned64(0x1000000001ULL, 4));
  EXPECT_FALSE(IsAligned64(0x1000000001ULL, 2));
  EXPECT_TRUE(IsAligned64(0x1000000002ULL, 2));
  EXPECT_TRUE(IsAligned64(0x1000000001ULL, 1));
  EXPECT_FALSE(IsAligned64(0xCCCCCCCCABCDABCDULL, 16));
  EXPECT_TRUE(IsAligned64(0xCCCCCCCCABCDABC0ULL, 16));
}

TEST(AlignTest, GetAlignment64) {
  const uint64 max_alignment = 1ULL << 63;

  EXPECT_EQ(max_alignment, GetAlignment64(0));

  // Try power of 2 values.
  for (uint64 i = 1; i < max_alignment; i <<= 1)
    EXPECT_EQ(i, GetAlignment64(i));

  EXPECT_EQ(max_alignment, GetAlignment64(max_alignment));

  // Try non-power of 2 values.
  EXPECT_EQ(0x800000000, GetAlignment64(0x1111111800000000));
  EXPECT_EQ(16, GetAlignment64(0x1111111176543210));
  EXPECT_EQ(8, GetAlignment64(0x11111111FFFFFFF8));
  EXPECT_EQ(4, GetAlignment64(0x11111111BCDEF0F4));
  EXPECT_EQ(2, GetAlignment64(0x11111111AAAAF122));
  EXPECT_EQ(1, GetAlignment64(0x111111111212F123));
}

}  // namespace common
