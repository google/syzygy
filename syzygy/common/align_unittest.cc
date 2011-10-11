// Copyright 2011 Google Inc.
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
}

TEST(AlignTest, AlignUp) {
  // Try power of two alignments.
  EXPECT_EQ(0, AlignUp(0, 1));
  EXPECT_EQ(1, AlignUp(1, 1));

  EXPECT_EQ(0, AlignUp(0, 2));
  EXPECT_EQ(2, AlignUp(1, 2));

  EXPECT_EQ(0x8000000, AlignUp(3, 0x8000000));
  EXPECT_EQ(0x8000000, AlignUp(0x8000000, 0x8000000));

  // And non-power of two alignments.
  EXPECT_EQ(0, AlignUp(0, 3));
  EXPECT_EQ(3, AlignUp(1, 3));

  EXPECT_EQ(0, AlignUp(0, 7));
  EXPECT_EQ(7, AlignUp(1, 7));

  EXPECT_EQ(0, AlignUp(0, 0x8000123));
  EXPECT_EQ(0x8000123, AlignUp(3, 0x8000123));
}

TEST(AlignTest, AlignDown) {
  // Try power of two alignments.
  EXPECT_EQ(0, AlignDown(0, 1));
  EXPECT_EQ(1, AlignDown(1, 1));

  EXPECT_EQ(0, AlignDown(0, 2));
  EXPECT_EQ(0, AlignDown(1, 2));

  EXPECT_EQ(0x8000000, AlignDown(0x8000000, 0x8000000));
  EXPECT_EQ(0x8000000, AlignDown(0x8000003, 0x8000000));

  // And non-power of two alignments.
  EXPECT_EQ(0, AlignDown(0, 3));
  EXPECT_EQ(0, AlignDown(1, 3));
  EXPECT_EQ(6, AlignDown(7, 3));

  EXPECT_EQ(0, AlignDown(0, 7));
  EXPECT_EQ(14, AlignDown(14, 7));

  EXPECT_EQ(0, AlignDown(1234, 0x8000123));
  EXPECT_EQ(0x8000123, AlignDown(0x8000123, 0x8000123));
  EXPECT_EQ(0x8000123, AlignDown(0x8000124, 0x8000123));
}

TEST(AlignTest, IsAligned) {
  // Try power of two alignments.
  EXPECT_TRUE(IsAligned(0, 1));
  EXPECT_TRUE(IsAligned(1, 1));

  EXPECT_TRUE(IsAligned(0, 2));
  EXPECT_FALSE(IsAligned(1, 2));

  EXPECT_TRUE(IsAligned(0x8000000, 0x8000000));
  EXPECT_FALSE(IsAligned(0x8000003, 0x8000000));

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
}

}  // namespace common
