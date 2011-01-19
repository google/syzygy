// Copyright 2010 Google Inc.
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
#include "gtest/gtest.h"
#include "sawbuck/image_util/address_space.h"
#include <limits>

namespace image_util {

typedef AddressRange<const uint8*, size_t> PointerRange;
typedef AddressRange<size_t, size_t> IntegerRange;

TEST(AddressRangeTest, Create) {
  PointerRange pointer_range(NULL, std::numeric_limits<size_t>::max());
  IntegerRange integer_range(0, std::numeric_limits<size_t>::max());
}

TEST(AddressRangeTest, Contains) {
  // Non-intersecting ranges first.
  EXPECT_FALSE(IntegerRange(10, 10).Contains(IntegerRange(0, 10)));
  EXPECT_FALSE(IntegerRange(0, 10).Contains(IntegerRange(10, 10)));

  // Overlapping, non-contained.
  EXPECT_FALSE(IntegerRange(5, 10).Contains(IntegerRange(10, 10)));
  EXPECT_FALSE(IntegerRange(0, 10).Contains(IntegerRange(5, 10)));

  // Contained, a couple of different cases.
  EXPECT_TRUE(IntegerRange(10, 10).Contains(IntegerRange(10, 10)));
  EXPECT_TRUE(IntegerRange(10, 10).Contains(IntegerRange(15, 5)));
  EXPECT_TRUE(IntegerRange(10, 10).Contains(IntegerRange(10, 5)));
}

TEST(AddressRangeTest, Intersects) {
  // Non-intersecting ranges first.
  EXPECT_FALSE(IntegerRange(10, 10).Intersects(IntegerRange(0, 10)));
  EXPECT_FALSE(IntegerRange(0, 10).Intersects(IntegerRange(10, 10)));

  // Overlapping, non-contained.
  EXPECT_TRUE(IntegerRange(5, 10).Intersects(IntegerRange(10, 10)));
  EXPECT_TRUE(IntegerRange(0, 10).Intersects(IntegerRange(5, 10)));

  // Contained, a couple of different cases.
  EXPECT_TRUE(IntegerRange(10, 10).Intersects(IntegerRange(10, 10)));
  EXPECT_TRUE(IntegerRange(10, 10).Intersects(IntegerRange(15, 5)));
  EXPECT_TRUE(IntegerRange(10, 10).Intersects(IntegerRange(10, 5)));
}

TEST(AddressRangeTest, Operators) {
  EXPECT_FALSE(IntegerRange(10, 10) < IntegerRange(10, 10));
  EXPECT_TRUE(IntegerRange(9, 10) < IntegerRange(10, 10));
  EXPECT_TRUE(IntegerRange(9, 11) < IntegerRange(10, 10));
  EXPECT_TRUE(IntegerRange(10, 9) < IntegerRange(10, 10));
}

typedef AddressSpace<const uint8*, size_t, void*> PointerAddressSpace;
typedef AddressSpace<size_t, size_t, void*> IntegerAddressSpace;

TEST(AddressSpaceTest, Create) {
  PointerAddressSpace pointer_space;
  IntegerAddressSpace integer_space;
}

TEST(AddressSpaceTest, Insert) {
  IntegerAddressSpace address_space;
  void* item = "Something to point at";

  // Non-overlapping insertions should work.
  EXPECT_TRUE(address_space.Insert(IntegerAddressSpace::Range(100, 10), item));
  EXPECT_TRUE(address_space.Insert(IntegerAddressSpace::Range(110, 5), item));
  EXPECT_TRUE(address_space.Insert(IntegerAddressSpace::Range(120, 10), item));

  // Overlapping insertions should be rejected.
  EXPECT_FALSE(address_space.Insert(IntegerAddressSpace::Range(100, 10), item));
  EXPECT_FALSE(address_space.Insert(IntegerAddressSpace::Range(95, 10), item));
  EXPECT_FALSE(address_space.Insert(IntegerAddressSpace::Range(100, 5), item));
  EXPECT_FALSE(address_space.Insert(IntegerAddressSpace::Range(105, 5), item));
}

TEST(AddressSpaceTest, Remove) {
  IntegerAddressSpace address_space;
  void* item = "Something to point at";

  // Insert some items.
  ASSERT_TRUE(address_space.Insert(IntegerAddressSpace::Range(100, 10), item));
  ASSERT_TRUE(address_space.Insert(IntegerAddressSpace::Range(110, 5), item));
  ASSERT_TRUE(address_space.Insert(IntegerAddressSpace::Range(120, 10), item));

  // Non-matching removals should fail.
  ASSERT_FALSE(address_space.Remove(IntegerAddressSpace::Range(100, 9)));
  ASSERT_FALSE(address_space.Remove(IntegerAddressSpace::Range(101, 9)));
  ASSERT_FALSE(address_space.Remove(IntegerAddressSpace::Range(115, 5)));

  // Matching removals should succeed.
  ASSERT_TRUE(address_space.Remove(IntegerAddressSpace::Range(100, 10)));
  ASSERT_TRUE(address_space.Remove(IntegerAddressSpace::Range(110, 5)));

  // Items should have been removed.
  ASSERT_FALSE(address_space.Remove(IntegerAddressSpace::Range(100, 10)));
  ASSERT_FALSE(address_space.Remove(IntegerAddressSpace::Range(110, 5)));
}

TEST(AddressSpaceTest, FindFirstIntersection) {
  IntegerAddressSpace address_space;
  void* item = "Something to point at";

  EXPECT_TRUE(address_space.Insert(IntegerAddressSpace::Range(100, 10), item));
  EXPECT_TRUE(address_space.Insert(IntegerAddressSpace::Range(110, 5), item));
  EXPECT_TRUE(address_space.Insert(IntegerAddressSpace::Range(120, 10), item));

  IntegerAddressSpace::RangeMap::iterator it =
      address_space.FindFirstIntersection(IntegerAddressSpace::Range(0, 99));
  EXPECT_TRUE(it == address_space.ranges().end());

  it = address_space.FindFirstIntersection(IntegerAddressSpace::Range(0, 100));
  EXPECT_TRUE(it == address_space.ranges().end());

  it = address_space.FindFirstIntersection(IntegerAddressSpace::Range(0, 130));
  ASSERT_TRUE(it != address_space.ranges().end());
  EXPECT_EQ(100, it->first.start());

  it = address_space.FindFirstIntersection(IntegerAddressSpace::Range(110, 10));
  ASSERT_TRUE(it != address_space.ranges().end());
  EXPECT_EQ(110, it->first.start());

  it = address_space.FindFirstIntersection(IntegerAddressSpace::Range(105, 30));
  ASSERT_TRUE(it != address_space.ranges().end());
  EXPECT_EQ(100, it->first.start());

  it = address_space.FindFirstIntersection(IntegerAddressSpace::Range(110, 30));
  ASSERT_TRUE(it != address_space.ranges().end());
  EXPECT_EQ(110, it->first.start());

  it = address_space.FindFirstIntersection(IntegerAddressSpace::Range(115, 5));
  EXPECT_TRUE(it == address_space.ranges().end());

  it = address_space.FindFirstIntersection(IntegerAddressSpace::Range(130, 30));
  EXPECT_TRUE(it == address_space.ranges().end());
}

TEST(AddressSpaceTest, FindContaining) {
  IntegerAddressSpace address_space;
  void* item = "Something to point at";

  EXPECT_TRUE(address_space.Insert(IntegerAddressSpace::Range(100, 10), item));
  EXPECT_TRUE(address_space.Insert(IntegerAddressSpace::Range(110, 5), item));
  EXPECT_TRUE(address_space.Insert(IntegerAddressSpace::Range(120, 10), item));

  IntegerAddressSpace::RangeMap::iterator it =
      address_space.FindContaining(IntegerAddressSpace::Range(110, 5));
  ASSERT_TRUE(it != address_space.ranges().end());
  EXPECT_EQ(110, it->first.start());

  it = address_space.FindContaining(IntegerAddressSpace::Range(110, 2));
  ASSERT_TRUE(it != address_space.ranges().end());
  EXPECT_EQ(110, it->first.start());

  it = address_space.FindContaining(IntegerAddressSpace::Range(113, 2));
  ASSERT_TRUE(it != address_space.ranges().end());
  EXPECT_EQ(110, it->first.start());

  it = address_space.FindContaining(IntegerAddressSpace::Range(109, 5));
  EXPECT_TRUE(it == address_space.ranges().end());

  it = address_space.FindContaining(IntegerAddressSpace::Range(111, 5));
  EXPECT_TRUE(it == address_space.ranges().end());

  it = address_space.FindContaining(IntegerAddressSpace::Range(109, 7));
  EXPECT_TRUE(it == address_space.ranges().end());
}

TEST(AddressSpaceTest, FindIntersecting) {
  IntegerAddressSpace address_space;
  void* item = "Something to point at";

  EXPECT_TRUE(address_space.Insert(IntegerAddressSpace::Range(100, 10), item));
  EXPECT_TRUE(address_space.Insert(IntegerAddressSpace::Range(110, 5), item));
  EXPECT_TRUE(address_space.Insert(IntegerAddressSpace::Range(120, 10), item));

  IntegerAddressSpace::RangeMapIterPair it_pair =
      address_space.FindIntersecting(IntegerAddressSpace::Range(0, 130));
  EXPECT_TRUE(it_pair.first == address_space.ranges().begin());
  EXPECT_TRUE(it_pair.second == address_space.ranges().end());

  it_pair = address_space.FindIntersecting(IntegerAddressSpace::Range(100, 15));
  ASSERT_TRUE(it_pair.first != address_space.ranges().end());
  ASSERT_TRUE(it_pair.second != address_space.ranges().end());
  EXPECT_EQ(100, it_pair.first->first.start());
  EXPECT_EQ(120, it_pair.second->first.start());
}

}  // namespace image_util
