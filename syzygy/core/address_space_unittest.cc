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
#include "syzygy/core/address_space.h"
#include <limits>
#include "gtest/gtest.h"

namespace core {

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

TEST(AddressSpaceTest, SubsumeInsert) {
  IntegerAddressSpace address_space;
  typedef IntegerAddressSpace::Range Range;
  void* item = "Something to point at";

  // Non-overlapping insertions should work.
  EXPECT_TRUE(address_space.SubsumeInsert(Range(100, 10), item));
  EXPECT_TRUE(address_space.SubsumeInsert(Range(110, 5), item));
  EXPECT_TRUE(address_space.SubsumeInsert(Range(120, 10), item));
  EXPECT_TRUE(address_space.ranges().size() == 3);

  // Insertion of sub-ranges of existing ranges should work, but not
  // actually create anything new.
  EXPECT_TRUE(address_space.SubsumeInsert(Range(100, 5), item));
  EXPECT_TRUE(address_space.SubsumeInsert(Range(111, 2), item));
  EXPECT_TRUE(address_space.SubsumeInsert(Range(127, 2), item));
  EXPECT_TRUE(address_space.ranges().size() == 3);

  // Reinsertions should work, but not actually create anything new.
  EXPECT_TRUE(address_space.SubsumeInsert(Range(100, 10), item));
  EXPECT_TRUE(address_space.SubsumeInsert(Range(110, 5), item));
  EXPECT_TRUE(address_space.SubsumeInsert(Range(120, 10), item));
  EXPECT_TRUE(address_space.ranges().size() == 3);

  // Overlapping (but not containing) intersections should be rejected.
  EXPECT_FALSE(address_space.SubsumeInsert(Range(95, 10), item));
  EXPECT_FALSE(address_space.SubsumeInsert(Range(100, 11), item));
  EXPECT_FALSE(address_space.SubsumeInsert(Range(125, 6), item));
  EXPECT_TRUE(address_space.ranges().size() == 3);

  // Insertions of ranges that contain all intersecting existing ranges
  // should replace those ranges.
  EXPECT_TRUE(address_space.SubsumeInsert(Range(95, 40), item));
  EXPECT_TRUE(address_space.ranges().size() == 1);
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

TEST(AddressSpaceTest, RemoveByIter) {
  IntegerAddressSpace address_space;
  void* item = "Something to point at";

  // Insert some items.
  ASSERT_TRUE(address_space.Insert(IntegerAddressSpace::Range(100, 10), item));
  ASSERT_TRUE(address_space.Insert(IntegerAddressSpace::Range(110, 5), item));
  ASSERT_TRUE(address_space.Insert(IntegerAddressSpace::Range(120, 10), item));

  // Removal by single iterator should succeed.
  address_space.Remove(address_space.begin());
  EXPECT_TRUE(address_space.ranges().size() == 2);

  // Removal by pair of iterators should succeed.
  address_space.Remove(address_space.begin(), address_space.end());
  EXPECT_TRUE(address_space.ranges().empty());
}

TEST(AddressSpaceTest, Intersects) {
  IntegerAddressSpace address_space;
  void* item = "Something to point at";

  // Insert some items.
  ASSERT_TRUE(address_space.Insert(IntegerAddressSpace::Range(100, 10), item));
  ASSERT_TRUE(address_space.Insert(IntegerAddressSpace::Range(110, 5), item));
  ASSERT_TRUE(address_space.Insert(IntegerAddressSpace::Range(120, 10), item));

  // Valid intersections should return true.
  ASSERT_TRUE(address_space.Intersects(95, 10));
  ASSERT_TRUE(address_space.Intersects(95, 50));

  // Empty intersections should fail.
  ASSERT_FALSE(address_space.Intersects(95, 5));
  ASSERT_FALSE(address_space.Intersects(115, 5));
}

TEST(AddressSpaceTest, ContainsExactly) {
  IntegerAddressSpace address_space;
  void* item = "Something to point at";

  // Insert some items.
  ASSERT_TRUE(address_space.Insert(IntegerAddressSpace::Range(100, 10), item));
  ASSERT_TRUE(address_space.Insert(IntegerAddressSpace::Range(110, 5), item));
  ASSERT_TRUE(address_space.Insert(IntegerAddressSpace::Range(120, 10), item));

  // Exact containment should return true.
  ASSERT_TRUE(address_space.ContainsExactly(100, 10));
  ASSERT_TRUE(address_space.ContainsExactly(110, 5));
  ASSERT_TRUE(address_space.ContainsExactly(120, 10));

  // Proper containment should fail (in both directions).
  ASSERT_FALSE(address_space.ContainsExactly(101, 8));
  ASSERT_FALSE(address_space.ContainsExactly(110, 4));
  ASSERT_FALSE(address_space.ContainsExactly(110, 6));
  ASSERT_FALSE(address_space.ContainsExactly(122, 8));

  // Intersections should fail.
  ASSERT_FALSE(address_space.ContainsExactly(95, 10));
  ASSERT_FALSE(address_space.ContainsExactly(125, 10));
}

TEST(AddressSpaceTest, Contains) {
  IntegerAddressSpace address_space;
  void* item = "Something to point at";

  // Insert some items.
  ASSERT_TRUE(address_space.Insert(IntegerAddressSpace::Range(100, 10), item));
  ASSERT_TRUE(address_space.Insert(IntegerAddressSpace::Range(110, 5), item));
  ASSERT_TRUE(address_space.Insert(IntegerAddressSpace::Range(120, 10), item));

  // Exact containment should return true.
  ASSERT_TRUE(address_space.Contains(100, 10));
  ASSERT_TRUE(address_space.Contains(110, 5));
  ASSERT_TRUE(address_space.Contains(120, 10));

  // Proper sub-ranges of existing ranges should return true.
  ASSERT_TRUE(address_space.Contains(101, 8));
  ASSERT_TRUE(address_space.Contains(110, 4));
  ASSERT_TRUE(address_space.Contains(122, 8));

  // Ranges that properly contain existing ranges should fail.
  ASSERT_FALSE(address_space.Contains(110, 6));

  // Intersections should fail.
  ASSERT_FALSE(address_space.Contains(95, 10));
  ASSERT_FALSE(address_space.Contains(125, 10));
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

  it_pair =
      address_space.FindIntersecting(IntegerAddressSpace::Range(115, 5));
  EXPECT_TRUE(it_pair.first == it_pair.second);
  EXPECT_TRUE(it_pair.second != address_space.end());

  it_pair = address_space.FindIntersecting(IntegerAddressSpace::Range(100, 15));
  ASSERT_TRUE(it_pair.first != address_space.ranges().end());
  ASSERT_TRUE(it_pair.second != address_space.ranges().end());
  EXPECT_EQ(100, it_pair.first->first.start());
  EXPECT_EQ(120, it_pair.second->first.start());
}

}  // namespace core
