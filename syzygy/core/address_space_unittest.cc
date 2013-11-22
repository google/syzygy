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
//
#include "syzygy/core/address_space.h"

#include <limits>
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"

namespace core {

typedef AddressRange<const uint8*, size_t> PointerRange;
typedef AddressRange<size_t, size_t> IntegerRange;
typedef AddressRangeMap<IntegerRange, IntegerRange> IntegerRangeMap;
typedef IntegerRangeMap::RangePair IntegerRangePair;
typedef IntegerRangeMap::RangePairs IntegerRangePairs;

namespace {

// A pretty printer for AddressRange. This makes failed unittests readable.
template<typename AddressType, typename SizeType>
std::ostream& operator<<(
    std::ostream& os,
    const AddressRange<AddressType, SizeType>& addr_range) {
  os << "AddressRange(" << addr_range.start() << ", " << addr_range.size()
     << ")";
  return os;
}

// A pretty printer for std::pair.
template<typename FirstType, typename SecondType>
std::ostream& operator<<(std::ostream& os,
                         const std::pair<FirstType, SecondType>& pair) {
  os << "pair(first=" << pair.first << ", second=" << pair.second << ")";
  return os;
}

}  // namespace

TEST(AddressRangeTest, Create) {
  PointerRange pointer_range1(NULL, std::numeric_limits<size_t>::max());
  IntegerRange integer_range1(0, std::numeric_limits<size_t>::max());

  PointerRange pointer_range2(NULL, 0);
  IntegerRange integer_range2(0, 0);
}

TEST(AddressRangeTest, IsEmtpy) {
  PointerRange pointer_range1(NULL, 0);
  EXPECT_TRUE(pointer_range1.IsEmpty());

  PointerRange pointer_range2(NULL, 1);
  EXPECT_FALSE(pointer_range2.IsEmpty());
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

  // An empty range contains no full range.
  EXPECT_FALSE(IntegerRange(10, 0).Contains(IntegerRange(10, 1)));
  EXPECT_FALSE(IntegerRange(10, 0).Contains(IntegerRange(9, 2)));

  // An empty range contains itself.
  EXPECT_TRUE(IntegerRange(10, 0).Contains(IntegerRange(10, 0)));

  // An non-empty range contains any empty range with a start address within it
  // or on its boundary.
  EXPECT_TRUE(IntegerRange(10, 2).Contains(IntegerRange(11, 0)));
  EXPECT_TRUE(IntegerRange(10, 2).Contains(IntegerRange(10, 0)));
  EXPECT_TRUE(IntegerRange(10, 2).Contains(IntegerRange(12, 0)));
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

  // An empty range only intersects with a non-empty range if its address lies
  // strictly within the non-empty range.
  EXPECT_TRUE(IntegerRange(10, 2).Intersects(IntegerRange(11, 0)));
  EXPECT_TRUE(IntegerRange(11, 0).Intersects(IntegerRange(10, 2)));
  EXPECT_FALSE(IntegerRange(10, 2).Intersects(IntegerRange(10, 0)));
  EXPECT_FALSE(IntegerRange(10, 2).Intersects(IntegerRange(12, 0)));
  EXPECT_FALSE(IntegerRange(10, 0).Intersects(IntegerRange(10, 2)));
  EXPECT_FALSE(IntegerRange(12, 0).Intersects(IntegerRange(10, 2)));
}

TEST(AddressRangeTest, Operators) {
  EXPECT_FALSE(IntegerRange(10, 10) < IntegerRange(10, 10));
  EXPECT_TRUE(IntegerRange(9, 10) < IntegerRange(10, 10));
  EXPECT_TRUE(IntegerRange(9, 11) < IntegerRange(10, 10));
  EXPECT_TRUE(IntegerRange(10, 9) < IntegerRange(10, 10));

  EXPECT_TRUE(IntegerRange(10, 0) < IntegerRange(10, 1));
  EXPECT_FALSE(IntegerRange(10, 1) < IntegerRange(10, 0));
  EXPECT_FALSE(IntegerRange(10, 0) < IntegerRange(10, 0));
  EXPECT_TRUE(IntegerRange(10, 0) == IntegerRange(10, 0));
  EXPECT_FALSE(IntegerRange(10, 0) != IntegerRange(10, 0));
}

TEST(AddressRangeTest, AddressRangeSerialization) {
  const AddressRange<size_t, size_t> range(100, 20);
  EXPECT_TRUE(testing::TestSerialization(range));
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

  // Empty insertions should be rejected.
  EXPECT_FALSE(address_space.Insert(IntegerAddressSpace::Range(10, 0), item));
}

TEST(AddressSpaceTest, FindOrInsert) {
  IntegerAddressSpace address_space;
  void* item = "Something to point at";

  typedef IntegerAddressSpace::Range Range;
  typedef IntegerAddressSpace::RangeMapIter Iter;

  Iter iter1, iter2, iter3, attempt;

  // Non-overlapping insertions should work.
  EXPECT_TRUE(address_space.FindOrInsert(Range(100, 10), item, &iter1));
  EXPECT_TRUE(address_space.FindOrInsert(Range(110, 5), item, &iter2));
  EXPECT_TRUE(address_space.FindOrInsert(Range(120, 10), item, &iter3));
  EXPECT_TRUE(iter1 != iter2);
  EXPECT_TRUE(iter1 != iter3);
  EXPECT_TRUE(iter2 != iter3);

  // Exactly matching range assertions insertions should be accepted.
  EXPECT_TRUE(address_space.FindOrInsert(Range(100, 10), item, &attempt));
  EXPECT_TRUE(attempt == iter1);
  EXPECT_TRUE(address_space.FindOrInsert(Range(110, 5), item, &attempt));
  EXPECT_TRUE(attempt == iter2);
  EXPECT_TRUE(address_space.FindOrInsert(Range(120, 10), item, &attempt));
  EXPECT_TRUE(attempt == iter3);

  // Non-matching overlapping insertions should be rejected.
  EXPECT_FALSE(address_space.Insert(Range(95, 10), item, &attempt));
  EXPECT_FALSE(address_space.Insert(Range(100, 8), item, &attempt));
  EXPECT_FALSE(address_space.Insert(Range(101, 8), item, &attempt));
  EXPECT_FALSE(address_space.Insert(Range(105, 5), item, &attempt));
  EXPECT_FALSE(address_space.Insert(Range(105, 9), item, &attempt));

  // Empty insertions should be rejected.
  EXPECT_FALSE(address_space.FindOrInsert(Range(10, 0), item, &attempt));
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

  // Insertions of ranges that intersect multiple ranges should merge/extend
  // them.
  address_space.MergeInsert(Range(90, 30), item);
  EXPECT_TRUE(address_space.ranges().size() == 2);
  address_space.MergeInsert(Range(124, 2), item);
  EXPECT_TRUE(address_space.ranges().size() == 2);

  // Insertions of ranges that contain all intersecting existing ranges
  // should replace those ranges.
  EXPECT_TRUE(address_space.SubsumeInsert(Range(85, 50), item));
  EXPECT_TRUE(address_space.ranges().size() == 1);

  // Empty insertions should be rejected.
  EXPECT_FALSE(address_space.SubsumeInsert(Range(10, 0), item));
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

  // Empty removals should always fail.
  EXPECT_FALSE(address_space.Remove(IntegerAddressSpace::Range(10, 0)));
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

TEST(AddressSpaceTest, Clear) {
  IntegerAddressSpace address_space;
  void* item = "Something to point at";

  // Insert some items.
  ASSERT_TRUE(address_space.Insert(IntegerAddressSpace::Range(100, 10), item));
  ASSERT_TRUE(address_space.Insert(IntegerAddressSpace::Range(110, 5), item));
  ASSERT_TRUE(address_space.Insert(IntegerAddressSpace::Range(120, 10), item));
  ASSERT_TRUE(!address_space.ranges().empty());

  address_space.Clear();
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

  // Intersections with empty ranges should fail.
  ASSERT_FALSE(address_space.Intersects(50, 0));
  ASSERT_FALSE(address_space.Intersects(100, 0));
  ASSERT_FALSE(address_space.Intersects(101, 0));
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

  // Containment of with empty ranges should always fail.
  ASSERT_FALSE(address_space.ContainsExactly(50, 0));
  ASSERT_FALSE(address_space.ContainsExactly(100, 0));
  ASSERT_FALSE(address_space.ContainsExactly(101, 0));
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

  // Containment of with empty ranges should always fail.
  ASSERT_FALSE(address_space.Contains(50, 0));
  ASSERT_FALSE(address_space.Contains(100, 0));
  ASSERT_FALSE(address_space.Contains(101, 0));
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

  // Empty ranges should never be found.
  it = address_space.FindFirstIntersection(IntegerAddressSpace::Range(102, 0));
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

  // Empty ranges should never be found.
  it = address_space.FindContaining(IntegerAddressSpace::Range(101, 0));
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

  it_pair = address_space.FindIntersecting(IntegerAddressSpace::Range(101, 0));
  EXPECT_TRUE(it_pair.first == it_pair.second);
  EXPECT_TRUE(it_pair.first == address_space.ranges().end());
}

TEST(AddressRangeMapTest, IsSimple) {
  IntegerRangeMap map;
  EXPECT_FALSE(map.IsSimple());

  EXPECT_TRUE(map.Push(IntegerRange(0, 10), IntegerRange(1000, 10)));
  EXPECT_TRUE(map.IsSimple());

  EXPECT_TRUE(map.Push(IntegerRange(20, 10), IntegerRange(1020, 10)));
  EXPECT_FALSE(map.IsSimple());

  IntegerRangeMap map2;
  EXPECT_TRUE(map2.Push(IntegerRange(0, 10), IntegerRange(1000, 15)));
  EXPECT_FALSE(map2.IsSimple());
}

TEST(AddressRangeMapTest, FindRangePair) {
  IntegerRangeMap map;

  IntegerRangeMap::RangePair pair1(
      IntegerRange(0, 10), IntegerRange(1000, 10));
  IntegerRangeMap::RangePair pair2(
      IntegerRange(10, 10), IntegerRange(1010, 15));
  IntegerRangeMap::RangePair pair3(
      IntegerRange(40, 10), IntegerRange(1040, 10));
  ASSERT_TRUE(map.Push(pair1.first, pair1.second));
  ASSERT_TRUE(map.Push(pair2.first, pair2.second));
  ASSERT_TRUE(map.Push(pair3.first, pair3.second));
  ASSERT_EQ(3u, map.size());

  const IntegerRangeMap::RangePair* pair = map.FindRangePair(5, 3);
  EXPECT_TRUE(pair != NULL);
  EXPECT_EQ(pair1, *pair);

  pair = map.FindRangePair(IntegerRange(40, 10));
  EXPECT_TRUE(pair != NULL);
  EXPECT_EQ(pair3, *pair);

  EXPECT_EQ(NULL, map.FindRangePair(5, 10));
  EXPECT_EQ(NULL, map.FindRangePair(IntegerRange(50, 1)));
  EXPECT_EQ(NULL, map.FindRangePair(2, 0));
}

TEST(AddressRangeMapTest, IsMapped) {
  IntegerRangeMap map;
  EXPECT_TRUE(map.Push(IntegerRange(0, 10), IntegerRange(1000, 10)));
  EXPECT_TRUE(map.Push(IntegerRange(10, 10), IntegerRange(1010, 15)));
  EXPECT_TRUE(map.Push(IntegerRange(40, 10), IntegerRange(1040, 10)));

  EXPECT_TRUE(map.IsMapped(5, 15));
  EXPECT_TRUE(map.IsMapped(IntegerRange(45, 5)));

  EXPECT_FALSE(map.IsMapped(15, 10));

  EXPECT_FALSE(map.IsMapped(0, 0));
}

TEST(AddressRangeMapTest, InOrderPush) {
  IntegerRangeMap map;
  EXPECT_EQ(0u, map.size());

  EXPECT_TRUE(map.Push(IntegerRange(0, 10), IntegerRange(1000, 10)));
  EXPECT_EQ(1u, map.size());

  EXPECT_TRUE(map.Push(IntegerRange(20, 10), IntegerRange(1020, 10)));
  EXPECT_EQ(2u, map.size());

  EXPECT_FALSE(map.Push(IntegerRange(15, 10), IntegerRange(1015, 10)));
  EXPECT_FALSE(map.Push(IntegerRange(20, 10), IntegerRange(1020, 10)));
  EXPECT_FALSE(map.Push(IntegerRange(23, 2), IntegerRange(1023, 2)));
  EXPECT_FALSE(map.Push(IntegerRange(25, 10), IntegerRange(1025, 10)));

  EXPECT_TRUE(map.Push(IntegerRange(40, 10), IntegerRange(1040, 10)));
  EXPECT_EQ(3u, map.size());

  EXPECT_FALSE(map.Push(IntegerRange(0, 0), IntegerRange(1000, 1)));
  EXPECT_FALSE(map.Push(IntegerRange(0, 1), IntegerRange(1000, 0)));
  EXPECT_EQ(3u, map.size());

  IntegerRangePairs expected;
  expected.push_back(
      IntegerRangePair(IntegerRange(0, 10), IntegerRange(1000, 10)));
  expected.push_back(
      IntegerRangePair(IntegerRange(20, 10), IntegerRange(1020, 10)));
  expected.push_back(
      IntegerRangePair(IntegerRange(40, 10), IntegerRange(1040, 10)));

  EXPECT_THAT(expected, testing::ContainerEq(map.range_pairs()));
}

TEST(AddressRangeMapTest, OutOfOrderPush) {
  IntegerRangeMap map;
  EXPECT_EQ(0u, map.size());

  EXPECT_TRUE(map.Push(IntegerRange(20, 10), IntegerRange(1020, 10)));
  EXPECT_EQ(1u, map.size());

  EXPECT_FALSE(map.Push(IntegerRange(0, 10), IntegerRange(1000, 10)));
  EXPECT_EQ(1u, map.size());

  IntegerRangePairs expected;
  expected.push_back(
      IntegerRangePair(IntegerRange(20, 10), IntegerRange(1020, 10)));

  EXPECT_THAT(expected, testing::ContainerEq(map.range_pairs()));
}

TEST(AddressRangeMapTest, InOrderPushAndMerge) {
  IntegerRangeMap map;
  EXPECT_EQ(0u, map.size());

  EXPECT_TRUE(map.Push(IntegerRange(0, 10), IntegerRange(1000, 10)));
  EXPECT_EQ(1u, map.size());

  EXPECT_TRUE(map.Push(IntegerRange(10, 10), IntegerRange(1010, 10)));
  EXPECT_EQ(1u, map.size());

  IntegerRangePairs expected;
  expected.push_back(
      IntegerRangePair(IntegerRange(0, 20), IntegerRange(1000, 20)));

  EXPECT_THAT(expected, testing::ContainerEq(map.range_pairs()));
}

TEST(AddressRangeMapTest, Insert) {
  IntegerRangeMap map;
  EXPECT_EQ(0u, map.size());

  EXPECT_TRUE(map.Insert(IntegerRange(20, 10), IntegerRange(1020, 10)));
  EXPECT_EQ(1u, map.size());

  EXPECT_TRUE(map.Insert(IntegerRange(0, 10), IntegerRange(1000, 10)));
  EXPECT_EQ(2u, map.size());

  EXPECT_TRUE(map.Insert(IntegerRange(40, 10), IntegerRange(1040, 10)));
  EXPECT_EQ(3u, map.size());

  // Attempting to insert a subset of an existing range should fail.
  EXPECT_FALSE(map.Insert(IntegerRange(5, 2), IntegerRange(1005, 2)));
  EXPECT_EQ(3u, map.size());

  // Attempting to insert an existing range should fail.
  EXPECT_FALSE(map.Insert(IntegerRange(0, 10), IntegerRange(1000, 10)));
  EXPECT_EQ(3u, map.size());

  // Attempting to insert an overlapping range should fail.
  EXPECT_FALSE(map.Insert(IntegerRange(5, 10), IntegerRange(1005, 10)));
  EXPECT_EQ(3u, map.size());

  // Inserting a contiguous range at end should merge with previous.
  EXPECT_TRUE(map.Insert(IntegerRange(50, 10), IntegerRange(1050, 10)));
  EXPECT_EQ(3u, map.size());

  // Inserting empty ranges should do nothing.
  EXPECT_FALSE(map.Insert(IntegerRange(0, 0), IntegerRange(1000, 1)));
  EXPECT_FALSE(map.Insert(IntegerRange(0, 1), IntegerRange(1000, 0)));
  EXPECT_EQ(3u, map.size());

  IntegerRangePairs expected;
  expected.push_back(
      IntegerRangePair(IntegerRange(0, 10), IntegerRange(1000, 10)));
  expected.push_back(
      IntegerRangePair(IntegerRange(20, 10), IntegerRange(1020, 10)));
  expected.push_back(
      IntegerRangePair(IntegerRange(40, 20), IntegerRange(1040, 20)));

  EXPECT_THAT(expected, testing::ContainerEq(map.range_pairs()));
}

TEST(AddressRangeMapTest, InsertAndLeftMerge) {
  IntegerRangeMap map;
  EXPECT_EQ(0u, map.size());

  EXPECT_TRUE(map.Insert(IntegerRange(20, 10), IntegerRange(1020, 10)));
  EXPECT_EQ(1u, map.size());

  EXPECT_TRUE(map.Insert(IntegerRange(0, 10), IntegerRange(1000, 10)));
  EXPECT_EQ(2u, map.size());

  EXPECT_TRUE(map.Insert(IntegerRange(10, 5), IntegerRange(1010, 5)));
  EXPECT_EQ(2u, map.size());

  IntegerRangePairs expected;
  expected.push_back(
      IntegerRangePair(IntegerRange(0, 15), IntegerRange(1000, 15)));
  expected.push_back(
      IntegerRangePair(IntegerRange(20, 10), IntegerRange(1020, 10)));

  EXPECT_THAT(expected, testing::ContainerEq(map.range_pairs()));
}

TEST(AddressRangeMapTest, InsertAndRightMerge) {
  IntegerRangeMap map;
  EXPECT_EQ(0u, map.size());

  EXPECT_TRUE(map.Insert(IntegerRange(20, 10), IntegerRange(1020, 10)));
  EXPECT_EQ(1u, map.size());

  EXPECT_TRUE(map.Insert(IntegerRange(0, 10), IntegerRange(1000, 10)));
  EXPECT_EQ(2u, map.size());

  EXPECT_TRUE(map.Insert(IntegerRange(15, 5), IntegerRange(1015, 5)));
  EXPECT_EQ(2u, map.size());

  IntegerRangePairs expected;
  expected.push_back(
      IntegerRangePair(IntegerRange(0, 10), IntegerRange(1000, 10)));
  expected.push_back(
      IntegerRangePair(IntegerRange(15, 15), IntegerRange(1015, 15)));

  EXPECT_THAT(expected, testing::ContainerEq(map.range_pairs()));
}

TEST(AddressRangeMapTest, InsertAndDoubleMerge) {
  IntegerRangeMap map;
  EXPECT_EQ(0u, map.size());

  EXPECT_TRUE(map.Insert(IntegerRange(20, 10), IntegerRange(1020, 10)));
  EXPECT_EQ(1u, map.size());

  EXPECT_TRUE(map.Insert(IntegerRange(0, 10), IntegerRange(1000, 10)));
  EXPECT_EQ(2u, map.size());

  EXPECT_TRUE(map.Insert(IntegerRange(10, 10), IntegerRange(1010, 10)));
  EXPECT_EQ(1u, map.size());

  IntegerRangePairs expected;
  expected.push_back(
      IntegerRangePair(IntegerRange(0, 30), IntegerRange(1000, 30)));

  EXPECT_THAT(expected, testing::ContainerEq(map.range_pairs()));
}

TEST(AddressRangeMapTest, Comparison) {
  IntegerRangeMap map1;
  IntegerRangeMap map2;
  EXPECT_TRUE(map1 == map2);
  EXPECT_FALSE(map1 != map2);

  map1.Push(IntegerRange(0, 10), IntegerRange(1000, 10));
  map2.Push(IntegerRange(0, 10), IntegerRange(1000, 10));
  EXPECT_TRUE(map1 == map2);
  EXPECT_FALSE(map1 != map2);

  map1.Push(IntegerRange(20, 10), IntegerRange(1020, 10));
  EXPECT_FALSE(map1 == map2);
  EXPECT_TRUE(map1 != map2);
}

TEST(AddressRangeMapTest, Serialization) {
  IntegerRangeMap map;
  EXPECT_TRUE(map.Push(IntegerRange(0, 10), IntegerRange(1000, 10)));
  EXPECT_TRUE(map.Push(IntegerRange(20, 10), IntegerRange(1020, 10)));
  EXPECT_TRUE(map.Push(IntegerRange(40, 10), IntegerRange(1040, 10)));

  EXPECT_TRUE(testing::TestSerialization(map));
}

TEST(AddressRangeMapTest, Clear) {
  IntegerRangeMap map;
  ASSERT_TRUE(map.Push(IntegerRange(0, 10), IntegerRange(1000, 10)));

  map.clear();
  EXPECT_EQ(0u, map.size());
}

TEST(AddressRangeMapTest, ComputeInverse) {
  IntegerRangeMap map;
  ASSERT_TRUE(map.Push(IntegerRange(0, 10), IntegerRange(1020, 10)));
  ASSERT_TRUE(map.Push(IntegerRange(20, 10), IntegerRange(1000, 10)));

  IntegerRangePairs expected;
  expected.push_back(
      IntegerRangePair(IntegerRange(1000, 10), IntegerRange(20, 10)));
  expected.push_back(
      IntegerRangePair(IntegerRange(1020, 10), IntegerRange(0, 10)));

  IntegerRangeMap imap;
  EXPECT_EQ(0u, map.ComputeInverse(&imap));
  EXPECT_THAT(expected, testing::ContainerEq(imap.range_pairs()));

  IntegerRangeMap iimap;
  EXPECT_EQ(0u, imap.ComputeInverse(&iimap));
  EXPECT_EQ(map, iimap);

  // Test in-place inversion.
  EXPECT_EQ(0u, iimap.ComputeInverse(&iimap));
  EXPECT_EQ(imap, iimap);
}

TEST(AddressRangeMapTest, ComputeInverseWithConflicts) {
  IntegerRangeMap map;
  ASSERT_TRUE(map.Push(IntegerRange(0, 10), IntegerRange(1000, 10)));
  ASSERT_TRUE(map.Push(IntegerRange(20, 10), IntegerRange(1000, 10)));

  IntegerRangePairs expected;
  expected.push_back(
      IntegerRangePair(IntegerRange(1000, 10), IntegerRange(0, 10)));

  IntegerRangeMap imap;
  EXPECT_EQ(1u, map.ComputeInverse(&imap));
  EXPECT_THAT(expected, testing::ContainerEq(imap.range_pairs()));
}

TEST(AddressRangeMapTest, InsertUnmappedAtStart) {
  IntegerRangeMap map;
  ASSERT_TRUE(map.Push(IntegerRange(0, 10), IntegerRange(1000, 10)));
  ASSERT_TRUE(map.Push(IntegerRange(20, 10), IntegerRange(1020, 10)));

  map.InsertUnmappedRange(IntegerRange(0, 10));
  map.InsertUnmappedRange(IntegerRange(0, 0));

  IntegerRangePairs expected;
  expected.push_back(
      IntegerRangePair(IntegerRange(10, 10), IntegerRange(1000, 10)));
  expected.push_back(
      IntegerRangePair(IntegerRange(30, 10), IntegerRange(1020, 10)));

  EXPECT_THAT(expected, testing::ContainerEq(map.range_pairs()));
}

TEST(AddressRangeMapTest, InsertUnmappedInMiddle) {
  IntegerRangeMap map;
  ASSERT_TRUE(map.Push(IntegerRange(0, 10), IntegerRange(1000, 10)));
  ASSERT_TRUE(map.Push(IntegerRange(20, 10), IntegerRange(1020, 10)));

  map.InsertUnmappedRange(IntegerRange(15, 5));
  map.InsertUnmappedRange(IntegerRange(15, 0));

  IntegerRangePairs expected;
  expected.push_back(
      IntegerRangePair(IntegerRange(0, 10), IntegerRange(1000, 10)));
  expected.push_back(
      IntegerRangePair(IntegerRange(25, 10), IntegerRange(1020, 10)));

  EXPECT_THAT(expected, testing::ContainerEq(map.range_pairs()));
}

TEST(AddressRangeMapTest, InsertUnmappedAfterEnd) {
  IntegerRangeMap map;
  ASSERT_TRUE(map.Push(IntegerRange(0, 10), IntegerRange(1000, 10)));
  ASSERT_TRUE(map.Push(IntegerRange(20, 10), IntegerRange(1020, 10)));

  map.InsertUnmappedRange(IntegerRange(30, 10));
  map.InsertUnmappedRange(IntegerRange(30, 0));

  IntegerRangePairs expected;
  expected.push_back(
      IntegerRangePair(IntegerRange(0, 10), IntegerRange(1000, 10)));
  expected.push_back(
      IntegerRangePair(IntegerRange(20, 10), IntegerRange(1020, 10)));

  EXPECT_THAT(expected, testing::ContainerEq(map.range_pairs()));
}

TEST(AddressRangeMapTest, InsertUnmappedSplit) {
  IntegerRangeMap map;
  ASSERT_TRUE(map.Push(IntegerRange(0, 10), IntegerRange(1000, 10)));

  map.InsertUnmappedRange(IntegerRange(5, 5));
  map.InsertUnmappedRange(IntegerRange(5, 0));

  IntegerRangePairs expected;
  expected.push_back(
      IntegerRangePair(IntegerRange(0, 5), IntegerRange(1000, 5)));
  expected.push_back(
      IntegerRangePair(IntegerRange(10, 5), IntegerRange(1005, 5)));

  EXPECT_THAT(expected, testing::ContainerEq(map.range_pairs()));
}

TEST(AddressRangeMapTest, InsertUnmappedSplitSingleton) {
  IntegerRangeMap map;
  ASSERT_TRUE(map.Push(IntegerRange(0, 2), IntegerRange(1000, 1)));

  map.InsertUnmappedRange(IntegerRange(1, 1));
  map.InsertUnmappedRange(IntegerRange(1, 0));

  IntegerRangePairs expected;
  expected.push_back(
      IntegerRangePair(IntegerRange(0, 1), IntegerRange(1000, 1)));
  expected.push_back(
      IntegerRangePair(IntegerRange(2, 1), IntegerRange(1000, 1)));

  EXPECT_THAT(expected, testing::ContainerEq(map.range_pairs()));
}

TEST(AddressRangeMapTest, RemoveMappedNoData) {
  IntegerRangeMap map;

  map.RemoveMappedRange(IntegerRange(10, 10));
  map.RemoveMappedRange(IntegerRange(10, 0));

  EXPECT_TRUE(map.empty());
}

TEST(AddressRangeMapTest, RemoveMappedEmpty) {
  IntegerRangeMap map;
  ASSERT_TRUE(map.Push(IntegerRange(0, 10), IntegerRange(1000, 10)));
  ASSERT_TRUE(map.Push(IntegerRange(20, 10), IntegerRange(1020, 10)));

  map.RemoveMappedRange(IntegerRange(10, 10));
  map.RemoveMappedRange(IntegerRange(10, 0));

  IntegerRangePairs expected;
  expected.push_back(
      IntegerRangePair(IntegerRange(0, 10), IntegerRange(1000, 10)));
  expected.push_back(
      IntegerRangePair(IntegerRange(10, 10), IntegerRange(1020, 10)));

  EXPECT_THAT(expected, testing::ContainerEq(map.range_pairs()));
}

TEST(AddressRangeMapTest, RemoveMappedNoSplit) {
  IntegerRangeMap map;
  ASSERT_TRUE(map.Push(IntegerRange(0, 10), IntegerRange(1000, 10)));
  ASSERT_TRUE(map.Push(IntegerRange(15, 2), IntegerRange(1015, 2)));
  ASSERT_TRUE(map.Push(IntegerRange(20, 10), IntegerRange(1020, 10)));

  map.RemoveMappedRange(IntegerRange(10, 10));
  map.RemoveMappedRange(IntegerRange(10, 0));

  IntegerRangePairs expected;
  expected.push_back(
      IntegerRangePair(IntegerRange(0, 10), IntegerRange(1000, 10)));
  expected.push_back(
      IntegerRangePair(IntegerRange(10, 10), IntegerRange(1020, 10)));

  EXPECT_THAT(expected, testing::ContainerEq(map.range_pairs()));
}

TEST(AddressRangeMapTest, RemoveMappedSplitLeft) {
  IntegerRangeMap map;
  ASSERT_TRUE(map.Push(IntegerRange(0, 10), IntegerRange(1000, 10)));
  ASSERT_TRUE(map.Push(IntegerRange(20, 10), IntegerRange(1020, 10)));

  map.RemoveMappedRange(IntegerRange(5, 10));
  map.RemoveMappedRange(IntegerRange(5, 0));

  IntegerRangePairs expected;
  expected.push_back(
      IntegerRangePair(IntegerRange(0, 5), IntegerRange(1000, 5)));
  expected.push_back(
      IntegerRangePair(IntegerRange(10, 10), IntegerRange(1020, 10)));

  EXPECT_THAT(expected, testing::ContainerEq(map.range_pairs()));
}

TEST(AddressRangeMapTest, RemoveMappedSplitRight) {
  IntegerRangeMap map;
  ASSERT_TRUE(map.Push(IntegerRange(0, 10), IntegerRange(1000, 10)));
  ASSERT_TRUE(map.Push(IntegerRange(20, 10), IntegerRange(1020, 10)));

  map.RemoveMappedRange(IntegerRange(15, 10));
  map.RemoveMappedRange(IntegerRange(15, 0));

  IntegerRangePairs expected;
  expected.push_back(
      IntegerRangePair(IntegerRange(0, 10), IntegerRange(1000, 10)));
  expected.push_back(
      IntegerRangePair(IntegerRange(15, 5), IntegerRange(1025, 5)));

  EXPECT_THAT(expected, testing::ContainerEq(map.range_pairs()));
}

TEST(AddressRangeMapTest, RemoveMappedSplitBoth) {
  IntegerRangeMap map;
  ASSERT_TRUE(map.Push(IntegerRange(0, 10), IntegerRange(1000, 10)));
  ASSERT_TRUE(map.Push(IntegerRange(20, 10), IntegerRange(1020, 10)));

  map.RemoveMappedRange(IntegerRange(5, 20));
  map.RemoveMappedRange(IntegerRange(5, 0));

  IntegerRangePairs expected;
  expected.push_back(
      IntegerRangePair(IntegerRange(0, 5), IntegerRange(1000, 5)));
  expected.push_back(
      IntegerRangePair(IntegerRange(5, 5), IntegerRange(1025, 5)));

  EXPECT_THAT(expected, testing::ContainerEq(map.range_pairs()));
}

TEST(AddressRangeMapTest, RemoveMappedSplitBothSingleton) {
  IntegerRangeMap map;
  ASSERT_TRUE(map.Push(IntegerRange(0, 10), IntegerRange(1000, 10)));

  map.RemoveMappedRange(IntegerRange(5, 2));
  map.RemoveMappedRange(IntegerRange(5, 0));

  IntegerRangePairs expected;
  expected.push_back(
      IntegerRangePair(IntegerRange(0, 5), IntegerRange(1000, 5)));
  expected.push_back(
      IntegerRangePair(IntegerRange(5, 3), IntegerRange(1007, 3)));

  EXPECT_THAT(expected, testing::ContainerEq(map.range_pairs()));
}

TEST(AddressRangeMapTest, RemoveMappedBeyondEnd) {
  IntegerRangeMap map;
  ASSERT_TRUE(map.Push(IntegerRange(0, 10), IntegerRange(1000, 10)));

  map.RemoveMappedRange(IntegerRange(10, 10));
  map.RemoveMappedRange(IntegerRange(10, 0));

  IntegerRangePairs expected;
  expected.push_back(
      IntegerRangePair(IntegerRange(0, 10), IntegerRange(1000, 10)));

  EXPECT_THAT(expected, testing::ContainerEq(map.range_pairs()));
}

}  // namespace core
