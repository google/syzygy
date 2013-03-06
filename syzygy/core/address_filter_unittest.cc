// Copyright 2013 Google Inc. All Rights Reserved.
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

#include "syzygy/core/address_filter.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/core/address.h"

namespace core {

namespace {

typedef AddressFilter<AbsoluteAddress, size_t> TestAddressFilter;
typedef TestAddressFilter::Range Range;
typedef TestAddressFilter::RangeSet RangeSet;

using testing::ContainerEq;

// A pretty printer for AddressRange. This makes failed unittests readable.
template<typename AddressType, typename SizeType>
std::ostream& operator<<(
    std::ostream& os,
    const core::AddressRange<AddressType, SizeType>& addr_range) {
  os << "AddressRange(" << addr_range.start() << ", " << addr_range.size()
     << ")";
  return os;
}

// A handy little factory.
Range MakeRange(size_t address, size_t size) {
  return Range(AbsoluteAddress(address), size);
}

}  // namespace

TEST(AddressFilterTest, DefaultConstructor) {
  TestAddressFilter f;
  EXPECT_EQ(Range(), f.extent());
  EXPECT_EQ(0u, f.size());

  // Adding a range should be a noop.
  f.Mark(MakeRange(0, 100));
  EXPECT_EQ(0u, f.size());
}

TEST(AddressFilterTest, RangeConstructor) {
  TestAddressFilter f(MakeRange(0, 100));
  EXPECT_EQ(0u, f.size());
  EXPECT_EQ(MakeRange(0, 100), f.extent());
}

TEST(AddressFilterTest, CopyConstructor) {
  TestAddressFilter f(MakeRange(0, 100));
  EXPECT_EQ(0u, f.size());
  EXPECT_EQ(MakeRange(0, 100), f.extent());
  f.Mark(MakeRange(50, 10));
  EXPECT_EQ(1u, f.size());

  TestAddressFilter f2(f);
  EXPECT_EQ(f.size(), f2.size());
  EXPECT_EQ(f.extent(), f2.extent());
  EXPECT_EQ(f.marked_ranges(), f2.marked_ranges());
}

TEST(AddressFilterTest, Assignment) {
  TestAddressFilter f(MakeRange(0, 100));
  EXPECT_EQ(0u, f.size());
  EXPECT_EQ(MakeRange(0, 100), f.extent());
  f.Mark(MakeRange(50, 10));
  EXPECT_EQ(1u, f.size());

  TestAddressFilter f2(MakeRange(0, 10));
  EXPECT_EQ(0u, f2.size());

  f2 = f;
  EXPECT_EQ(f.size(), f2.size());
  EXPECT_EQ(f.extent(), f2.extent());
  EXPECT_EQ(f.marked_ranges(), f2.marked_ranges());
}

TEST(AddressFilterTest, Comparison) {
  TestAddressFilter f(MakeRange(0, 100));

  TestAddressFilter f2(MakeRange(0, 10));
  EXPECT_FALSE(f == f2);
  EXPECT_TRUE(f != f2);

  f2 = f;
  EXPECT_TRUE(f == f2);
  EXPECT_FALSE(f != f2);

  f.Mark(MakeRange(50, 10));
  EXPECT_FALSE(f == f2);
  EXPECT_TRUE(f != f2);

  f2.Mark(MakeRange(50, 10));
  EXPECT_TRUE(f == f2);
  EXPECT_FALSE(f != f2);
}

TEST(AddressFilterTest, Clear) {
  TestAddressFilter f(MakeRange(0, 100));
  EXPECT_EQ(0u, f.size());
  f.Mark(MakeRange(50, 10));
  EXPECT_EQ(1u, f.size());
  f.Clear();
  EXPECT_EQ(0u, f.size());
}

TEST(AddressFilterTest, Empty) {
  TestAddressFilter f(MakeRange(0, 100));
  EXPECT_TRUE(f.empty());
  f.Mark(MakeRange(50, 10));
  EXPECT_FALSE(f.empty());
  f.Mark(MakeRange(70, 10));
  EXPECT_FALSE(f.empty());
}

TEST(AddressFilterTest, MarkOneRangeLeftOfExtent) {
  TestAddressFilter f(MakeRange(10, 100));
  EXPECT_EQ(0u, f.size());
  f.Mark(MakeRange(0, 5));
  EXPECT_EQ(0u, f.size());
}

TEST(AddressFilterTest, MarkOneRangeRightOfExtent) {
  TestAddressFilter f(MakeRange(0, 100));
  EXPECT_EQ(0u, f.size());
  f.Mark(MakeRange(105, 20));
  EXPECT_EQ(0u, f.size());
}

TEST(AddressFilterTest, MarkOneRangeIntersectingLeftOfExtent) {
  TestAddressFilter f(MakeRange(10, 100));
  EXPECT_EQ(0u, f.size());
  f.Mark(MakeRange(0, 20));
  EXPECT_EQ(1u, f.size());

  RangeSet expected;
  expected.insert(MakeRange(10, 10));
  EXPECT_THAT(expected, ContainerEq(f.marked_ranges()));
}

TEST(AddressFilterTest, MarkOneRangeIntersectingRightOfExtent) {
  TestAddressFilter f(MakeRange(0, 100));
  EXPECT_EQ(0u, f.size());
  f.Mark(MakeRange(90, 20));
  EXPECT_EQ(1u, f.size());

  RangeSet expected;
  expected.insert(MakeRange(90, 10));
  EXPECT_THAT(expected, ContainerEq(f.marked_ranges()));
}

TEST(AddressFilterTest, MarkOneRangeInExtent) {
  TestAddressFilter f(MakeRange(0, 100));
  EXPECT_EQ(0u, f.size());
  f.Mark(MakeRange(50, 10));
  EXPECT_EQ(1u, f.size());

  RangeSet expected;
  expected.insert(MakeRange(50, 10));
  EXPECT_THAT(expected, ContainerEq(f.marked_ranges()));
}

TEST(AddressFilterTest, MarkRangeToLeftOfExisting) {
  TestAddressFilter f(MakeRange(0, 100));
  EXPECT_EQ(0u, f.size());
  f.Mark(MakeRange(50, 10));
  EXPECT_EQ(1u, f.size());

  f.Mark(MakeRange(30, 10));
  EXPECT_EQ(2u, f.size());

  RangeSet expected;
  expected.insert(MakeRange(30, 10));
  expected.insert(MakeRange(50, 10));
  EXPECT_THAT(expected, ContainerEq(f.marked_ranges()));
}

TEST(AddressFilterTest, MarkRangeToRightOfExisting) {
  TestAddressFilter f(MakeRange(0, 100));
  EXPECT_EQ(0u, f.size());
  f.Mark(MakeRange(50, 10));
  EXPECT_EQ(1u, f.size());

  f.Mark(MakeRange(70, 10));
  EXPECT_EQ(2u, f.size());

  RangeSet expected;
  expected.insert(MakeRange(50, 10));
  expected.insert(MakeRange(70, 10));
  EXPECT_THAT(expected, ContainerEq(f.marked_ranges()));
}

TEST(AddressFilterTest, MarkLeftInterceptingExisting) {
  TestAddressFilter f(MakeRange(0, 100));
  EXPECT_EQ(0u, f.size());
  f.Mark(MakeRange(50, 10));
  EXPECT_EQ(1u, f.size());

  f.Mark(MakeRange(45, 10));
  EXPECT_EQ(1u, f.size());

  RangeSet expected;
  expected.insert(MakeRange(45, 15));
  EXPECT_THAT(expected, ContainerEq(f.marked_ranges()));
}

TEST(AddressFilterTest, MarkRightInterceptingExisting) {
  TestAddressFilter f(MakeRange(0, 100));
  EXPECT_EQ(0u, f.size());
  f.Mark(MakeRange(50, 10));
  EXPECT_EQ(1u, f.size());

  f.Mark(MakeRange(55, 10));
  EXPECT_EQ(1u, f.size());

  RangeSet expected;
  expected.insert(MakeRange(50, 15));
  EXPECT_THAT(expected, ContainerEq(f.marked_ranges()));
}

TEST(AddressFilterTest, MarkInsideExisting) {
  TestAddressFilter f(MakeRange(0, 100));
  EXPECT_EQ(0u, f.size());
  f.Mark(MakeRange(50, 10));
  EXPECT_EQ(1u, f.size());

  f.Mark(MakeRange(53, 5));
  EXPECT_EQ(1u, f.size());

  RangeSet expected;
  expected.insert(MakeRange(50, 10));
  EXPECT_THAT(expected, ContainerEq(f.marked_ranges()));
}

TEST(AddressFilterTest, MarkSubsumingExisting) {
  TestAddressFilter f(MakeRange(0, 100));
  EXPECT_EQ(0u, f.size());
  f.Mark(MakeRange(50, 10));
  EXPECT_EQ(1u, f.size());

  f.Mark(MakeRange(40, 30));
  EXPECT_EQ(1u, f.size());

  RangeSet expected;
  expected.insert(MakeRange(40, 30));
  EXPECT_THAT(expected, ContainerEq(f.marked_ranges()));
}

TEST(AddressFilterTest, MarkBetweenExisting) {
  TestAddressFilter f(MakeRange(0, 100));
  EXPECT_EQ(0u, f.size());
  f.Mark(MakeRange(50, 10));
  EXPECT_EQ(1u, f.size());

  f.Mark(MakeRange(70, 10));
  EXPECT_EQ(2u, f.size());

  f.Mark(MakeRange(65, 2));
  EXPECT_EQ(3u, f.size());

  RangeSet expected;
  expected.insert(MakeRange(50, 10));
  expected.insert(MakeRange(65, 2));
  expected.insert(MakeRange(70, 10));
  EXPECT_THAT(expected, ContainerEq(f.marked_ranges()));
}

TEST(AddressFilterTest, MarkBetweenExistingInterceptsLeft) {
  TestAddressFilter f(MakeRange(0, 100));
  EXPECT_EQ(0u, f.size());
  f.Mark(MakeRange(50, 10));
  EXPECT_EQ(1u, f.size());

  f.Mark(MakeRange(70, 10));
  EXPECT_EQ(2u, f.size());

  f.Mark(MakeRange(55, 10));
  EXPECT_EQ(2u, f.size());

  RangeSet expected;
  expected.insert(MakeRange(50, 15));
  expected.insert(MakeRange(70, 10));
  EXPECT_THAT(expected, ContainerEq(f.marked_ranges()));
}

TEST(AddressFilterTest, MarkBetweenExistingInterceptsRight) {
  TestAddressFilter f(MakeRange(0, 100));
  EXPECT_EQ(0u, f.size());
  f.Mark(MakeRange(50, 10));
  EXPECT_EQ(1u, f.size());

  f.Mark(MakeRange(70, 10));
  EXPECT_EQ(2u, f.size());

  f.Mark(MakeRange(65, 10));
  EXPECT_EQ(2u, f.size());

  RangeSet expected;
  expected.insert(MakeRange(50, 10));
  expected.insert(MakeRange(65, 15));
  EXPECT_THAT(expected, ContainerEq(f.marked_ranges()));
}

TEST(AddressFilterTest, MarkBetweenExistingInterceptsBoth) {
  TestAddressFilter f(MakeRange(0, 100));
  EXPECT_EQ(0u, f.size());
  f.Mark(MakeRange(50, 10));
  EXPECT_EQ(1u, f.size());

  f.Mark(MakeRange(70, 10));
  EXPECT_EQ(2u, f.size());

  f.Mark(MakeRange(55, 20));
  EXPECT_EQ(1u, f.size());

  RangeSet expected;
  expected.insert(MakeRange(50, 30));
  EXPECT_THAT(expected, ContainerEq(f.marked_ranges()));
}

TEST(AddressFilterTest, MarkSubsumingMultiple) {
  TestAddressFilter f(MakeRange(0, 100));
  EXPECT_EQ(0u, f.size());
  f.Mark(MakeRange(50, 10));
  EXPECT_EQ(1u, f.size());

  f.Mark(MakeRange(70, 10));
  EXPECT_EQ(2u, f.size());

  f.Mark(MakeRange(40, 50));
  EXPECT_EQ(1u, f.size());

  RangeSet expected;
  expected.insert(MakeRange(40, 50));
  EXPECT_THAT(expected, ContainerEq(f.marked_ranges()));
}

TEST(AddressFilterTest, MarkExactlyAlignedAtBeginning) {
  TestAddressFilter f(MakeRange(0, 100));
  EXPECT_EQ(0u, f.size());
  f.Mark(MakeRange(50, 10));
  EXPECT_EQ(1u, f.size());
  f.Mark(MakeRange(0, 50));
  EXPECT_EQ(1u, f.size());

  RangeSet expected;
  expected.insert(MakeRange(0, 60));
  EXPECT_THAT(expected, ContainerEq(f.marked_ranges()));
}

TEST(AddressFilterTest, MarkExactlyAligned) {
  TestAddressFilter f(MakeRange(0, 100));
  EXPECT_EQ(0u, f.size());
  f.Mark(MakeRange(50, 10));
  EXPECT_EQ(1u, f.size());
  f.Mark(MakeRange(60, 10));
  EXPECT_EQ(1u, f.size());

  RangeSet expected;
  expected.insert(MakeRange(50, 20));
  EXPECT_THAT(expected, ContainerEq(f.marked_ranges()));
}

TEST(AddressFilterTest, MarkExactlyBetween) {
  TestAddressFilter f(MakeRange(0, 100));
  EXPECT_EQ(0u, f.size());
  f.Mark(MakeRange(50, 10));
  EXPECT_EQ(1u, f.size());
  f.Mark(MakeRange(70, 10));
  EXPECT_EQ(2u, f.size());
  f.Mark(MakeRange(60, 10));
  EXPECT_EQ(1u, f.size());

  RangeSet expected;
  expected.insert(MakeRange(50, 30));
  EXPECT_THAT(expected, ContainerEq(f.marked_ranges()));
}

TEST(AddressFilterTest, UnmarkLeftOfExtent) {
  TestAddressFilter f(MakeRange(10, 100));
  EXPECT_EQ(0u, f.size());

  f.Unmark(MakeRange(0, 5));
  EXPECT_EQ(0u, f.size());
}

TEST(AddressFilterTest, UnmarkRightOfExtent) {
  TestAddressFilter f(MakeRange(0, 100));
  EXPECT_EQ(0u, f.size());

  f.Unmark(MakeRange(105, 5));
  EXPECT_EQ(0u, f.size());
}

TEST(AddressFilterTest, UnmarkAlreadyUnmarked) {
  TestAddressFilter f(MakeRange(0, 100));
  EXPECT_EQ(0u, f.size());

  f.Mark(MakeRange(50, 10));
  EXPECT_EQ(1u, f.size());
}

TEST(AddressFilterTest, UnmarkExact) {
  TestAddressFilter f(MakeRange(0, 100));
  EXPECT_EQ(0u, f.size());
  f.Mark(MakeRange(50, 10));
  EXPECT_EQ(1u, f.size());

  f.Unmark(MakeRange(50, 10));
  EXPECT_EQ(0u, f.size());
}

TEST(AddressFilterTest, UnmarkSubsuming) {
  TestAddressFilter f(MakeRange(0, 100));
  EXPECT_EQ(0u, f.size());
  f.Mark(MakeRange(50, 10));
  EXPECT_EQ(1u, f.size());

  f.Unmark(MakeRange(45, 20));
  EXPECT_EQ(0u, f.size());
}

TEST(AddressFilterTest, UnmarkLeft) {
  TestAddressFilter f(MakeRange(0, 100));
  EXPECT_EQ(0u, f.size());
  f.Mark(MakeRange(50, 10));
  EXPECT_EQ(1u, f.size());

  f.Unmark(MakeRange(45, 10));
  EXPECT_EQ(1u, f.size());

  RangeSet expected;
  expected.insert(MakeRange(55, 5));
  EXPECT_THAT(expected, ContainerEq(f.marked_ranges()));
}

TEST(AddressFilterTest, UnmarkRight) {
  TestAddressFilter f(MakeRange(0, 100));
  EXPECT_EQ(0u, f.size());
  f.Mark(MakeRange(50, 10));
  EXPECT_EQ(1u, f.size());

  f.Unmark(MakeRange(55, 10));
  EXPECT_EQ(1u, f.size());

  RangeSet expected;
  expected.insert(MakeRange(50, 5));
  EXPECT_THAT(expected, ContainerEq(f.marked_ranges()));
}

TEST(AddressFilterTest, UnmarkSplit) {
  TestAddressFilter f(MakeRange(0, 100));
  EXPECT_EQ(0u, f.size());
  f.Mark(MakeRange(50, 10));
  EXPECT_EQ(1u, f.size());

  f.Unmark(MakeRange(55, 3));
  EXPECT_EQ(2u, f.size());

  RangeSet expected;
  expected.insert(MakeRange(50, 5));
  expected.insert(MakeRange(58, 2));
  EXPECT_THAT(expected, ContainerEq(f.marked_ranges()));
}

TEST(AddressFilterTest, UnmarkMultiple) {
  TestAddressFilter f(MakeRange(0, 100));
  EXPECT_EQ(0u, f.size());
  f.Mark(MakeRange(50, 10));
  EXPECT_EQ(1u, f.size());
  f.Mark(MakeRange(70, 10));
  EXPECT_EQ(2u, f.size());

  f.Unmark(MakeRange(40, 40));
  EXPECT_EQ(0u, f.size());
}

TEST(AddressFilterTest, UnmarkMultipleIntersectLeft) {
  TestAddressFilter f(MakeRange(0, 100));
  EXPECT_EQ(0u, f.size());
  f.Mark(MakeRange(30, 5));
  EXPECT_EQ(1u, f.size());
  f.Mark(MakeRange(40, 5));
  EXPECT_EQ(2u, f.size());
  f.Mark(MakeRange(50, 5));
  EXPECT_EQ(3u, f.size());
  f.Mark(MakeRange(60, 5));
  EXPECT_EQ(4u, f.size());

  f.Unmark(MakeRange(32, 58 - 32));
  EXPECT_EQ(2u, f.size());

  RangeSet expected;
  expected.insert(MakeRange(30, 2));
  expected.insert(MakeRange(60, 5));
  EXPECT_THAT(expected, ContainerEq(f.marked_ranges()));
}

TEST(AddressFilterTest, UnmarkMultipleIntersectRight) {
  TestAddressFilter f(MakeRange(0, 100));
  EXPECT_EQ(0u, f.size());
  f.Mark(MakeRange(30, 5));
  EXPECT_EQ(1u, f.size());
  f.Mark(MakeRange(40, 5));
  EXPECT_EQ(2u, f.size());
  f.Mark(MakeRange(50, 5));
  EXPECT_EQ(3u, f.size());
  f.Mark(MakeRange(60, 5));
  EXPECT_EQ(4u, f.size());

  f.Unmark(MakeRange(38, 62 - 38));
  EXPECT_EQ(2u, f.size());

  RangeSet expected;
  expected.insert(MakeRange(30, 5));
  expected.insert(MakeRange(62, 3));
  EXPECT_THAT(expected, ContainerEq(f.marked_ranges()));
}

TEST(AddressFilterTest, UnmarkMultipleIntersectBothSides) {
  TestAddressFilter f(MakeRange(0, 100));
  EXPECT_EQ(0u, f.size());
  f.Mark(MakeRange(30, 5));
  EXPECT_EQ(1u, f.size());
  f.Mark(MakeRange(40, 5));
  EXPECT_EQ(2u, f.size());
  f.Mark(MakeRange(50, 5));
  EXPECT_EQ(3u, f.size());
  f.Mark(MakeRange(60, 5));
  EXPECT_EQ(4u, f.size());

  f.Unmark(MakeRange(32, 30));
  EXPECT_EQ(2u, f.size());

  RangeSet expected;
  expected.insert(MakeRange(30, 2));
  expected.insert(MakeRange(62, 3));
  EXPECT_THAT(expected, ContainerEq(f.marked_ranges()));
}

TEST(AddressFilterTest, IsMarkedLeftOfExtent) {
  TestAddressFilter f(MakeRange(10, 100));
  EXPECT_EQ(0u, f.size());

  EXPECT_FALSE(f.IsMarked(MakeRange(0, 5)));
}

TEST(AddressFilterTest, IsMarkedRightOfExtent) {
  TestAddressFilter f(MakeRange(0, 100));
  EXPECT_EQ(0u, f.size());

  EXPECT_FALSE(f.IsMarked(MakeRange(105, 5)));
}

TEST(AddressFilterTest, IsMarkedEmptySet) {
  TestAddressFilter f(MakeRange(0, 100));
  EXPECT_EQ(0u, f.size());

  EXPECT_FALSE(f.IsMarked(MakeRange(50, 5)));
}

TEST(AddressFilterTest, IsMarkedLeftIntersect) {
  TestAddressFilter f(MakeRange(0, 100));
  EXPECT_EQ(0u, f.size());
  f.Mark(MakeRange(50, 10));
  EXPECT_EQ(1u, f.size());

  EXPECT_FALSE(f.IsMarked(MakeRange(45, 10)));
}

TEST(AddressFilterTest, IsMarkedRightIntersect) {
  TestAddressFilter f(MakeRange(0, 100));
  EXPECT_EQ(0u, f.size());
  f.Mark(MakeRange(50, 10));
  EXPECT_EQ(1u, f.size());

  EXPECT_FALSE(f.IsMarked(MakeRange(55, 10)));
}

TEST(AddressFilterTest, IsMarkedSubsumes) {
  TestAddressFilter f(MakeRange(0, 100));
  EXPECT_EQ(0u, f.size());
  f.Mark(MakeRange(50, 10));
  EXPECT_EQ(1u, f.size());

  EXPECT_FALSE(f.IsMarked(MakeRange(45, 20)));
}

TEST(AddressFilterTest, IsMarkedExact) {
  TestAddressFilter f(MakeRange(0, 100));
  EXPECT_EQ(0u, f.size());
  f.Mark(MakeRange(50, 10));
  EXPECT_EQ(1u, f.size());

  EXPECT_TRUE(f.IsMarked(MakeRange(50, 10)));
}

TEST(AddressFilterTest, IsMarkedInside) {
  TestAddressFilter f(MakeRange(0, 100));
  EXPECT_EQ(0u, f.size());
  f.Mark(MakeRange(50, 10));
  EXPECT_EQ(1u, f.size());

  EXPECT_TRUE(f.IsMarked(MakeRange(55, 3)));
}

TEST(AddressFilterTest, IsMarkedBetween) {
  TestAddressFilter f(MakeRange(0, 100));
  EXPECT_EQ(0u, f.size());
  f.Mark(MakeRange(50, 10));
  EXPECT_EQ(1u, f.size());
  f.Mark(MakeRange(70, 10));
  EXPECT_EQ(2u, f.size());

  EXPECT_FALSE(f.IsMarked(MakeRange(62, 5)));
}

TEST(AddressFilterTest, IsUnmarkedLeftOfExtent) {
  TestAddressFilter f(MakeRange(10, 100));
  EXPECT_EQ(0u, f.size());

  EXPECT_TRUE(f.IsUnmarked(MakeRange(0, 5)));
}

TEST(AddressFilterTest, IsUnmarkedRightOfExtent) {
  TestAddressFilter f(MakeRange(0, 100));
  EXPECT_EQ(0u, f.size());

  EXPECT_TRUE(f.IsUnmarked(MakeRange(105, 5)));
}

TEST(AddressFilterTest, IsUnmarkedEmptySet) {
  TestAddressFilter f(MakeRange(10, 100));
  EXPECT_EQ(0u, f.size());

  EXPECT_TRUE(f.IsUnmarked(MakeRange(50, 10)));
}

TEST(AddressFilterTest, IsUnmarkedLeftIntersect) {
  TestAddressFilter f(MakeRange(0, 100));
  EXPECT_EQ(0u, f.size());
  f.Mark(MakeRange(50, 10));
  EXPECT_EQ(1u, f.size());

  EXPECT_FALSE(f.IsUnmarked(MakeRange(45, 10)));
}

TEST(AddressFilterTest, IsUnmarkedRightIntersect) {
  TestAddressFilter f(MakeRange(0, 100));
  EXPECT_EQ(0u, f.size());
  f.Mark(MakeRange(50, 10));
  EXPECT_EQ(1u, f.size());

  EXPECT_FALSE(f.IsUnmarked(MakeRange(55, 10)));
}

TEST(AddressFilterTest, IsUnmarkedSubsumes) {
  TestAddressFilter f(MakeRange(0, 100));
  EXPECT_EQ(0u, f.size());
  f.Mark(MakeRange(50, 10));
  EXPECT_EQ(1u, f.size());

  EXPECT_FALSE(f.IsUnmarked(MakeRange(45, 20)));
}

TEST(AddressFilterTest, IsUnmarkedExact) {
  TestAddressFilter f(MakeRange(0, 100));
  EXPECT_EQ(0u, f.size());
  f.Mark(MakeRange(50, 10));
  EXPECT_EQ(1u, f.size());

  EXPECT_FALSE(f.IsUnmarked(MakeRange(50, 10)));
}

TEST(AddressFilterTest, IsUnmarkedInside) {
  TestAddressFilter f(MakeRange(0, 100));
  EXPECT_EQ(0u, f.size());
  f.Mark(MakeRange(50, 10));
  EXPECT_EQ(1u, f.size());

  EXPECT_FALSE(f.IsUnmarked(MakeRange(55, 3)));
}

TEST(AddressFilterTest, IsUnmarkedBetween) {
  TestAddressFilter f(MakeRange(0, 100));
  EXPECT_EQ(0u, f.size());
  f.Mark(MakeRange(50, 10));
  EXPECT_EQ(1u, f.size());
  f.Mark(MakeRange(70, 10));
  EXPECT_EQ(2u, f.size());

  EXPECT_TRUE(f.IsUnmarked(MakeRange(62, 5)));
}

TEST(AddressFilterTest, Invert) {
  TestAddressFilter f(MakeRange(0, 100));
  EXPECT_EQ(0u, f.size());
  f.Mark(MakeRange(50, 10));
  EXPECT_EQ(1u, f.size());
  f.Mark(MakeRange(70, 10));
  EXPECT_EQ(2u, f.size());

  TestAddressFilter fi;
  f.Invert(&fi);
  EXPECT_EQ(f.extent(), fi.extent());
  EXPECT_EQ(3u, fi.size());

  RangeSet expected;
  expected.insert(MakeRange(0, 50));
  expected.insert(MakeRange(60, 10));
  expected.insert(MakeRange(80, 20));
  EXPECT_THAT(expected, ContainerEq(fi.marked_ranges()));

  // Invert in place.
  fi.Invert(&fi);
  EXPECT_EQ(f, fi);
}

TEST(AddressFilterTest, InvertEmpty) {
  TestAddressFilter f(MakeRange(0, 100));
  EXPECT_EQ(0u, f.size());

  f.Invert(&f);
  EXPECT_EQ(1u, f.size());
  EXPECT_EQ(f.extent(), *f.marked_ranges().begin());
}

TEST(AddressFilterTest, EmptyIntersect) {
  TestAddressFilter f1(MakeRange(0, 100));
  EXPECT_EQ(0u, f1.size());

  TestAddressFilter f2(MakeRange(0, 100));
  EXPECT_EQ(0u, f2.size());

  TestAddressFilter f3;
  f1.Intersect(f2, &f3);
  EXPECT_EQ(f1.extent(), f3.extent());
  EXPECT_EQ(0u, f3.size());
}

TEST(AddressFilterTest, IntersectNonOverlappingExtents) {
  TestAddressFilter f1(MakeRange(0, 100));
  EXPECT_EQ(0u, f1.size());

  TestAddressFilter f2(MakeRange(200, 100));
  EXPECT_EQ(0u, f2.size());

  TestAddressFilter f3;
  f1.Intersect(f2, &f3);
  EXPECT_EQ(f1.extent(), f3.extent());
  EXPECT_EQ(0u, f3.size());

  f2.Intersect(f1, &f3);
  EXPECT_EQ(f2.extent(), f3.extent());
  EXPECT_EQ(0u, f3.size());
}

TEST(AddressFilterTest, IntersectIdentity) {
  TestAddressFilter f1(MakeRange(0, 100));
  EXPECT_EQ(0u, f1.size());
  f1.Mark(MakeRange(30, 10));
  f1.Mark(MakeRange(50, 10));
  f1.Mark(MakeRange(90, 10));
  EXPECT_EQ(3u, f1.size());

  TestAddressFilter f2(f1);
  EXPECT_EQ(f1, f2);

  TestAddressFilter f3;
  f1.Intersect(f2, &f3);
  EXPECT_EQ(f1, f3);

  f2.Intersect(f1, &f3);
  EXPECT_EQ(f2, f3);
}

TEST(AddressFilterTest, IntersectInverseIsEmpty) {
  TestAddressFilter f1(MakeRange(0, 100));
  EXPECT_EQ(0u, f1.size());
  f1.Mark(MakeRange(30, 10));
  f1.Mark(MakeRange(50, 10));
  f1.Mark(MakeRange(90, 10));
  EXPECT_EQ(3u, f1.size());

  TestAddressFilter f2;
  f1.Invert(&f2);

  TestAddressFilter f3;
  f1.Intersect(f2, &f3);
  EXPECT_TRUE(f3.empty());
}

TEST(AddressFilterTest, IntersectionIsSymmetric) {
  TestAddressFilter f1(MakeRange(0, 100));
  EXPECT_EQ(0u, f1.size());
  f1.Mark(MakeRange(30, 10));
  f1.Mark(MakeRange(50, 10));
  f1.Mark(MakeRange(90, 10));
  EXPECT_EQ(3u, f1.size());

  TestAddressFilter f2(MakeRange(0, 100));
  EXPECT_EQ(0u, f2.size());
  f2.Mark(MakeRange(0, 10));
  f2.Mark(MakeRange(25, 10));
  f2.Mark(MakeRange(45, 10));
  f2.Mark(MakeRange(85, 15));
  EXPECT_EQ(4u, f2.size());

  TestAddressFilter f3;
  f1.Intersect(f2, &f3);

  TestAddressFilter f4;
  f2.Intersect(f1, &f4);

  EXPECT_EQ(f3, f4);

  RangeSet expected;
  expected.insert(MakeRange(30, 5));
  expected.insert(MakeRange(50, 5));
  expected.insert(MakeRange(90, 10));
  EXPECT_THAT(expected, ContainerEq(f3.marked_ranges()));
}

TEST(AddressFilterTest, UnionInverseIsFull) {
  TestAddressFilter f1(MakeRange(0, 100));
  EXPECT_EQ(0u, f1.size());
  f1.Mark(MakeRange(30, 10));
  f1.Mark(MakeRange(50, 10));
  f1.Mark(MakeRange(90, 10));
  EXPECT_EQ(3u, f1.size());

  TestAddressFilter f2;
  f1.Invert(&f2);

  TestAddressFilter f3;
  f1.Union(f2, &f3);
  EXPECT_FALSE(f3.empty());
  EXPECT_EQ(1u, f3.size());

  RangeSet expected;
  expected.insert(MakeRange(0, 100));
  EXPECT_THAT(expected, ContainerEq(f3.marked_ranges()));
}

TEST(AddressFilterTest, UnionIsSymmetric) {
  TestAddressFilter f1(MakeRange(0, 100));
  EXPECT_EQ(0u, f1.size());
  f1.Mark(MakeRange(30, 10));
  f1.Mark(MakeRange(50, 10));
  f1.Mark(MakeRange(90, 10));
  EXPECT_EQ(3u, f1.size());

  TestAddressFilter f2(MakeRange(0, 100));
  EXPECT_EQ(0u, f2.size());
  f2.Mark(MakeRange(0, 10));
  f2.Mark(MakeRange(25, 10));
  f2.Mark(MakeRange(45, 10));
  f2.Mark(MakeRange(85, 15));
  EXPECT_EQ(4u, f2.size());

  TestAddressFilter f3;
  f1.Union(f2, &f3);

  TestAddressFilter f4;
  f2.Union(f1, &f4);

  EXPECT_EQ(f3, f4);

  RangeSet expected;
  expected.insert(MakeRange(0, 10));
  expected.insert(MakeRange(25, 15));
  expected.insert(MakeRange(45, 15));
  expected.insert(MakeRange(85, 15));
  EXPECT_THAT(expected, ContainerEq(f3.marked_ranges()));
}

TEST(AddressFilterTest, SelfDifferenceIsEmpty) {
  TestAddressFilter f1(MakeRange(0, 100));
  EXPECT_EQ(0u, f1.size());
  f1.Mark(MakeRange(30, 10));
  f1.Mark(MakeRange(50, 10));
  f1.Mark(MakeRange(90, 10));
  EXPECT_EQ(3u, f1.size());

  TestAddressFilter f2(f1);
  TestAddressFilter f3;
  f1.Subtract(f2, &f3);
  EXPECT_TRUE(f3.empty());

  f1.Subtract(f1, &f1);
  EXPECT_TRUE(f1.empty());
}

TEST(AddressFilterTest, Difference) {
  TestAddressFilter f1(MakeRange(0, 100));
  EXPECT_EQ(0u, f1.size());
  f1.Mark(MakeRange(30, 10));
  f1.Mark(MakeRange(50, 10));
  f1.Mark(MakeRange(90, 10));
  EXPECT_EQ(3u, f1.size());

  TestAddressFilter f2(MakeRange(0, 100));
  EXPECT_EQ(0u, f2.size());
  f2.Mark(MakeRange(0, 10));
  f2.Mark(MakeRange(25, 10));
  f2.Mark(MakeRange(45, 10));
  f2.Mark(MakeRange(85, 15));
  EXPECT_EQ(4u, f2.size());

  {
    TestAddressFilter f3;
    f1.Subtract(f2, &f3);

    RangeSet expected;
    expected.insert(MakeRange(35, 5));
    expected.insert(MakeRange(55, 5));
    EXPECT_THAT(expected, ContainerEq(f3.marked_ranges()));
  }

  {
    TestAddressFilter f3;
    f2.Subtract(f1, &f3);

    RangeSet expected;
    expected.insert(MakeRange(0, 10));
    expected.insert(MakeRange(25, 5));
    expected.insert(MakeRange(45, 5));
    expected.insert(MakeRange(85, 5));
    EXPECT_THAT(expected, ContainerEq(f3.marked_ranges()));
  }
}

}  // namespace core
