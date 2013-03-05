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

TEST(AddressFilterTest, Constructor) {
  TestAddressFilter f(MakeRange(0, 100));
  EXPECT_EQ(0u, f.size());
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

}  // namespace core
