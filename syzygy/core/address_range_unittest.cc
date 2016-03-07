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
#include "syzygy/core/address_range.h"

#include <limits>
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"

namespace core {

typedef AddressRange<const uint8_t*, size_t> PointerRange;
typedef AddressRange<size_t, size_t> IntegerRange;

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

}  // namespace

TEST(AddressRangeTest, Create) {
  PointerRange pointer_range1(nullptr, std::numeric_limits<size_t>::max());
  IntegerRange integer_range1(0, std::numeric_limits<size_t>::max());

  PointerRange pointer_range2(nullptr, 0);
  IntegerRange integer_range2(0, 0);
}

TEST(AddressRangeTest, IsEmtpy) {
  PointerRange pointer_range1(nullptr, 0);
  EXPECT_TRUE(pointer_range1.IsEmpty());

  PointerRange pointer_range2(nullptr, 1);
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

TEST(AddressRangeTest, Offset) {
  EXPECT_EQ(IntegerRange(100, 20).Offset(40).start(), 140);

  AddressRange<uint32_t*, size_t> pointer_range(nullptr, 20);
  EXPECT_EQ(pointer_range.Offset(40).start(), pointer_range.start() + 40);
}

}  // namespace core
