// Copyright 2015 Google Inc. All Rights Reserved.
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

#include "syzygy/refinery/core/address.h"

#include "gtest/gtest.h"

namespace refinery {

TEST(AddressRangeTest, AddressRangeSpans) {
  AddressRange range(80ULL, 16U);

  // No match: candidate range is outside.
  ASSERT_FALSE(range.Spans(AddressRange(73ULL, 5U)));
  ASSERT_FALSE(range.Spans(AddressRange(96ULL, 3U)));

  // No match: candidate range straddles.
  ASSERT_FALSE(range.Spans(AddressRange(75ULL, 10ULL)));
  ASSERT_FALSE(range.Spans(AddressRange(90ULL, 10ULL)));

  // No match: candidate range is a superset.
  ASSERT_FALSE(range.Spans(AddressRange(75ULL, 32ULL)));

  // Match: candidate range is a subset.
  ASSERT_TRUE(range.Spans(AddressRange(84ULL, 4ULL)));
  ASSERT_TRUE(range.Spans(AddressRange(80ULL, 4ULL)));
  ASSERT_TRUE(range.Spans(AddressRange(92ULL, 4ULL)));

  // Match: candidate range is an exact match.
  ASSERT_TRUE(range.Spans(AddressRange(80ULL, 16U)));
}

TEST(AddressRangeTest, AddressRangeIntersects) {
  AddressRange range(80ULL, 16U);

  // No match: candidate range is outside.
  ASSERT_FALSE(range.Intersects(AddressRange(73ULL, 5U)));
  ASSERT_FALSE(range.Intersects(AddressRange(100ULL, 3U)));

  // No match: candidate range is contiguous.
  ASSERT_FALSE(range.Intersects(AddressRange(75ULL, 5U)));
  ASSERT_FALSE(range.Intersects(AddressRange(96ULL, 3U)));

  // Match: candidate range straddles.
  ASSERT_TRUE(range.Intersects(AddressRange(75ULL, 10ULL)));
  ASSERT_TRUE(range.Intersects(AddressRange(90ULL, 10ULL)));

  // Match: candidate range is a subset.
  ASSERT_TRUE(range.Intersects(AddressRange(84ULL, 4ULL)));

  // Match: candidate range is a superset.
  ASSERT_TRUE(range.Intersects(AddressRange(75ULL, 32ULL)));

  // Match: candidate range is exact match.
  ASSERT_TRUE(range.Intersects(AddressRange(80ULL, 16U)));
}

}  // namespace refinery
