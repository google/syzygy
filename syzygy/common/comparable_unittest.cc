// Copyright 2014 Google Inc. All Rights Reserved.
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

#include "syzygy/common/comparable.h"

#include "gtest/gtest.h"

namespace common {

namespace {

struct TestComparable : public Comparable<TestComparable> {
 public:
  explicit TestComparable(size_t value) : val(value) {
  }

  int Compare(const TestComparable& other) const {
    return val - other.val;
  }

  size_t val;
};

}  // namespace

TEST(ComparableTest, Operators) {
  TestComparable one(1);
  TestComparable one_copy(1);
  TestComparable two(2);
  EXPECT_EQ(one, one_copy);
  EXPECT_NE(one, two);
  EXPECT_LE(one, one_copy);
  EXPECT_LE(one, two);
  EXPECT_LT(one, two);
  EXPECT_GE(one, one_copy);
  EXPECT_GE(two, one);
  EXPECT_GT(two, one);
}

}  // namespace common
