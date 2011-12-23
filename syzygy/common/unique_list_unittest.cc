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
//
// Unit-tests for a templatized non-mapping container that enforces that
// each member is unique.

#include "syzygy/common/unique_list.h"

#include <algorithm>
#include <functional>

#include "base/basictypes.h"
#include "gtest/gtest.h"

namespace common {

namespace {

typedef UniqueList<int> UniqueIntList;

const int kValues[] = { 5, 3, 4, 1, 2, 5, 3, 4, 1, 2 };
const size_t kNumValues = arraysize(kValues);
const size_t kNumUniqueValues = 5;
const int* const kValuesBegin = &kValues[0];
const int* const kValuesEnd = kValuesBegin + kNumValues;



}  // namespace

TEST(UniqueListTest, Constructors) {
  UniqueIntList ul(kValuesBegin, kValuesEnd);
  ASSERT_EQ(kNumUniqueValues, ul.size());
  const int* value = kValuesBegin;
  for (UniqueIntList::iterator it = ul.begin(); it != ul.end(); ++it, ++value) {
    EXPECT_EQ(*value, *it);
  }
}

TEST(UniqueListTest, Insert) {
  UniqueIntList ul;
  ASSERT_NE(ul.end(), ul.insert(ul.begin(), *kValuesBegin));
  ASSERT_EQ(1, ul.size());
  ul.insert(ul.end(), kValuesBegin, kValuesEnd);
  ASSERT_EQ(kNumUniqueValues, ul.size());
  const int* value = kValuesBegin;
  for (UniqueIntList::iterator it = ul.begin(); it != ul.end(); ++it, ++value) {
    EXPECT_EQ(*value, *it);
  }
}

TEST(UniqueListTest, PushBack) {
  UniqueIntList ul;

  ASSERT_EQ(0, ul.size());
  ASSERT_TRUE(ul.push_back(1));
  ASSERT_TRUE(ul.push_back(2));
  ASSERT_EQ(2, ul.size());
  ASSERT_FALSE(ul.push_back(2));
  ASSERT_EQ(2, ul.size());

  ASSERT_EQ(1, ul.front());
  ASSERT_EQ(2, ul.back());

  for (const int* value = kValuesBegin; value != kValuesEnd; ++value) {
    ul.push_back(*value);
  }

  ASSERT_EQ(kNumUniqueValues, ul.size());
}

TEST(UniqueListTest, PopBack) {
  UniqueIntList ul(kValuesBegin, kValuesEnd);

  ASSERT_EQ(kNumUniqueValues, ul.size());
  ASSERT_EQ(*(kValuesBegin + kNumUniqueValues - 1), ul.back());
  ul.pop_back();
  ASSERT_EQ(kNumUniqueValues - 1, ul.size());
  ASSERT_EQ(*(kValuesBegin + kNumUniqueValues - 2), ul.back());
}

TEST(UniqueListTest, PushFront) {
  UniqueIntList ul;

  ASSERT_EQ(0, ul.size());
  ASSERT_TRUE(ul.push_front(1));
  ASSERT_TRUE(ul.push_front(2));
  ASSERT_EQ(2, ul.size());
  ASSERT_FALSE(ul.push_front(2));
  ASSERT_EQ(2, ul.size());

  ASSERT_EQ(1, ul.back());
  ASSERT_EQ(2, ul.front());

  for (const int* value = kValuesBegin; value != kValuesEnd; ++value) {
    ul.push_front(*value);
  }

  ASSERT_EQ(kNumUniqueValues, ul.size());
}

TEST(UniqueListTest, PopFront) {
  UniqueIntList ul(kValuesBegin, kValuesEnd);

  ASSERT_EQ(kNumUniqueValues, ul.size());
  ASSERT_EQ(*kValuesEnd, ul.front());
  ul.pop_front();
  ASSERT_EQ(kNumUniqueValues - 1, ul.size());
  ASSERT_EQ(*(kValuesBegin + 1), ul.front());
}

TEST(UniqueListTest, Resize) {
  UniqueIntList ul(kValuesBegin, kValuesEnd);
  ASSERT_EQ(kNumUniqueValues, ul.size());
  int removed_value = ul.back();
  ASSERT_TRUE(ul.resize(kNumUniqueValues - 1));
  ASSERT_EQ(kNumUniqueValues - 1, ul.size());
  ASSERT_FALSE(ul.contains(removed_value));
}

TEST(UniqueListTest, Assign) {
  UniqueIntList ul;

  ASSERT_TRUE(ul.push_back(6));
  ASSERT_EQ(1, ul.size());

  ul.assign(kValuesBegin, kValuesEnd);
  ASSERT_EQ(kNumUniqueValues, ul.size());
  ASSERT_FALSE(ul.contains(6));
}

TEST(UniqueListTest, Erase) {
  UniqueIntList ul(kValuesBegin, kValuesEnd);

  ASSERT_EQ(kNumUniqueValues, ul.size());

  // Remove one of the values.
  UniqueIntList::iterator it = ul.begin();
  ++it;
  ++it;
  int removed_value = *it;
  ASSERT_NE(ul.end(), ul.erase(it));
  ASSERT_EQ(kNumUniqueValues - 1, ul.size());

  // Verify the values are as we expect.
  const int* value = kValuesBegin;
  for (UniqueIntList::iterator it = ul.begin(); it != ul.end(); ++it, ++value) {
    if (*value == removed_value) {
      // Skip the removed value.
      ++value;
    }
    EXPECT_EQ(*value, *it);
  }
}

TEST(UniqueListTest, EraseRange) {
  UniqueIntList ul(kValuesBegin, kValuesEnd);
  ASSERT_EQ(kNumUniqueValues, ul.size());

  ul.erase(++ul.begin(), ul.end());
  ASSERT_EQ(1, ul.size());
  ASSERT_EQ(*kValuesBegin, ul.front());
}

TEST(UniqueListTest, Clear) {
  UniqueIntList ul(kValuesBegin, kValuesEnd);
  ASSERT_EQ(kNumUniqueValues, ul.size());

  ul.clear();
  ASSERT_EQ(0, ul.size());
}

TEST(UniqueListTest, Swap) {
  UniqueIntList list1(kValuesBegin, kValuesEnd);
  UniqueIntList list2;

  ASSERT_EQ(kNumUniqueValues, list1.size());
  ASSERT_EQ(0, list2.size());

  list1.swap(list2);

  ASSERT_EQ(0, list1.size());
  ASSERT_EQ(kNumUniqueValues, list2.size());
}

TEST(UniqueListTest, Sort) {
  UniqueIntList ul(kValuesBegin, kValuesEnd);

  EXPECT_EQ(kNumUniqueValues, ul.size());

  // The container should not be sorted.
  EXPECT_NE(ul.end(),
            std::adjacent_find(ul.begin(), ul.end(), std::greater<int>()));

  ul.sort();

  // Now the container should be sorted.
  EXPECT_EQ(ul.end(),
            std::adjacent_find(ul.begin(), ul.end(), std::greater<int>()));
}

TEST(UniqueListTest, Reverse) {
  UniqueIntList ul(kValuesBegin, kValuesEnd);

  EXPECT_EQ(kNumUniqueValues, ul.size());
  ul.sort();

  // The container should be sorted in increasing order.
  EXPECT_EQ(ul.end(),
            std::adjacent_find(ul.begin(), ul.end(), std::greater<int>()));

  ul.reverse();

  // The container should now be sorted in decreasing order.
  EXPECT_EQ(ul.end(),
            std::adjacent_find(ul.begin(), ul.end(), std::less<int>()));
}

TEST(UniqueListTest, Splice) {
  UniqueIntList list1(kValuesBegin, kValuesEnd);
  UniqueIntList list2;

  ASSERT_EQ(kNumUniqueValues, list1.size());
  ASSERT_EQ(0, list2.size());

  list2.splice(list2.begin(), list1);

  ASSERT_EQ(0, list1.size());
  ASSERT_EQ(kNumUniqueValues, list2.size());

  list1.splice(list1.begin(), list2, list2.begin());

  ASSERT_EQ(1, list1.size());
  ASSERT_EQ(kNumUniqueValues - 1, list2.size());
}

TEST(UniqueListTest, Remove) {
  const int kValueToRemove = 3;
  UniqueIntList list(kValuesBegin, kValuesEnd);
  ASSERT_EQ(kNumUniqueValues, list.size());
  ASSERT_TRUE(list.contains(kValueToRemove));
  list.remove(kValueToRemove);
  ASSERT_EQ(kNumUniqueValues - 1, list.size());
  ASSERT_FALSE(list.contains(kValueToRemove));
}

TEST(UniqueListTest, RemoveIf) {
  const int kValueToRemove = 3;
  UniqueIntList list(kValuesBegin, kValuesEnd);
  ASSERT_EQ(kNumUniqueValues, list.size());
  ASSERT_TRUE(list.contains(kValueToRemove));
  list.remove_if(std::bind1st(std::equal_to<int>(), kValueToRemove));
  ASSERT_EQ(kNumUniqueValues - 1, list.size());
  ASSERT_FALSE(list.contains(kValueToRemove));
}

}  // namespace common
