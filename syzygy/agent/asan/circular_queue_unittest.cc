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

#include "syzygy/agent/asan/circular_queue.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/agent/asan/unittest_util.h"

namespace agent {
namespace asan {

namespace {
  using testing::MockMemoryNotifier;

  using ::testing::_;
  using ::testing::AtLeast;
}

TEST(CircularQueue, MaxCapacity) {
  size_t capacity = 100;
  CircularQueue<int> q(capacity);
  EXPECT_EQ(capacity, q.max_capacity());
}

TEST(CircularQueue, PushIncreasesSize) {
  size_t capacity = 100;
  CircularQueue<int> q(capacity);

  for (size_t i = 0; i < capacity; ++i) {
    EXPECT_EQ(i, q.size());
    q.push(i);
    EXPECT_EQ(i + 1, q.size());
  }
}

TEST(CircularQueue, PopDecreasesSize) {
  size_t capacity = 100;
  CircularQueue<int> q(capacity);

  for (size_t i = 0; i < capacity; ++i) {
    for (size_t j = 0; j < i; ++j)
      q.push(i);
    for (size_t j = 0; j < i; ++j) {
      EXPECT_EQ(i - j, q.size());
      q.pop();
      EXPECT_EQ(i - j - 1, q.size());
    }
  }
}

TEST(CircularQueue, ComplyWithLIFO) {
  size_t capacity = 100;
  CircularQueue<int> q(capacity);

  size_t initial = 10;
  for (size_t i = 0; i < initial; ++i)
    EXPECT_TRUE(q.push(i));

  for (size_t i = initial; i < 1000 * capacity; ++i) {
    EXPECT_TRUE(q.push(i));
    EXPECT_EQ(i - initial, q.front());
    EXPECT_TRUE(q.pop());
  }
}

TEST(CircularQueue, Stress) {
  size_t capacity = 100;
  CircularQueue<int> q(capacity);
  EXPECT_TRUE(q.empty());

  for (size_t i = 0; i < capacity; ++i) {
    for (size_t j = 0; j < i; ++j) {
      EXPECT_TRUE(q.push(i));
      EXPECT_FALSE(q.empty());
    }
    for (size_t j = 0; j < i; ++j) {
      EXPECT_FALSE(q.empty());
      EXPECT_TRUE(q.pop());
    }
    EXPECT_TRUE(q.empty());
  }
  EXPECT_TRUE(q.empty());
}

TEST(CircularQueue, PushWhenFull) {
  size_t capacity = 100;
  CircularQueue<int> q(capacity);
  EXPECT_TRUE(q.empty());

  for (size_t i = 0; i < capacity; ++i) {
    EXPECT_TRUE(q.push(i));
    EXPECT_FALSE(q.empty());
  }

  EXPECT_EQ(capacity, q.size());

  EXPECT_FALSE(q.push(1));
  EXPECT_FALSE(q.push(2));
  EXPECT_FALSE(q.push(3));

  EXPECT_EQ(capacity, q.size());
}

TEST(CircularQueue, PopWhenEmpty) {
  size_t capacity = 100;
  CircularQueue<int> q(capacity);
  EXPECT_FALSE(q.pop());
  EXPECT_TRUE(q.push(0));
  EXPECT_TRUE(q.pop());
  EXPECT_TRUE(q.empty());
}

TEST(CircularQueue, PopUntilEmpty) {
  size_t capacity = 100;
  CircularQueue<int> q(capacity);

  for (size_t i = 0; i < capacity; ++i) {
    EXPECT_TRUE(q.push(i));
    EXPECT_FALSE(q.empty());
  }

  while (q.pop()) { }
  EXPECT_TRUE(q.empty());
  EXPECT_EQ(0u, q.size());
}

TEST(CircularQueue, EmptyAndZeroSize) {
  size_t capacity = 100;
  CircularQueue<int> q(capacity);

  EXPECT_TRUE(q.empty());
  EXPECT_EQ(0u, q.size());

  EXPECT_TRUE(q.push(1));
  EXPECT_TRUE(q.pop());

  EXPECT_TRUE(q.empty());
  EXPECT_EQ(0u, q.size());
}

TEST(CircularQueue, MemoryNotifierIsCalled) {
  MockMemoryNotifier mock_notifier;

  // Should be called by the underlying container.
  EXPECT_CALL(mock_notifier,
    NotifyInternalUse(_, _))
    .Times(AtLeast(1));

  // Ensure no calls to NotifyFutureHeapUse.
  EXPECT_CALL(mock_notifier,
    NotifyFutureHeapUse(_, _))
    .Times(0);

  // Should be called by the underlying container.
  EXPECT_CALL(mock_notifier,
    NotifyReturnedToOS(_, _))
    .Times(AtLeast(1));

  size_t capacity = 100000;
  CircularQueue<int, MemoryNotifierAllocator<int>> q(capacity, &mock_notifier);
  // This should give compilation error.
  // CircularQueue<int> q(capacity, &mock_notifier);
}


}  // namespace asan
}  // namespace agent
