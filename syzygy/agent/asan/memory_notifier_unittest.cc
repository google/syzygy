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

#include "syzygy/agent/asan/memory_notifier.h"

#include <set>
#include <utility>

#include "base/basictypes.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace agent {
namespace asan {

namespace {

class DummyMemoryNotifier : public MemoryNotifierInterface {
 public:
  typedef std::pair<const void*, size_t> MemoryRange;
  typedef std::set<MemoryRange> MemoryRangeSet;

  DummyMemoryNotifier()
      : internal_used_(0), future_used_(0) {
  }

  virtual ~DummyMemoryNotifier() { }

  virtual void NotifyInternalUse(const void* address, size_t size) {
    MemoryRange range(address, size);
    ASSERT_TRUE(internal_.find(range) == internal_.end());
    ASSERT_TRUE(future_.find(range) == future_.end());
    internal_used_ += size;
    internal_.insert(range);
  }

  virtual void NotifyFutureHeapUse(const void* address, size_t size) {
    MemoryRange range(address, size);
    ASSERT_TRUE(internal_.find(range) == internal_.end());
    ASSERT_TRUE(future_.find(range) == future_.end());
    future_used_ += size;
    future_.insert(range);
  }

  virtual void NotifyReturnedToOS(const void* address, size_t size) {
    MemoryRange range(address, size);
    size_t count_internal = internal_.erase(range);
    size_t count_future = future_.erase(range);
    ASSERT_EQ(1u, count_internal + count_future);
    if (count_internal) {
      internal_used_ -= size;
      ASSERT_LE(0u, internal_used_);
    }
    if (count_future) {
      future_used_ -= size;
      ASSERT_LE(0u, future_used_);
    }
  }

  size_t internal_used_;
  size_t future_used_;
  MemoryRangeSet internal_;
  MemoryRangeSet future_;
};

typedef DummyMemoryNotifier::MemoryRange MemoryRange;

}  // namespace

TEST(MemoryNotifierAllocatorTest, ConstructorsWorkAsExpected) {
  DummyMemoryNotifier n;

  MemoryNotifierAllocator<uint32> a1(&n);
  EXPECT_EQ(&n, a1.memory_notification());

  MemoryNotifierAllocator<uint32> a2(a1);
  EXPECT_EQ(&n, a2.memory_notification());

  MemoryNotifierAllocator<uint16> a3(a1);
  EXPECT_EQ(&n, a3.memory_notification());
}

TEST(MemoryNotifierAllocatorTest, NotifiesInternalUse) {
  DummyMemoryNotifier n;
  MemoryNotifierAllocator<uint32> a1(&n);
  MemoryNotifierAllocator<uint16> a2(a1);

  EXPECT_EQ(0u, n.internal_.size());
  EXPECT_EQ(0u, n.future_.size());

  uint32* ui32 = a1.allocate(10);
  EXPECT_EQ(1u, n.internal_.size());
  EXPECT_EQ(0u, n.future_.size());
  EXPECT_THAT(n.internal_,
              testing::UnorderedElementsAre(MemoryRange(ui32, 40)));

  uint16* ui16 = a2.allocate(8);
  EXPECT_EQ(2u, n.internal_.size());
  EXPECT_EQ(0u, n.future_.size());
  EXPECT_THAT(n.internal_,
              testing::UnorderedElementsAre(MemoryRange(ui32, 40),
                                            MemoryRange(ui16, 16)));

  a1.deallocate(ui32, 10);
  EXPECT_EQ(1u, n.internal_.size());
  EXPECT_EQ(0u, n.future_.size());
  EXPECT_THAT(n.internal_,
              testing::UnorderedElementsAre(MemoryRange(ui16, 16)));

  a2.deallocate(ui16, 8);
  EXPECT_EQ(0u, n.internal_.size());
  EXPECT_EQ(0u, n.future_.size());
}

TEST(MemoryNotifierAllocatorTest, StlContainerStressTest) {
  DummyMemoryNotifier n;
  typedef std::set<uint32,
                   std::less<uint32>,
                   MemoryNotifierAllocator<uint32>> DummySet;
  MemoryNotifierAllocator<uint32> a(&n);
  DummySet s(a);

  for (size_t i = 0; i < 10000; ++i) {
    uint32 j = ::rand() % 2000;
    s.insert(j);
  }

  for (size_t i = 0; i < 1500; ++i) {
    uint32 j = ::rand() % 2000;
    s.erase(j);
  }

  s.clear();
}

}  // namespace asan
}  // namespace agent
