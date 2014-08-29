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

#include "syzygy/agent/asan/heaps/internal_heap.h"

#include "gtest/gtest.h"
#include "syzygy/agent/asan/unittest_util.h"
#include "syzygy/agent/asan/heaps/ctmalloc_heap.h"
#include "syzygy/agent/asan/heaps/win_heap.h"

namespace agent {
namespace asan {
namespace heaps {

namespace {

using testing::_;
using testing::Return;

}  // namespace

TEST(InternalHeapTest, EndToEnd) {
  memory_notifiers::NullMemoryNotifier mock_notifier;
  WinHeap win_heap;
  InternalHeap h(&mock_notifier, &win_heap);

  // Allocate and free a zero-sized allocation. This should succeed
  // by definition.
  void* alloc = h.Allocate(0);
  EXPECT_TRUE(h.Free(alloc));

  // Make a bunch of different sized allocations.
  std::set<void*> allocs;
  for (size_t i = 1; i < 1024 * 1024; i <<= 1) {
    void* alloc = h.Allocate(i);
    allocs.insert(alloc);
  }

  // Now free them.
  std::set<void*>::const_iterator it = allocs.begin();
  for (; it != allocs.end(); ++it)
    EXPECT_TRUE(h.Free(*it));
}

TEST(InternalHeapTest, GetAllocationSize) {
  memory_notifiers::NullMemoryNotifier mock_notifier;
  testing::DummyHeap heap;
  InternalHeap h(&mock_notifier, &heap);

  void* alloc = h.Allocate(67);
  ASSERT_TRUE(alloc != NULL);
  EXPECT_EQ(common::AlignUp(67u, kShadowRatio), h.GetAllocationSize(alloc));
}

TEST(InternalHeapTest, NotificationsWorkWithNonNotifyingHeap) {
  testing::MockMemoryNotifier mock_notifier;
  WinHeap win_heap;
  InternalHeap h(&mock_notifier, &win_heap);

  EXPECT_CALL(mock_notifier, NotifyInternalUse(_, 16)).Times(1);
  EXPECT_CALL(mock_notifier, NotifyReturnedToOS(_, 16)).Times(1);
  void* alloc = h.Allocate(8);
  h.Free(alloc);
}

TEST(InternalHeapTest, NotificationsWorkWithNotifyingHeap) {
  memory_notifiers::NullMemoryNotifier null_notifier;
  testing::MockMemoryNotifier mock_notifier;
  CtMallocHeap ctmalloc_heap(&null_notifier);
  InternalHeap h(&mock_notifier, &ctmalloc_heap);

  EXPECT_CALL(mock_notifier, NotifyInternalUse(_, 16)).Times(1);
  EXPECT_CALL(mock_notifier, NotifyFutureHeapUse(_, 16)).Times(1);
  void* alloc = h.Allocate(8);
  h.Free(alloc);
}

TEST(InternalHeapTest, HeaderIsAllocated) {
  memory_notifiers::NullMemoryNotifier null_notifier;
  testing::MockHeap mock_heap;
  uint8 dummy_allocation[16] = {};

  EXPECT_CALL(mock_heap, GetHeapFeatures()).Times(1).WillOnce(Return(0));
  InternalHeap h(&null_notifier, &mock_heap);

  void* header = dummy_allocation;
  void* expected_alloc = dummy_allocation + sizeof(uint32);

  EXPECT_CALL(mock_heap, Allocate(16)).Times(1).WillOnce(Return(header));
  void* alloc = h.Allocate(8);
  EXPECT_EQ(expected_alloc, alloc);
  EXPECT_EQ(16, *reinterpret_cast<uint32*>(dummy_allocation));

  EXPECT_CALL(mock_heap, Free(header)).Times(1).WillOnce(Return(true));
  EXPECT_TRUE(h.Free(alloc));
}

}  // namespace heaps
}  // namespace asan
}  // namespace agent
