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

#include "syzygy/agent/asan/heaps/win_heap.h"

#include "gtest/gtest.h"

namespace agent {
namespace asan {
namespace heaps {

namespace {

class TestWinHeap : public WinHeap {
 public:
  using WinHeap::heap_lock_held_;
};

}  // namespace

TEST(WinHeapTest, GetHeapTypeIsValid) {
  WinHeap h;
  EXPECT_EQ(kWinHeap, h.GetHeapType());
}

TEST(WinHeapTest, FeaturesAreValid) {
  WinHeap h;
  EXPECT_EQ(WinHeap::kHeapSupportsGetAllocationSize,
            h.GetHeapFeatures());
}

TEST(WinHeapTest, HeapTest) {
  WinHeap h;

  // Allocate and free a zero-sized allocation. This should succeed
  // by definition.
  void* alloc = h.Allocate(0);
  EXPECT_TRUE(h.Free(alloc));

  // Make a bunch of different sized allocations.
  std::set<void*> allocs;
  for (uint32_t i = 1; i < 1024 * 1024; i <<= 1) {
    void* alloc = h.Allocate(i);
    allocs.insert(alloc);
  }

  // Now free them.
  std::set<void*>::const_iterator it = allocs.begin();
  for (; it != allocs.end(); ++it)
    EXPECT_TRUE(h.Free(*it));
}

TEST(WinHeapTest, GetAllocationSize) {
  WinHeap h;

  void* alloc = h.Allocate(67);
  ASSERT_TRUE(alloc != NULL);
  EXPECT_EQ(67u, h.GetAllocationSize(alloc));
}

TEST(WinHeapTest, Lock) {
  TestWinHeap h;

  EXPECT_FALSE(h.heap_lock_held_);
  h.Lock();
  EXPECT_TRUE(h.heap_lock_held_);

  // TryLock does not acquire the underlying heap lock, as there's no
  // 'try' functionality for it.
  EXPECT_TRUE(h.TryLock());
  EXPECT_TRUE(h.heap_lock_held_);
  h.Unlock();
  EXPECT_TRUE(h.heap_lock_held_);
  h.Unlock();
  EXPECT_FALSE(h.heap_lock_held_);
}

}  // namespace heaps
}  // namespace asan
}  // namespace agent
