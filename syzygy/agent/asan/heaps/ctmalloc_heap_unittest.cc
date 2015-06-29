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

#include "syzygy/agent/asan/heaps/ctmalloc_heap.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/agent/asan/unittest_util.h"
#include "syzygy/agent/asan/heaps/win_heap.h"

namespace agent {
namespace asan {
namespace heaps {

TEST(CtMallocHeapTest, GetHeapTypeIsValid) {
  testing::NullMemoryNotifier n;
  CtMallocHeap h(&n);
  EXPECT_EQ(kCtMallocHeap, h.GetHeapType());
}

TEST(CtMallocHeapTest, FeaturesAreValid) {
  testing::NullMemoryNotifier n;
  CtMallocHeap h(&n);
  EXPECT_EQ(CtMallocHeap::kHeapReportsReservations |
                CtMallocHeap::kHeapSupportsIsAllocated |
                CtMallocHeap::kHeapSupportsGetAllocationSize |
                CtMallocHeap::kHeapGetAllocationSizeIsUpperBound,
            h.GetHeapFeatures());
}

TEST(CtMallocHeapTest, HeapTest) {
  testing::NullMemoryNotifier n;
  CtMallocHeap h(&n);

  // Allocate and free a zero-sized allocation. This should succeed
  // by definition.
  void* alloc = h.Allocate(0);
  EXPECT_EQ(0u, reinterpret_cast<uintptr_t>(alloc) % kShadowRatio);
  EXPECT_TRUE(h.Free(alloc));

  // Make a bunch of different sized allocations.
  std::set<void*> allocs;
  for (size_t i = 1; i < 1024 * 1024; i <<= 1) {
    void* alloc = h.Allocate(i);
    EXPECT_EQ(0u, reinterpret_cast<uintptr_t>(alloc) % kShadowRatio);
    allocs.insert(alloc);
  }

  // Now free them.
  std::set<void*>::const_iterator it = allocs.begin();
  for (; it != allocs.end(); ++it)
    EXPECT_TRUE(h.Free(*it));
}

TEST(CtMallocHeapTest, ZeroSizedAllocationsHaveDistinctAddresses) {
  testing::NullMemoryNotifier n;
  CtMallocHeap h(&n);

  void* a1 = h.Allocate(0);
  EXPECT_TRUE(a1 != NULL);
  void* a2 = h.Allocate(0);
  EXPECT_TRUE(a2 != NULL);
  EXPECT_NE(a1, a2);
  h.Free(a1);
  h.Free(a2);
}

TEST(CtMallocHeapTest, IsAllocated) {
  testing::NullMemoryNotifier n;
  CtMallocHeap h(&n);

  EXPECT_FALSE(h.IsAllocated(NULL));

  void* a = h.Allocate(100);
  EXPECT_EQ(0u, reinterpret_cast<uintptr_t>(a) % kShadowRatio);
  EXPECT_TRUE(h.IsAllocated(a));
  EXPECT_FALSE(h.IsAllocated(reinterpret_cast<uint8*>(a) - 1));
  EXPECT_FALSE(h.IsAllocated(reinterpret_cast<uint8*>(a) + 1));

  h.Free(a);
  EXPECT_FALSE(h.IsAllocated(a));

  // An allocation made in another heap should resolve as not belonging to
  // this heap.
  WinHeap wh;
  a = wh.Allocate(100);
  EXPECT_FALSE(h.IsAllocated(a));
  wh.Free(a);
}

TEST(CtMallocHeapTest, IsAllocatedLargeAllocation) {
  testing::NullMemoryNotifier n;
  CtMallocHeap h(&n);

  EXPECT_FALSE(h.IsAllocated(NULL));

  // Mix large and small allocations to ensure that the CTMalloc data
  // structures correctly keep track of both.
  void* a = h.Allocate(100);
  void* b = h.Allocate(64 * 1024 * 1024);

  EXPECT_EQ(0u, reinterpret_cast<uintptr_t>(a) % kShadowRatio);
  EXPECT_TRUE(h.IsAllocated(a));
  EXPECT_FALSE(h.IsAllocated(reinterpret_cast<uint8*>(a) - 1));
  EXPECT_FALSE(h.IsAllocated(reinterpret_cast<uint8*>(a) + 1));

  EXPECT_EQ(0u, reinterpret_cast<uintptr_t>(b) % kShadowRatio);
  EXPECT_TRUE(h.IsAllocated(b));
  EXPECT_FALSE(h.IsAllocated(reinterpret_cast<uint8*>(b) - 1));
  EXPECT_FALSE(h.IsAllocated(reinterpret_cast<uint8*>(b) + 1));

  h.Free(a);
  EXPECT_FALSE(h.IsAllocated(a));
  EXPECT_TRUE(h.IsAllocated(b));

  h.Free(b);
  EXPECT_FALSE(h.IsAllocated(a));
  EXPECT_FALSE(h.IsAllocated(b));
}

TEST(CtMallocHeapTest, GetAllocationSize) {
  testing::NullMemoryNotifier n;
  CtMallocHeap h(&n);

  const size_t kAllocSize = 67;
  void* alloc = h.Allocate(kAllocSize);
  ASSERT_TRUE(alloc != NULL);
  EXPECT_LE(kAllocSize, h.GetAllocationSize(alloc));

  // CTMalloc cleans up any oustanding allocations on tear down.
}

TEST(CtMallocHeapTest, GetAllocationSizeLargeAllocation) {
  testing::NullMemoryNotifier n;
  CtMallocHeap h(&n);

  const size_t kAllocSize = 64 * 1024 * 1024;
  void* alloc = h.Allocate(kAllocSize);
  ASSERT_TRUE(alloc != NULL);
  EXPECT_LE(kAllocSize, h.GetAllocationSize(alloc));

  // CTMalloc cleans up any oustanding allocations on tear down.
}

TEST(CtMallocHeapTest, Lock) {
  testing::NullMemoryNotifier n;
  CtMallocHeap h(&n);
  h.Lock();
  EXPECT_TRUE(h.TryLock());
  h.Unlock();
  h.Unlock();
}

TEST(CtMallocHeapTest, NotifierIsCalled) {
  using testing::_;

  testing::StrictMock<testing::MockMemoryNotifier> n;
  scoped_ptr<CtMallocHeap> h;
  h.reset(new CtMallocHeap(&n));
  testing::Mock::VerifyAndClearExpectations(&n);

  EXPECT_CALL(n, NotifyFutureHeapUse(_, _));
  void* alloc = h->Allocate(100);
  testing::Mock::VerifyAndClearExpectations(&n);

  h->Free(alloc);
  testing::Mock::VerifyAndClearExpectations(&n);

  EXPECT_CALL(n, NotifyReturnedToOS(_, _));
  h.reset(nullptr);
  testing::Mock::VerifyAndClearExpectations(&n);
}

}  // namespace heaps
}  // namespace asan
}  // namespace agent
