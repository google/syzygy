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

#include "gtest/gtest.h"
#include "syzygy/agent/asan/unittest_util.h"

namespace agent {
namespace asan {
namespace heaps {

TEST(CtMallocHeapTest, FeaturesAreValid) {
  testing::NullMemoryNotifier n;
  CtMallocHeap h(&n);
  EXPECT_EQ(CtMallocHeap::kHeapReportsReservations, h.GetHeapFeatures());
}

TEST(CtMallocHeapTest, HeapTest) {
  testing::NullMemoryNotifier n;
  CtMallocHeap h(&n);

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

// NOTE: For now IsAllocated is not supported by this heap.
TEST(CtMallocHeapTest, IsAllocated) {
  testing::NullMemoryNotifier n;
  CtMallocHeap h(&n);

  EXPECT_FALSE(h.IsAllocated(NULL));

  void* a = h.Allocate(100);
  EXPECT_FALSE(h.IsAllocated(a));
  EXPECT_FALSE(h.IsAllocated(reinterpret_cast<uint8*>(a) - 1));
  EXPECT_FALSE(h.IsAllocated(reinterpret_cast<uint8*>(a) + 1));

  h.Free(a);
  EXPECT_FALSE(h.IsAllocated(a));
}

}  // namespace heaps
}  // namespace asan
}  // namespace agent
