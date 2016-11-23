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

#include "syzygy/agent/asan/heaps/large_block_heap.h"

#include "syzygy/agent/asan/unittest_util.h"
#include "syzygy/agent/asan/memory_notifiers/null_memory_notifier.h"

namespace agent {
namespace asan {
namespace heaps {

namespace {

// Provides an ordering for BlockInfo objects.
struct BlockInfoLessThan {
  bool operator()(const BlockInfo& bi1, const BlockInfo& bi2) const {
    return bi1.header < bi2.header;
  }
};

typedef std::set<BlockInfo, BlockInfoLessThan> BlockInfoSet;

testing::DummyHeap dummy_heap;
agent::asan::memory_notifiers::NullMemoryNotifier dummy_notifier;

// A LargeBlockHeap that uses a null memory notifier.
class TestLargeBlockHeap : public LargeBlockHeap {
 public:
  using LargeBlockHeap::FreeAllAllocations;

  TestLargeBlockHeap() : LargeBlockHeap(&dummy_notifier, &dummy_heap) {
  }
};

}  // namespace

TEST(LargeBlockHeapTest, GetHeapTypeIsValid) {
  TestLargeBlockHeap h;
  EXPECT_EQ(kLargeBlockHeap, h.GetHeapType());
}

TEST(LargeBlockHeapTest, FeaturesAreValid) {
  TestLargeBlockHeap h;
  EXPECT_EQ(HeapInterface::kHeapSupportsIsAllocated |
                HeapInterface::kHeapSupportsGetAllocationSize |
                HeapInterface::kHeapReportsReservations,
            h.GetHeapFeatures());
}

TEST(LargeBlockHeapTest, EndToEnd) {
  TestLargeBlockHeap h;
  EXPECT_EQ(0u, h.size());

  BlockLayout layout = {};
  BlockInfo block = {};

  // Allocate and free a zero-sized allocation. This should succeed by
  // definition.
  void* alloc = h.AllocateBlock(0, 0, 0, &layout);
  EXPECT_EQ(1u, h.size());
  BlockInitialize(layout, alloc, &block);
  EXPECT_TRUE(h.FreeBlock(block));
  EXPECT_EQ(0u, h.size());

  // Make a bunch of different sized allocations.
  BlockInfoSet blocks;
  for (uint32_t i = 1, j = 1; i < 1024 * 1024; i <<= 1, ++j) {
    void* alloc = h.AllocateBlock(i, 0, 0, &layout);
    EXPECT_EQ(j, h.size());
    EXPECT_EQ(0u, layout.block_size % GetPageSize());
    EXPECT_EQ(0u, reinterpret_cast<uintptr_t>(alloc) % GetPageSize());
    EXPECT_LE(GetPageSize(), layout.header_size + layout.header_padding_size);
    EXPECT_EQ(i, layout.body_size);
    EXPECT_LE(GetPageSize(), layout.trailer_padding_size + layout.trailer_size);
    BlockInitialize(layout, alloc, &block);
    blocks.insert(block);
  }

  // Now free them.
  BlockInfoSet::const_iterator it = blocks.begin();
  for (; it != blocks.end(); ++it)
    EXPECT_TRUE(h.FreeBlock(*it));
  EXPECT_EQ(0u, h.size());
}

TEST(LargeBlockHeapTest, ZeroSizedAllocationsHaveDistinctAddresses) {
  TestLargeBlockHeap h;

  void* a1 = h.Allocate(0);
  EXPECT_TRUE(a1 != NULL);
  void* a2 = h.Allocate(0);
  EXPECT_TRUE(a2 != NULL);
  EXPECT_NE(a1, a2);
  EXPECT_TRUE(h.Free(a1));
  EXPECT_TRUE(h.Free(a2));

  BlockLayout layout = {};

  BlockInfo b1 = {};
  a1 = h.AllocateBlock(0, 0, 0, &layout);
  EXPECT_TRUE(a1 != NULL);
  BlockInitialize(layout, a1, &b1);

  BlockInfo b2 = {};
  a2 = h.AllocateBlock(0, 0, 0, &layout);
  EXPECT_TRUE(a2 != NULL);
  BlockInitialize(layout, a2, &b2);

  EXPECT_NE(a1, a2);
  EXPECT_NE(b1.header, b2.header);

  EXPECT_TRUE(h.FreeBlock(b1));
  EXPECT_TRUE(h.FreeBlock(b2));
}

TEST(LargeBlockHeapTest, IsAllocated) {
  TestLargeBlockHeap h;

  EXPECT_FALSE(h.IsAllocated(NULL));

  void* a = h.Allocate(100);
  EXPECT_TRUE(h.IsAllocated(a));
  EXPECT_FALSE(h.IsAllocated(reinterpret_cast<uint8_t*>(a) - 1));
  EXPECT_FALSE(h.IsAllocated(reinterpret_cast<uint8_t*>(a) + 1));

  EXPECT_TRUE(h.Free(a));
  EXPECT_FALSE(h.IsAllocated(a));
}

TEST(LargeBlockHeapTest, GetAllocationSize) {
  TestLargeBlockHeap h;

  void* alloc = h.Allocate(67);
  ASSERT_TRUE(alloc != NULL);
  EXPECT_EQ(67u, h.GetAllocationSize(alloc));
  EXPECT_TRUE(h.Free(alloc));
}

TEST(LargeBlockHeapTest, Lock) {
  TestLargeBlockHeap h;

  h.Lock();
  EXPECT_TRUE(h.TryLock());
  h.Unlock();
  h.Unlock();
}

TEST(LargeBlockHeapTest, FreeAllAllocations) {
  const size_t kAllocCount = 10;
  TestLargeBlockHeap h;
  for (size_t i = 0; i < kAllocCount; ++i)
    h.Allocate(42);
  EXPECT_EQ(kAllocCount, h.size());
  h.FreeAllAllocations();
  EXPECT_EQ(0U, h.size());
}

TEST(LargeBlockHeapTest, DestructionWithOutstandingAllocationsSucceeds) {
  const size_t kAllocCount = 10;
  TestLargeBlockHeap h;
  // Create some allocations and intentionally leak them. They should be
  // automatically released in the LargeBlockHeap destructor. This will only
  // fail due to a CHECK in the LargeBlockHeap that ensure that there's no more
  // alive allocations after calling FreeAllAllocations.
  for (size_t i = 0; i < kAllocCount; ++i)
    h.Allocate(42);
  EXPECT_EQ(kAllocCount, h.size());
}

}  // namespace heaps
}  // namespace asan
}  // namespace agent
