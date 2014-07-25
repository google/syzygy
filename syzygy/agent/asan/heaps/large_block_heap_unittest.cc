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

#include "gtest/gtest.h"

namespace agent {
namespace asan {
namespace heaps {

namespace {

// Provides an ordering for BlockInfo objects.
struct BlockInfoLessThan {
  bool operator()(const BlockInfo& bi1, const BlockInfo& bi2) const {
    return bi1.block < bi2.block;
  }
};

typedef std::set<BlockInfo, BlockInfoLessThan> BlockInfoSet;

}  // namespace

TEST(LargeBlockHeapTest, EndToEnd) {
  LargeBlockHeap h;
  EXPECT_EQ(0u, h.size());

  BlockLayout layout = {};
  BlockInfo block = {};

  // Allocate and free a zero-sized allocation. This should succeed
  // by definition.
  void* alloc = h.AllocateBlock(0, 0, 0, &layout);
  EXPECT_EQ(1u, h.size());
  BlockInitialize(layout, alloc, false, &block);
  EXPECT_TRUE(h.FreeBlock(block));
  EXPECT_EQ(0u, h.size());

  // Make a bunch of different sized allocations.
  BlockInfoSet blocks;
  for (size_t i = 1, j = 1; i < 1024 * 1024; i <<= 1, ++j) {
    void* alloc = h.AllocateBlock(i, 0, 0, &layout);
    EXPECT_EQ(j, h.size());
    EXPECT_EQ(0u, layout.block_size % kPageSize);
    EXPECT_EQ(0u, reinterpret_cast<uintptr_t>(alloc) % kPageSize);
    EXPECT_LE(kPageSize, layout.header_size + layout.header_padding_size);
    EXPECT_EQ(i, layout.body_size);
    EXPECT_LE(kPageSize, layout.trailer_padding_size + layout.trailer_size);
    BlockInitialize(layout, alloc, false, &block);
    blocks.insert(block);
  }

  // Now free them.
  BlockInfoSet::const_iterator it = blocks.begin();
  for (; it != blocks.end(); ++it)
    EXPECT_TRUE(h.FreeBlock(*it));
  EXPECT_EQ(0u, h.size());
}

}  // namespace heaps
}  // namespace asan
}  // namespace agent
