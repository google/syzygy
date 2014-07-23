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

#include "syzygy/agent/asan/heaps/simple_block_heap.h"

#include "gtest/gtest.h"
#include "syzygy/agent/asan/heaps/win_heap.h"

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

TEST(SimpleBlockHeapTest, EndToEnd) {
  WinHeap win_heap;
  SimpleBlockHeap h(&win_heap);

  BlockLayout layout = {};
  BlockInfo block = {};

  // Allocate and free a zero-sized allocation. This should succeed
  // by definition.
  void* alloc = h.AllocateBlock(0, 0, 0, &layout);
  BlockInitialize(layout, alloc, false, &block);
  EXPECT_TRUE(h.FreeBlock(block));

  // Make a bunch of different sized allocations.
  BlockInfoSet blocks;
  for (size_t i = 1; i < 1024 * 1024; i <<= 1) {
    void* alloc = h.AllocateBlock(i, 0, 0, &layout);
    BlockInitialize(layout, alloc, false, &block);
    blocks.insert(block);
  }

  // Now free them.
  BlockInfoSet::const_iterator it = blocks.begin();
  for (; it != blocks.end(); ++it)
    EXPECT_TRUE(h.FreeBlock(*it));
}

}  // namespace heaps
}  // namespace asan
}  // namespace agent
