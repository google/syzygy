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

#include "syzygy/reorder/linear_order_generator.h"

#include "base/scoped_ptr.h"
#include "base/time.h"
#include "gtest/gtest.h"
#include "syzygy/core/address.h"
#include "syzygy/core/block_graph.h"
#include "syzygy/core/random_number_generator.h"
#include "syzygy/reorder/order_generator_test.h"

class LinearOrderGeneratorTest : public testing::OrderGeneratorTest {
 protected:
  reorder::Reorderer::UniqueTime GetSystemTime() {
    return reorder::Reorderer::UniqueTime(base::Time::NowFromSystemTime());
  }

  void ExpectLinearOrdering(
      reorder::Reorderer::Order::BlockList::const_iterator it,
      reorder::Reorderer::Order::BlockList::const_iterator end) {
    // Verifies that the given block list appears in a linear order in the
    // original image.
    core::RelativeAddress cur_addr;
    for (; it != end; it++) {
      core::RelativeAddress addr;
      EXPECT_TRUE(order_.image.address_space.GetAddressOf(*it, &addr));
      EXPECT_LT(cur_addr, addr);
      cur_addr = addr;
    }
  }

  reorder::LinearOrderGenerator order_generator_;
};

TEST_F(LinearOrderGeneratorTest, DoNotReorder) {
  EXPECT_TRUE(order_generator_.CalculateReordering(false, false, &order_));

  ExpectNoDuplicateBlocks();

  // Verify that the order found in order_ matches the original decomposed
  // image.
  reorder::Reorderer::Order::BlockListMap::const_iterator it =
      order_.section_block_lists.begin();
  for (; it != order_.section_block_lists.end(); ++it) {
    const IMAGE_SECTION_HEADER* section = order_.pe.section_header(it->first);
    ExpectNoReorder(section, it->second);
  }
}

TEST_F(LinearOrderGeneratorTest, ReorderCode) {
  core::RandomNumberGenerator random(12345);

  // Get the .text code section.
  size_t section_index = order_.pe.GetSectionIndex(".text");
  const IMAGE_SECTION_HEADER* section =
      order_.pe.section_header(section_index);
  ASSERT_TRUE(section != NULL);

  // Get 5 random blocks.
  std::vector<core::RelativeAddress> addrs;
  std::vector<const core::BlockGraph::Block*> blocks;
  std::set<const core::BlockGraph::Block*> block_set;
  while (blocks.size() < 5) {
    core::RelativeAddress addr(
        section->VirtualAddress + random(section->Misc.VirtualSize));
    addrs.push_back(addr);
    const core::BlockGraph::Block* block =
        order_.image.address_space.GetBlockByAddress(addr);
    if (!block_set.insert(block).second)
      continue;
    blocks.push_back(block);
  }

  // Test multiple calls to the same block in a process group.
  // Expected process group 1 calls: block1, block0, block3.
  order_generator_.OnProcessStarted(1, GetSystemTime());
  order_generator_.OnCodeBlockEntry(blocks[1], addrs[1], 1, 1, GetSystemTime());
  order_generator_.OnCodeBlockEntry(blocks[0], addrs[0], 1, 1, GetSystemTime());
  order_generator_.OnCodeBlockEntry(blocks[1], addrs[1], 1, 1, GetSystemTime());
  order_generator_.OnCodeBlockEntry(blocks[3], addrs[3], 1, 1, GetSystemTime());
  order_generator_.OnProcessEnded(1, GetSystemTime());

  // Test out of order time calls to different blocks.
  // Expected process group 2 calls: block0, block2, block4.
  order_generator_.OnProcessStarted(2, GetSystemTime());
  reorder::Reorderer::UniqueTime time = GetSystemTime();
  order_generator_.OnCodeBlockEntry(blocks[2], addrs[2], 2, 1, GetSystemTime());
  order_generator_.OnCodeBlockEntry(blocks[0], addrs[0], 2, 1, time);
  order_generator_.OnCodeBlockEntry(blocks[4], addrs[4], 2, 1, time);
  order_generator_.OnProcessEnded(2, GetSystemTime());

  // Test nested processes.
  // Expected process group 3 calls: block0, block1, block2.
  order_generator_.OnProcessStarted(3, GetSystemTime());
  order_generator_.OnCodeBlockEntry(blocks[0], addrs[0], 3, 1, GetSystemTime());
  order_generator_.OnProcessStarted(4, GetSystemTime());
  order_generator_.OnCodeBlockEntry(blocks[1], addrs[1], 4, 1, GetSystemTime());
  order_generator_.OnCodeBlockEntry(blocks[2], addrs[2], 4, 1, GetSystemTime());
  order_generator_.OnProcessEnded(4, GetSystemTime());
  order_generator_.OnProcessEnded(3, GetSystemTime());

  // Expected ordering:
  // - block0 (highest call count).
  // - block1, block2 (second highest call count, block2 has smaller average).
  // - block3, block4 (single call count, order by process group id).

  // Do the reordering.
  EXPECT_TRUE(order_generator_.CalculateReordering(true, false, &order_));

  ExpectNoDuplicateBlocks();

  // Verify that code blocks have been reordered and that data blocks have not.
  reorder::Reorderer::Order::BlockListMap::const_iterator it =
      order_.section_block_lists.begin();
  for (; it != order_.section_block_lists.end(); ++it) {
    const IMAGE_SECTION_HEADER* section = order_.pe.section_header(it->first);
    if (order_.pe.GetSectionName(*section) == ".text") {
      // Compare the first 5 elements.
      EXPECT_TRUE(std::equal(blocks.begin(), blocks.end(), it->second.begin()));
      // Expect a linear ordering in the rest.
      ExpectLinearOrdering(it->second.begin() + 5, it->second.end());
    } else {
      ExpectNoReorder(section, it->second);
    }
  }
}
