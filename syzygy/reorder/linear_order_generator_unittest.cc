// Copyright 2012 Google Inc. All Rights Reserved.
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

#include "base/memory/scoped_ptr.h"
#include "base/time/time.h"
#include "gtest/gtest.h"
#include "syzygy/block_graph/block_graph.h"
#include "syzygy/core/address.h"
#include "syzygy/core/random_number_generator.h"
#include "syzygy/reorder/order_generator_test.h"

namespace reorder {

namespace {

class LinearOrderGeneratorTest : public testing::OrderGeneratorTest {
 protected:
  void ExpectLinearOrder(
      Reorderer::Order::BlockSpecVector::const_iterator it,
      Reorderer::Order::BlockSpecVector::const_iterator end) {
    // Verifies that the given block list appears in a linear order in the
    // original image.
    core::RelativeAddress cur_addr;
    for (; it != end; ++it) {
      core::RelativeAddress addr;
      EXPECT_TRUE(image_layout_.blocks.GetAddressOf(it->block, &addr));
      EXPECT_LT(cur_addr, addr);
      cur_addr = addr;
    }
  }

  LinearOrderGenerator order_generator_;
};

bool IsSameBlock(const block_graph::BlockGraph::Block* block,
                 const Reorderer::Order::BlockSpec& block_spec) {
  return block == block_spec.block;
}

}  // namespace

TEST_F(LinearOrderGeneratorTest, DoNotReorder) {
  EXPECT_TRUE(order_generator_.CalculateReordering(input_dll_,
                                                   image_layout_,
                                                   false,
                                                   false,
                                                   &order_));

  ExpectNoDuplicateBlocks();

  // Verify that the order found in order_ matches the original decomposed
  // image.
  for (size_t i = 0; i != order_.sections.size(); ++i) {
    const IMAGE_SECTION_HEADER* section = input_dll_.section_header(i);
    ExpectSameOrder(section, order_.sections[i].blocks);
  }
}

TEST_F(LinearOrderGeneratorTest, ReorderCode) {
  core::RandomNumberGenerator random(12345);

  // Get the .text code section.
  size_t section_index = input_dll_.GetSectionIndex(".text");
  const IMAGE_SECTION_HEADER* section =
      input_dll_.section_header(section_index);
  ASSERT_TRUE(section != NULL);

  // Get 5 random blocks.
  std::vector<core::RelativeAddress> addrs;
  block_graph::ConstBlockVector blocks;
  std::set<const block_graph::BlockGraph::Block*> block_set;
  while (blocks.size() < 5) {
    core::RelativeAddress addr(
        section->VirtualAddress + random(section->Misc.VirtualSize));
    addrs.push_back(addr);
    const block_graph::BlockGraph::Block* block =
        image_layout_.blocks.GetBlockByAddress(addr);
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
  Reorderer::UniqueTime time = GetSystemTime();
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
  EXPECT_TRUE(order_generator_.CalculateReordering(input_dll_,
                                                   image_layout_,
                                                   true,
                                                   false,
                                                   &order_));

  ExpectNoDuplicateBlocks();

  // Verify that code blocks have been reordered and that data blocks have not.
  for (size_t i = 0; i != order_.sections.size(); ++i) {
    const IMAGE_SECTION_HEADER* section = input_dll_.section_header(i);
    if (input_dll_.GetSectionName(*section) == ".text") {
      // We expect that some reordering has occurred.
      ExpectDifferentOrder(section, order_.sections[i].blocks);
      // The first 5 blocks should be as given in the ordering.
      EXPECT_TRUE(std::equal(blocks.begin(),
                             blocks.end(),
                             order_.sections[i].blocks.begin(),
                             &IsSameBlock));
      // The remaining blocks should be in linear order.
      ExpectLinearOrder(order_.sections[i].blocks.begin() + 5,
                        order_.sections[i].blocks.end());
    } else {
      ExpectSameOrder(section, order_.sections[i].blocks);
    }
  }
}

}  // namespace reorder
