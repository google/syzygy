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

#include "syzygy/reorder/dead_code_finder.h"

#include "gtest/gtest.h"
#include "syzygy/block_graph/block_graph.h"
#include "syzygy/core/address.h"
#include "syzygy/core/random_number_generator.h"
#include "syzygy/reorder/order_generator_test.h"

namespace reorder {

class DeadCodeFinderTest : public testing::OrderGeneratorTest {
 protected:
  typedef std::set<const block_graph::BlockGraph::Block*> BlockSet;
  typedef BlockSet::iterator BlockIter;

  DeadCodeFinderTest() : random_(12345) {
  }

  DeadCodeFinder dead_code_finder_;
  BlockSet live_blocks_;
  BlockSet dead_blocks_;
  core::RandomNumberGenerator random_;
};

TEST_F(DeadCodeFinderTest, TestDLL) {
  const size_t kNumBlocks = 20;
  const char kSectionName[] = ".text";
  // Get the .text code section.
  size_t section_index = input_dll_.GetSectionIndex(kSectionName);
  const IMAGE_SECTION_HEADER* section =
      input_dll_.section_header(section_index);
  ASSERT_TRUE(section != NULL);

  // Get a bunch of random blocks to visit (and consider live).
  ASSERT_TRUE(live_blocks_.size() == 0);
  while (live_blocks_.size() < kNumBlocks) {
    core::RelativeAddress addr(
        section->VirtualAddress + random_(section->Misc.VirtualSize));
    const block_graph::BlockGraph::Block* block =
        image_layout_.blocks.GetBlockByAddress(addr);
    ASSERT_TRUE(block->addr() <= addr);
    ASSERT_TRUE(addr <= block->addr() + block->size());
    live_blocks_.insert(block);
  }

  // Get a bunch of random blocks to NOT visit (and consider dead).
  ASSERT_TRUE(dead_blocks_.size() == 0);
  while (dead_blocks_.size() < kNumBlocks) {
    core::RelativeAddress addr(
        section->VirtualAddress + random_(section->Misc.VirtualSize));
    const block_graph::BlockGraph::Block* block =
        image_layout_.blocks.GetBlockByAddress(addr);
    if ((block->attributes() & block_graph::BlockGraph::GAP_BLOCK) == 0 &&
        (live_blocks_.find(block) == live_blocks_.end())) {
      dead_blocks_.insert(block);
    }
  }

  // Generate calls to the live blocks.
  dead_code_finder_.OnProcessStarted(1, GetSystemTime());
  for (BlockIter it = live_blocks_.begin();  it != live_blocks_.end(); ++it) {
    dead_code_finder_.OnCodeBlockEntry(
        *it, (*it)->addr(), 1, 1, GetSystemTime());
  }
  dead_code_finder_.OnProcessEnded(1, GetSystemTime());

  // Do the reordering.
  ASSERT_TRUE(dead_code_finder_.CalculateReordering(input_dll_,
                                                    image_layout_,
                                                    true,
                                                    false,
                                                    &order_));

  ExpectNoDuplicateBlocks();

  // Check the live blocks.
  for (BlockIter it = live_blocks_.begin();  it != live_blocks_.end(); ++it) {
    EXPECT_FALSE(dead_code_finder_.IsDead(*it))
        << "Block '" << (*it)->name() << "' was not expected to be dead.";
  }

  // Check the dead blocks.
  for (BlockIter it = dead_blocks_.begin();  it != dead_blocks_.end(); ++it) {
    EXPECT_TRUE(dead_code_finder_.IsDead(*it))
        << "Block '" << (*it)->name() << "' was expected to be dead.";
  }

  // Check the ordering.
  ASSERT_EQ(image_layout_.sections.size(), order_.sections.size());
  for (size_t i = 0; i < order_.sections.size(); ++i) {
    EXPECT_EQ(image_layout_.sections[i].name, order_.sections[i].name);
    EXPECT_EQ(image_layout_.sections[i].characteristics,
              order_.sections[i].characteristics);
    if (i != section_index)
      continue;
    ASSERT_EQ(kSectionName, order_.sections[i].name);
    EXPECT_GE(order_.sections[i].blocks.size(), dead_blocks_.size());
    Reorderer::Order::BlockSpecVector::const_iterator it =
        order_.sections[0].blocks.begin();
    for (; it != order_.sections[0].blocks.end(); ++it) {
      EXPECT_TRUE(dead_code_finder_.IsDead(it->block));
      EXPECT_TRUE(live_blocks_.find(it->block) == live_blocks_.end());
    }
  }
}

}  // namespace reorder
