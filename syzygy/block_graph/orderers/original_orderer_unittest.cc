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
//
// Unittests for BlockGraph::Orderers::OriginalOrderer.

#include "syzygy/block_graph/orderers/original_orderer.h"

#include <algorithm>

#include "base/strings/stringprintf.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/block_graph/unittest_util.h"

namespace block_graph {
namespace orderers {

namespace {

using testing::Pointwise;

// Declares a tuple matcher that gets the section() property of the first
// value, and compares it to the second value. It would be nice to do
// this with Pointwise(Property(&section, Eq())), but Property can't
// handle tuple matchers.
MATCHER(SectionEq, std::string("has section() ") +
    std::string(negation ? "not " : "") + std::string("equal to")) {
  return ::std::tr1::get<0>(arg)->section() == ::std::tr1::get<1>(arg);
}

// Adds a block to the given block-graph with the provided properties.
BlockGraph::Block* AddBlock(BlockGraph* bg,
                            BlockGraph::Section* section,
                            size_t number,
                            size_t src_addr,
                            bool initialized) {
  DCHECK(bg != NULL);
  DCHECK(section != NULL);

  std::string name = base::StringPrintf("block%d", number);
  BlockGraph::Block* block = bg->AddBlock(
      BlockGraph::DATA_BLOCK, 10, name);
  DCHECK(block != NULL);

  if (src_addr != 0)
    block->source_ranges().Push(
        BlockGraph::Block::DataRange(0, block->size()),
        BlockGraph::Block::SourceRange(BlockGraph::RelativeAddress(src_addr),
                                       block->size()));

  block->set_section(section->id());
  if (initialized) {
    uint8* data = block->AllocateData(block->size());
    // Make some non-zero data so that this block can not be implicitly
    // initialized.
    data[0] = 1;
  }

  return block;
}

}  // namespace

TEST(OriginalOrdererTest, OrderIsAsExpected) {
  BlockGraph bg;
  BlockGraph::Section* section1 = bg.AddSection("section1", 0);
  BlockGraph::Section* section2 = bg.AddSection("section2", 0);
  BlockGraph::Section* section3 = bg.AddSection("section3", 0);

  // Blocks 2 and 3 have the same source range but 3 is not initialized,
  //     testing criteria 1.
  // Blocks 1-3 have source range data, block 4-5 do not. This tests criteria 2.
  // Blocks 1 and 2 have differing source ranges, testing criteria 3.
  // Blocks 4 and 5 are identical except block 5 has a higher block ID, testing
  //     criteria 4.

  // These blocks are scrambled so that ordering them by ID is not correct.
  BlockGraph::Block* block1 = AddBlock(&bg, section1, 3, 30, false);
  BlockGraph::Block* block2 = AddBlock(&bg, section1, 2, 30, true);
  BlockGraph::Block* block3 = AddBlock(&bg, section1, 4, 0, false);
  BlockGraph::Block* block4 = AddBlock(&bg, section1, 1, 10, true);

  // Needs to be created last so that the ID is the greatest.
  BlockGraph::Block* block5 = AddBlock(&bg, section1, 5, 0, false);

  OrderedBlockGraph obg(&bg);

  // Shuffle the sections.
  std::vector<BlockGraph::Section*> sections, shuffled_sections;
  sections.push_back(section1);
  sections.push_back(section2);
  sections.push_back(section3);
  shuffled_sections = sections;
  std::random_shuffle(shuffled_sections.begin(), shuffled_sections.end());
  for (size_t i = 0; i < shuffled_sections.size(); ++i)
    obg.PlaceAtTail(shuffled_sections[i]);

  // Shuffle the blocks in section1.
  BlockVector blocks, shuffled_blocks;
  blocks.push_back(block4);
  blocks.push_back(block2);
  blocks.push_back(block1);
  blocks.push_back(block3);
  blocks.push_back(block5);
  shuffled_blocks = blocks;
  std::random_shuffle(shuffled_blocks.begin(), shuffled_blocks.end());
  for (size_t i = 0; i < shuffled_blocks.size(); ++i)
    obg.PlaceAtTail(section1, shuffled_blocks[i]);

  // Run the default orderer.
  OriginalOrderer orderer;
  EXPECT_TRUE(orderer.OrderBlockGraph(&obg, block1));

  EXPECT_THAT(obg.ordered_sections(),
              Pointwise(SectionEq(), sections));

  EXPECT_THAT(obg.ordered_section(section1).ordered_blocks(),
              Pointwise(testing::Eq(), blocks));
}

}  // namespace orderers
}  // namespace block_graph
