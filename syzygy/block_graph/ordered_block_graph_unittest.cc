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

#include "syzygy/block_graph/ordered_block_graph.h"

#include "base/strings/stringprintf.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace block_graph {

using testing::ElementsAre;

namespace {

// A functor for comparing two blocks based on their size.
struct BlockSizeCompareFunctor {
  bool operator()(const BlockGraph::Block* block1,
                  const BlockGraph::Block* block2) const {
    DCHECK(block1 != NULL);
    DCHECK(block2 != NULL);
    return block1->size() < block2->size();
  }
};

// A functor for comparing two sections based on their name. Reverses the
// sort order.
struct ReverseSectionNameCompareFunctor {
  bool operator()(const BlockGraph::Section* section1,
                  const BlockGraph::Section* section2) const {
    DCHECK(section1 != NULL);
    DCHECK(section2 != NULL);
    return section1->name() > section2->name();
  }
};

template<typename C> std::vector<size_t> GetIds(const C& c) {
  std::vector<size_t> ids;
  typename C::const_iterator it = c.begin();
  for (; it != c.end(); ++it)
    ids.push_back((*it)->id());
  return ids;
}

const OrderedBlockGraph::BlockList& GetSectionBlockList(
    const OrderedBlockGraph& obg, size_t section_id) {
  const BlockGraph::Section* section =
      obg.block_graph()->GetSectionById(section_id);
  return obg.ordered_section(section).ordered_blocks();
}

#define EXPECT_SECTION_ORDER(obg, ...) \
    EXPECT_THAT(GetIds(obg.ordered_sections()), ElementsAre(__VA_ARGS__))

#define EXPECT_SECTION_CONTAINS(obg, section_id, ...) \
    EXPECT_THAT(GetIds(GetSectionBlockList(obg, section_id)), \
                ElementsAre(__VA_ARGS__))

class TestOrderedBlockGraph : public OrderedBlockGraph {
 public:
  explicit TestOrderedBlockGraph(BlockGraph* block_graph)
      : OrderedBlockGraph(block_graph) { }

  bool IndicesAreValid() {
    SectionList::iterator section_it = ordered_sections_.begin();
    for (; section_it != ordered_sections_.end(); ++section_it) {
      SectionInfo* section_info = GetSectionInfo((*section_it)->section());
      if (section_info == NULL || section_info->it != section_it)
        return false;

      const BlockList& ordered_blocks(
          section_info->ordered_section.ordered_blocks());
      BlockList::const_iterator block_it = ordered_blocks.begin();
      for (; block_it != ordered_blocks.end(); ++block_it) {
        BlockInfo* block_info = GetBlockInfo(*block_it);
        if (block_info == NULL || block_info->it != block_it)
          return false;
      }
    }

    return true;
  }
};

class OrderedBlockGraphTest : public testing::Test {
 public:
  virtual void SetUp() {
  }

  // Creates a bunch of blocks in a bunch of sections. The blocks will be
  // distributed to the section in order of increasing block ID, with blocks
  // not in any section coming last. The sizes of the blocks will be inversely
  // related to their ID.
  void InitBlockGraph(size_t sections,
                      size_t blocks_per_section,
                      size_t blocks_no_section) {
    size_t block_count = 0;
    const size_t kTotalBlockCount = sections * blocks_per_section +
        blocks_no_section;

    // Create sections and blocks in each section.
    for (size_t i = 0; i < sections; ++i) {
      BlockGraph::Section* section = block_graph_.AddSection(
          base::StringPrintf("s%d", i), 0);
      ASSERT_TRUE(section);
      for (size_t j = 0; j < blocks_per_section; ++j) {
        BlockGraph::Block* block = block_graph_.AddBlock(
            BlockGraph::DATA_BLOCK, 10 + kTotalBlockCount - block_count,
            base::StringPrintf("b%d", block_count));
        ASSERT_TRUE(block);
        block->set_section(section->id());
        ++block_count;
      }
    }

    // Create blocks not in any section.
    for (size_t i = 0; i < blocks_no_section; ++i) {
      BlockGraph::Block* block = block_graph_.AddBlock(
          BlockGraph::DATA_BLOCK, 10 + kTotalBlockCount - block_count,
          base::StringPrintf("b%d", block_count));
      ASSERT_TRUE(block);
      ++block_count;
    }
  }

  BlockGraph block_graph_;
};

}  // namespace

TEST_F(OrderedBlockGraphTest, CreateEmpty) {
  TestOrderedBlockGraph ordered(&block_graph_);
  EXPECT_TRUE(ordered.IndicesAreValid());
}

TEST_F(OrderedBlockGraphTest, CreateNonEmpty) {
  InitBlockGraph(3, 3, 3);
  TestOrderedBlockGraph ordered(&block_graph_);
  EXPECT_SECTION_ORDER(ordered, 0, 1, 2);
  EXPECT_SECTION_CONTAINS(ordered, 0, 1, 2, 3);
  EXPECT_SECTION_CONTAINS(ordered, 1, 4, 5, 6);
  EXPECT_SECTION_CONTAINS(ordered, 2, 7, 8, 9);
  EXPECT_SECTION_CONTAINS(ordered, BlockGraph::kInvalidSectionId,
                          10, 11, 12);
  EXPECT_TRUE(ordered.IndicesAreValid());
}

TEST_F(OrderedBlockGraphTest, SectionPlaceAtHead) {
  InitBlockGraph(3, 0, 0);
  TestOrderedBlockGraph ordered(&block_graph_);
  EXPECT_SECTION_ORDER(ordered, 0, 1, 2);
  BlockGraph::Section* section0 = block_graph_.GetSectionById(0);
  BlockGraph::Section* section1 = block_graph_.GetSectionById(1);

  // This should be a noop.
  ordered.PlaceAtHead(section0);
  EXPECT_SECTION_ORDER(ordered, 0, 1, 2);
  EXPECT_TRUE(ordered.IndicesAreValid());

  // This should move a section.
  ordered.PlaceAtHead(section1);
  EXPECT_SECTION_ORDER(ordered, 1, 0, 2);
  EXPECT_TRUE(ordered.IndicesAreValid());
}

TEST_F(OrderedBlockGraphTest, SectionPlaceAtTail) {
  InitBlockGraph(3, 0, 0);
  TestOrderedBlockGraph ordered(&block_graph_);
  EXPECT_SECTION_ORDER(ordered, 0, 1, 2);
  BlockGraph::Section* section1 = block_graph_.GetSectionById(1);
  BlockGraph::Section* section2 = block_graph_.GetSectionById(2);

  // This should be a noop.
  ordered.PlaceAtTail(section2);
  EXPECT_SECTION_ORDER(ordered, 0, 1, 2);
  EXPECT_TRUE(ordered.IndicesAreValid());

  // This should move a section.
  ordered.PlaceAtTail(section1);
  EXPECT_SECTION_ORDER(ordered, 0, 2, 1);
  EXPECT_TRUE(ordered.IndicesAreValid());
}

TEST_F(OrderedBlockGraphTest, SectionPlaceBefore) {
  InitBlockGraph(3, 0, 0);
  TestOrderedBlockGraph ordered(&block_graph_);
  EXPECT_SECTION_ORDER(ordered, 0, 1, 2);
  BlockGraph::Section* section1 = block_graph_.GetSectionById(1);
  BlockGraph::Section* section2 = block_graph_.GetSectionById(2);

  // This should be a noop.
  ordered.PlaceBefore(section2, section1);
  EXPECT_SECTION_ORDER(ordered, 0, 1, 2);
  EXPECT_TRUE(ordered.IndicesAreValid());

  // This should move a section.
  ordered.PlaceBefore(section1, section2);
  EXPECT_SECTION_ORDER(ordered, 0, 2, 1);
  EXPECT_TRUE(ordered.IndicesAreValid());
}

TEST_F(OrderedBlockGraphTest, SectionPlaceAfter) {
  InitBlockGraph(3, 0, 0);
  TestOrderedBlockGraph ordered(&block_graph_);
  EXPECT_SECTION_ORDER(ordered, 0, 1, 2);
  BlockGraph::Section* section0 = block_graph_.GetSectionById(0);
  BlockGraph::Section* section1 = block_graph_.GetSectionById(1);

  // This should be a noop.
  ordered.PlaceAfter(section0, section1);
  EXPECT_SECTION_ORDER(ordered, 0, 1, 2);
  EXPECT_TRUE(ordered.IndicesAreValid());

  // This should move a section.
  ordered.PlaceAfter(section1, section0);
  EXPECT_SECTION_ORDER(ordered, 1, 0, 2);
  EXPECT_TRUE(ordered.IndicesAreValid());
}

TEST_F(OrderedBlockGraphTest, SectionSortEmpty) {
  InitBlockGraph(0, 0, 0);
  TestOrderedBlockGraph ordered(&block_graph_);
  ordered.Sort(ReverseSectionNameCompareFunctor());
}

TEST_F(OrderedBlockGraphTest, SectionSort) {
  InitBlockGraph(3, 0, 0);
  TestOrderedBlockGraph ordered(&block_graph_);
  EXPECT_SECTION_ORDER(ordered, 0, 1, 2);
  EXPECT_TRUE(ordered.IndicesAreValid());

  ordered.Sort(ReverseSectionNameCompareFunctor());
  EXPECT_SECTION_ORDER(ordered, 2, 1, 0);
  EXPECT_TRUE(ordered.IndicesAreValid());
}

TEST_F(OrderedBlockGraphTest, BlockPlaceAtHead) {
  InitBlockGraph(0, 0, 3);
  TestOrderedBlockGraph ordered(&block_graph_);
  EXPECT_SECTION_CONTAINS(ordered, NULL, 1, 2, 3);
  BlockGraph::Block* block1 = block_graph_.GetBlockById(1);
  BlockGraph::Block* block2 = block_graph_.GetBlockById(2);

  // This should be a noop.
  ordered.PlaceAtHead(NULL, block1);
  EXPECT_SECTION_CONTAINS(ordered, NULL, 1, 2, 3);
  EXPECT_TRUE(ordered.IndicesAreValid());

  // This should move a block.
  ordered.PlaceAtHead(NULL, block2);
  EXPECT_SECTION_CONTAINS(ordered, NULL, 2, 1, 3);
  EXPECT_TRUE(ordered.IndicesAreValid());
}

TEST_F(OrderedBlockGraphTest, BlockPlaceAtTail) {
  InitBlockGraph(0, 0, 3);
  TestOrderedBlockGraph ordered(&block_graph_);
  EXPECT_SECTION_CONTAINS(ordered, NULL, 1, 2, 3);
  BlockGraph::Block* block2 = block_graph_.GetBlockById(2);
  BlockGraph::Block* block3 = block_graph_.GetBlockById(3);

  // This should be a noop.
  ordered.PlaceAtTail(NULL, block3);
  EXPECT_SECTION_CONTAINS(ordered, NULL, 1, 2, 3);
  EXPECT_TRUE(ordered.IndicesAreValid());

  // This should move a block.
  ordered.PlaceAtTail(NULL, block2);
  EXPECT_SECTION_CONTAINS(ordered, NULL, 1, 3, 2);
  EXPECT_TRUE(ordered.IndicesAreValid());
}

TEST_F(OrderedBlockGraphTest, BlockPlaceBefore) {
  InitBlockGraph(0, 0, 3);
  TestOrderedBlockGraph ordered(&block_graph_);
  EXPECT_SECTION_CONTAINS(ordered, NULL, 1, 2, 3);
  BlockGraph::Block* block2 = block_graph_.GetBlockById(2);
  BlockGraph::Block* block3 = block_graph_.GetBlockById(3);

  // This should be a noop.
  ordered.PlaceBefore(block3, block2);
  EXPECT_SECTION_CONTAINS(ordered, NULL, 1, 2, 3);
  EXPECT_TRUE(ordered.IndicesAreValid());

  // This should move a block.
  ordered.PlaceBefore(block2, block3);
  EXPECT_SECTION_CONTAINS(ordered, NULL, 1, 3, 2);
  EXPECT_TRUE(ordered.IndicesAreValid());
}

TEST_F(OrderedBlockGraphTest, BlockPlaceAfter) {
  InitBlockGraph(0, 0, 3);
  TestOrderedBlockGraph ordered(&block_graph_);
  EXPECT_SECTION_CONTAINS(ordered, NULL, 1, 2, 3);
  BlockGraph::Block* block1 = block_graph_.GetBlockById(1);
  BlockGraph::Block* block2 = block_graph_.GetBlockById(2);

  // This should be a noop.
  ordered.PlaceAfter(block1, block2);
  EXPECT_SECTION_CONTAINS(ordered, NULL, 1, 2, 3);
  EXPECT_TRUE(ordered.IndicesAreValid());

  // This should move a block.
  ordered.PlaceAfter(block2, block1);
  EXPECT_SECTION_CONTAINS(ordered, NULL, 2, 1, 3);
  EXPECT_TRUE(ordered.IndicesAreValid());
}

TEST_F(OrderedBlockGraphTest, BlockPlaceAtHeadDifferentSection) {
  InitBlockGraph(2, 1, 0);
  TestOrderedBlockGraph ordered(&block_graph_);
  EXPECT_SECTION_CONTAINS(ordered, 0, 1);
  EXPECT_SECTION_CONTAINS(ordered, 1, 2);
  BlockGraph::Section* section0 = block_graph_.GetSectionById(0);
  BlockGraph::Block* block1 = block_graph_.GetBlockById(1);
  BlockGraph::Block* block2 = block_graph_.GetBlockById(2);
  EXPECT_EQ(block1->section(), 0);
  EXPECT_EQ(block2->section(), 1);
  ordered.PlaceAtHead(section0, block2);
  EXPECT_EQ(block1->section(), 0);
  EXPECT_EQ(block2->section(), 0);
  EXPECT_SECTION_CONTAINS(ordered, 0, 2, 1);
  EXPECT_SECTION_CONTAINS(ordered, 1);
  EXPECT_TRUE(ordered.IndicesAreValid());
}

TEST_F(OrderedBlockGraphTest, BlockPlaceAtTailDifferentSection) {
  InitBlockGraph(2, 1, 0);
  TestOrderedBlockGraph ordered(&block_graph_);
  EXPECT_SECTION_CONTAINS(ordered, 0, 1);
  EXPECT_SECTION_CONTAINS(ordered, 1, 2);
  BlockGraph::Section* section0 = block_graph_.GetSectionById(0);
  BlockGraph::Block* block1 = block_graph_.GetBlockById(1);
  BlockGraph::Block* block2 = block_graph_.GetBlockById(2);
  EXPECT_EQ(block1->section(), 0);
  EXPECT_EQ(block2->section(), 1);
  ordered.PlaceAtTail(section0, block2);
  EXPECT_EQ(block1->section(), 0);
  EXPECT_EQ(block2->section(), 0);
  EXPECT_SECTION_CONTAINS(ordered, 0, 1, 2);
  EXPECT_SECTION_CONTAINS(ordered, 1);
  EXPECT_TRUE(ordered.IndicesAreValid());
}

TEST_F(OrderedBlockGraphTest, BlockPlaceBeforeDifferentSection) {
  InitBlockGraph(2, 1, 0);
  TestOrderedBlockGraph ordered(&block_graph_);
  EXPECT_SECTION_CONTAINS(ordered, 0, 1);
  EXPECT_SECTION_CONTAINS(ordered, 1, 2);
  BlockGraph::Block* block1 = block_graph_.GetBlockById(1);
  BlockGraph::Block* block2 = block_graph_.GetBlockById(2);
  EXPECT_EQ(block1->section(), 0);
  EXPECT_EQ(block2->section(), 1);
  ordered.PlaceBefore(block1, block2);
  EXPECT_EQ(block1->section(), 0);
  EXPECT_EQ(block2->section(), 0);
  EXPECT_SECTION_CONTAINS(ordered, 0, 2, 1);
  EXPECT_SECTION_CONTAINS(ordered, 1);
  EXPECT_TRUE(ordered.IndicesAreValid());
}

TEST_F(OrderedBlockGraphTest, BlockPlaceAfterDifferentSection) {
  InitBlockGraph(2, 1, 0);
  TestOrderedBlockGraph ordered(&block_graph_);
  EXPECT_SECTION_CONTAINS(ordered, 0, 1);
  EXPECT_SECTION_CONTAINS(ordered, 1, 2);
  BlockGraph::Block* block1 = block_graph_.GetBlockById(1);
  BlockGraph::Block* block2 = block_graph_.GetBlockById(2);
  EXPECT_EQ(block1->section(), 0);
  EXPECT_EQ(block2->section(), 1);
  ordered.PlaceAfter(block1, block2);
  EXPECT_EQ(block1->section(), 0);
  EXPECT_EQ(block2->section(), 0);
  EXPECT_SECTION_CONTAINS(ordered, 0, 1, 2);
  EXPECT_SECTION_CONTAINS(ordered, 1);
  EXPECT_TRUE(ordered.IndicesAreValid());
}

TEST_F(OrderedBlockGraphTest, BlockChangeToAnotherSectionAndBack) {
  InitBlockGraph(2, 1, 0);
  TestOrderedBlockGraph ordered(&block_graph_);
  EXPECT_SECTION_CONTAINS(ordered, 0, 1);
  EXPECT_SECTION_CONTAINS(ordered, 1, 2);

  BlockGraph::Section* section0 = block_graph_.GetSectionById(0);
  BlockGraph::Section* section1 = block_graph_.GetSectionById(1);
  BlockGraph::Block* block1 = block_graph_.GetBlockById(1);
  EXPECT_EQ(block1->section(), 0);

  // Move from section0 to section1, and back to section0.
  ordered.PlaceAtHead(section1, block1);
  ordered.PlaceAtHead(section0, block1);
}

TEST_F(OrderedBlockGraphTest, BlockEmpty) {
  InitBlockGraph(0, 0, 0);
  TestOrderedBlockGraph ordered(&block_graph_);
  ordered.Sort(NULL, BlockSizeCompareFunctor());
}

TEST_F(OrderedBlockGraphTest, BlockSort) {
  InitBlockGraph(0, 0, 3);
  TestOrderedBlockGraph ordered(&block_graph_);
  EXPECT_SECTION_CONTAINS(ordered, NULL, 1, 2, 3);
  ordered.Sort(NULL, BlockSizeCompareFunctor());
  EXPECT_SECTION_CONTAINS(ordered, NULL, 3, 2, 1);
  EXPECT_TRUE(ordered.IndicesAreValid());
}

}  // namespace block_graph
