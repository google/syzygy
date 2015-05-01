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

#include "syzygy/reorder/transforms/basic_block_layout_transform.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/block_graph/basic_block_test_util.h"

namespace reorder {
namespace transforms {

namespace {

typedef BasicBlockSubGraphLayoutTransform::BasicBlockMap BasicBlockMap;

using testing::BasicBlockTest;
using testing::ContainerEq;

class BasicBlockSubGraphLayoutTransformTest : public BasicBlockTest {
 public:
  virtual void SetUp() override {
    BasicBlockTest::SetUp();
    ASSERT_NO_FATAL_FAILURE(InitBlockGraph());
    ASSERT_NO_FATAL_FAILURE(InitBasicBlockSubGraph());
  }

  bool Insert(size_t offset, size_t block_index, size_t bb_index) {
    return bb_map_.insert(std::make_pair(
        offset,
        std::make_pair(block_index, bb_index))).second;
  }

  void LayoutIsAsExpected() {
    BasicBlockMap bb_map;

    size_t bd_idx = 0;
    BasicBlockSubGraph::BlockDescriptionList::const_iterator bd_it =
        subgraph_.block_descriptions().begin();
    for (; bd_it != subgraph_.block_descriptions().end(); ++bd_it, ++bd_idx) {
      size_t bb_idx = 0;
      BasicBlockSubGraph::BasicBlockOrdering::const_iterator bb_it =
          bd_it->basic_block_order.begin();
      for (; bb_it != bd_it->basic_block_order.end(); ++bb_it, ++bb_idx) {
        size_t bb_offset = (*bb_it)->offset();
        ASSERT_TRUE(bb_map.insert(std::make_pair(
            bb_offset, std::make_pair(bd_idx, bb_idx))).second);
      }
    }
    EXPECT_THAT(bb_map, ContainerEq(bb_map_));
  }

  BasicBlockMap bb_map_;
};

}  // namespace

TEST_F(BasicBlockSubGraphLayoutTransformTest, NonContiguousBlockIndicesFails) {
  // This is a valid map, but we use block indices of 0 and 2 rather than 0 and
  // 1.
  ASSERT_TRUE(Insert(0, 0, 0));
  ASSERT_TRUE(Insert(23, 0, 1));
  ASSERT_TRUE(Insert(24, 0, 2));
  ASSERT_TRUE(Insert(31, 0, 3));
  ASSERT_TRUE(Insert(36, 0, 4));
  ASSERT_TRUE(Insert(37, 2, 0));
  ASSERT_TRUE(Insert(42, 2, 1));
  ASSERT_TRUE(Insert(49, 2, 2));
  ASSERT_TRUE(Insert(52, 2, 3));
  ASSERT_TRUE(Insert(64, 2, 4));
  BasicBlockSubGraphLayoutTransform tx(bb_map_);
  EXPECT_FALSE(tx.TransformBasicBlockSubGraph(
      &policy_, &block_graph_, &subgraph_));
}

TEST_F(BasicBlockSubGraphLayoutTransformTest,
       NonContiguousBasicBlockPositionsFails) {
  // This is a valid map, but we use non-contiguous basic block positions.
  ASSERT_TRUE(Insert(0, 0, 0));
  ASSERT_TRUE(Insert(23, 0, 1));
  ASSERT_TRUE(Insert(24, 0, 2));
  ASSERT_TRUE(Insert(31, 0, 3));
  ASSERT_TRUE(Insert(36, 0, 4));
  ASSERT_TRUE(Insert(37, 0, 5));
  ASSERT_TRUE(Insert(42, 0, 6));
  ASSERT_TRUE(Insert(49, 0, 7));
  ASSERT_TRUE(Insert(52, 0, 8));
  ASSERT_TRUE(Insert(64, 0, 10));
  BasicBlockSubGraphLayoutTransform tx(bb_map_);
  EXPECT_FALSE(tx.TransformBasicBlockSubGraph(
      &policy_, &block_graph_, &subgraph_));
}

TEST_F(BasicBlockSubGraphLayoutTransformTest, Identity) {
  ASSERT_TRUE(Insert(0, 0, 0));
  ASSERT_TRUE(Insert(23, 0, 1));
  ASSERT_TRUE(Insert(24, 0, 2));
  ASSERT_TRUE(Insert(31, 0, 3));
  ASSERT_TRUE(Insert(36, 0, 4));
  ASSERT_TRUE(Insert(37, 0, 5));
  ASSERT_TRUE(Insert(42, 0, 6));
  ASSERT_TRUE(Insert(49, 0, 7));
  ASSERT_TRUE(Insert(52, 0, 8));
  ASSERT_TRUE(Insert(64, 0, 9));

  BasicBlockSubGraphLayoutTransform tx(bb_map_);
  EXPECT_TRUE(tx.TransformBasicBlockSubGraph(
      &policy_, &block_graph_, &subgraph_));
  LayoutIsAsExpected();
}

TEST_F(BasicBlockSubGraphLayoutTransformTest, CodeAndDataSplit) {
  // Code blocks.
  ASSERT_TRUE(Insert(0, 0, 0));
  ASSERT_TRUE(Insert(24, 0, 1));
  ASSERT_TRUE(Insert(31, 0, 2));
  ASSERT_TRUE(Insert(36, 0, 3));
  ASSERT_TRUE(Insert(37, 0, 4));
  ASSERT_TRUE(Insert(42, 0, 5));
  ASSERT_TRUE(Insert(49, 0, 6));

  // Data blocks.
  ASSERT_TRUE(Insert(52, 1, 0));
  ASSERT_TRUE(Insert(64, 1, 1));

  // We explicitly do not specify the BB at offset 23, which consists of
  // padding that can be deleted.

  BasicBlockSubGraphLayoutTransform tx(bb_map_);
  EXPECT_TRUE(tx.TransformBasicBlockSubGraph(
      &policy_, &block_graph_, &subgraph_));
  LayoutIsAsExpected();
}

namespace {

class BasicBlockLayoutTransformTest : public BasicBlockTest {
 public:
  typedef BasicBlockLayoutTransform::Order Order;

  virtual void SetUp() override {
    BasicBlockTest::SetUp();
    header_block_ = block_graph_.AddBlock(BlockGraph::DATA_BLOCK,
        10, "Dummy Header Block");
    ASSERT_TRUE(header_block_ != NULL);
    ASSERT_NO_FATAL_FAILURE(InitBlockGraph());
  }

  BlockGraph::Block* header_block_;
};

}  // namespace

TEST_F(BasicBlockLayoutTransformTest, NewSectionNoBlocksFails) {
  Order order;
  order.sections.resize(1);
  order.sections[0].id = Order::SectionSpec::kNewSectionId;
  order.sections[0].name = ".text.new";
  order.sections[0].characteristics = text_section_->characteristics();
  order.sections[0].blocks.resize(0);

  BasicBlockLayoutTransform tx(&order);
  EXPECT_FALSE(tx.TransformBlockGraph(
      &policy_, &block_graph_, header_block_));
}

TEST_F(BasicBlockLayoutTransformTest, InvalidExistingSectionFails) {
  Order order;
  order.sections.resize(1);
  order.sections[0].id = 47;
  order.sections[0].name = "foobar";
  // Leave characteristics initialized to the default value.
  order.sections[0].blocks.resize(1);
  order.sections[0].blocks[0].block = assembly_func_;

  BasicBlockLayoutTransform tx(&order);
  EXPECT_FALSE(tx.TransformBlockGraph(
      &policy_, &block_graph_, header_block_));
}

TEST_F(BasicBlockLayoutTransformTest, ReorderSection) {
  Order order;
  order.sections.resize(1);

  order.sections[0].id = text_section_->id();
  order.sections[0].name = text_section_->name();
  order.sections[0].blocks.resize(3);
  order.sections[0].blocks[0].block = func2_;
  order.sections[0].blocks[1].block = assembly_func_;
  order.sections[0].blocks[2].block = func1_;

  BasicBlockLayoutTransform tx(&order);
  EXPECT_TRUE(tx.TransformBlockGraph(
      &policy_, &block_graph_, header_block_));

  // No new blocks or sections were created.
  EXPECT_EQ(5u, block_graph_.blocks().size());
  EXPECT_EQ(2u, block_graph_.sections().size());
}

TEST_F(BasicBlockLayoutTransformTest, CreateNewSection) {
  Order order;
  order.sections.resize(2);

  order.sections[0].id = text_section_->id();
  order.sections[0].name = ".text.hot";
  order.sections[0].characteristics = text_section_->characteristics();
  order.sections[0].blocks.resize(1);
  order.sections[0].blocks[0].block = assembly_func_;

  order.sections[1].id = Order::SectionSpec::kNewSectionId;
  order.sections[1].name = ".text.cold";
  order.sections[1].characteristics = text_section_->characteristics();
  order.sections[1].blocks.resize(2);
  order.sections[1].blocks[0].block = func1_;
  order.sections[1].blocks[1].block = func2_;

  // Remember these for validation post-transform.
  DWORD text_section_characteristics = text_section_->characteristics();

  BasicBlockLayoutTransform tx(&order);
  EXPECT_TRUE(tx.TransformBlockGraph(
      &policy_, &block_graph_, header_block_));

  // No new blocks were created, but one new section was.
  EXPECT_EQ(5u, block_graph_.blocks().size());
  EXPECT_EQ(3u, block_graph_.sections().size());

  // The .text section has been renamed but the characteristics are the same.
  EXPECT_EQ(order.sections[0].name, text_section_->name());
  EXPECT_EQ(text_section_characteristics, text_section_->characteristics());
  EXPECT_EQ(text_section_->id(), assembly_func_->section());

  // The new section is as expected.
  BlockGraph::Section* new_section =
      &(block_graph_.sections_mutable().rbegin()->second);
  EXPECT_EQ(order.sections[1].id, new_section->id());
  EXPECT_EQ(order.sections[1].name, new_section->name());
  EXPECT_EQ(order.sections[1].characteristics, new_section->characteristics());
  EXPECT_EQ(new_section->id(), func1_->section());
  EXPECT_EQ(new_section->id(), func2_->section());
}

TEST_F(BasicBlockLayoutTransformTest, SplitBlock) {
  Order order;
  order.sections.resize(2);

  Order::OffsetVector assembly_func_code_bbs;
  assembly_func_code_bbs.push_back(0);
  assembly_func_code_bbs.push_back(24);
  assembly_func_code_bbs.push_back(31);
  assembly_func_code_bbs.push_back(36);
  assembly_func_code_bbs.push_back(37);
  assembly_func_code_bbs.push_back(42);
  assembly_func_code_bbs.push_back(49);

  Order::OffsetVector assembly_func_data_bbs;
  assembly_func_data_bbs.push_back(52);
  assembly_func_data_bbs.push_back(64);

  order.sections[0].id = text_section_->id();
  order.sections[0].name = text_section_->name();
  order.sections[0].characteristics = text_section_->characteristics();
  order.sections[0].blocks.resize(3);
  order.sections[0].blocks[0].block = func1_;
  order.sections[0].blocks[1].block = func2_;
  order.sections[0].blocks[2].block = assembly_func_;
  order.sections[0].blocks[2].basic_block_offsets = assembly_func_code_bbs;

  order.sections[1].id = data_section_->id();
  order.sections[1].name = data_section_->name();
  order.sections[1].characteristics = data_section_->characteristics();
  order.sections[1].blocks.resize(2);
  order.sections[1].blocks[0].block = data_;
  order.sections[1].blocks[1].block = assembly_func_;
  order.sections[1].blocks[1].basic_block_offsets = assembly_func_data_bbs;

  BlockGraph::BlockId old_assembly_func_id = assembly_func_->id();

  BasicBlockLayoutTransform tx(&order);
  EXPECT_TRUE(tx.TransformBlockGraph(
      &policy_, &block_graph_, header_block_));

  // One new block has been created and no new sections.
  EXPECT_EQ(6u, block_graph_.blocks().size());
  EXPECT_EQ(2u, block_graph_.sections().size());

  // The assembly func block no longer exists.
  EXPECT_TRUE(block_graph_.GetBlockById(old_assembly_func_id) == NULL);

  // Get the 2 new blocks that replaced the assembly func.
  BlockGraph::BlockMap::reverse_iterator block_it =
      block_graph_.blocks_mutable().rbegin();
  BlockGraph::Block* new_block2 = &((block_it++)->second);
  BlockGraph::Block* new_block1 = &(block_it->second);

  // We expect these blocks to be in the appropriate sections, and the order to
  // have been updated.
  EXPECT_EQ(text_section_->id(), new_block1->section());
  EXPECT_EQ(data_section_->id(), new_block2->section());
  EXPECT_EQ(order.sections[0].blocks[2].block, new_block1);
  EXPECT_EQ(order.sections[1].blocks[1].block, new_block2);
}

}  // namespace transforms
}  // namespace reorder
