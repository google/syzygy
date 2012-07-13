// Copyright 2012 Google Inc.
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
// Unittests for reorder::orderers::ExplicitOrderer.

#include "syzygy/reorder/orderers/explicit_orderer.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace reorder {
namespace orderers {

namespace {

using block_graph::BlockGraph;
using block_graph::OrderedBlockGraph;
using testing::ContainerEq;

class ExplicitOrdererTest : public testing::Test {
 public:
  ExplicitOrdererTest() { }

  virtual void SetUp() {
    sections_.push_back(block_graph_.AddSection("0", 0));
    sections_.push_back(block_graph_.AddSection("1", 0));

    blocks_.push_back(block_graph_.AddBlock(BlockGraph::DATA_BLOCK, 10, "0"));
    blocks_.push_back(block_graph_.AddBlock(BlockGraph::DATA_BLOCK, 10, "1"));
    blocks_.push_back(block_graph_.AddBlock(BlockGraph::DATA_BLOCK, 10, "2"));
    blocks_.push_back(block_graph_.AddBlock(BlockGraph::DATA_BLOCK, 10, "3"));

    blocks_[0]->set_section(sections_[0]->id());
    blocks_[1]->set_section(sections_[0]->id());
    blocks_[2]->set_section(sections_[1]->id());
    blocks_[3]->set_section(sections_[1]->id());
  }

  Reorderer::Order order_;
  BlockGraph block_graph_;

  std::vector<BlockGraph::Section*> sections_;
  block_graph::BlockVector blocks_;
};

template<typename Container>
Reorderer::Order::BlockList ToBlockList(const Container& container) {
  return Reorderer::Order::BlockList(container.begin(), container.end());
}

}  // namespace

TEST_F(ExplicitOrdererTest, FailsWithInvalidSection) {
  order_.section_block_lists[0xCCCCCCCC].push_back(blocks_[0]);

  OrderedBlockGraph obg(&block_graph_);
  ExplicitOrderer orderer(&order_);
  EXPECT_FALSE(orderer.OrderBlockGraph(&obg, NULL));
}

TEST_F(ExplicitOrdererTest, FailsWithInvalidBlock) {
  BlockGraph::SectionId sid = sections_[0]->id();
  order_.section_block_lists[sid].push_back(blocks_[0]);
  order_.section_block_lists[sid].push_back(
      reinterpret_cast<BlockGraph::Block*>(0xCCCCCCCC));

  OrderedBlockGraph obg(&block_graph_);
  ExplicitOrderer orderer(&order_);
  EXPECT_FALSE(orderer.OrderBlockGraph(&obg, NULL));
}

TEST_F(ExplicitOrdererTest, OrderIsAsExpected) {
  BlockGraph::SectionId sid0 = sections_[0]->id();
  BlockGraph::SectionId sid1 = sections_[1]->id();

  order_.section_block_lists[sid0].push_back(blocks_[2]);
  order_.section_block_lists[sid0].push_back(blocks_[3]);
  order_.section_block_lists[sid0].push_back(blocks_[1]);
  order_.section_block_lists[sid1].push_back(blocks_[0]);

  OrderedBlockGraph obg(&block_graph_);
  ExplicitOrderer orderer(&order_);
  EXPECT_TRUE(orderer.OrderBlockGraph(&obg, NULL));

  EXPECT_THAT(order_.section_block_lists[sid0],
              ContainerEq(ToBlockList(
                  obg.ordered_section(sections_[0]).ordered_blocks())));
  EXPECT_THAT(order_.section_block_lists[sid1],
              ContainerEq(ToBlockList(
                  obg.ordered_section(sections_[1]).ordered_blocks())));
}

}  // namespace orderers
}  // namespace reorder
