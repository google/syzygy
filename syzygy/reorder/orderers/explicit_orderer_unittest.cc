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
// Unittests for reorder::orderers::ExplicitOrderer.

#include "syzygy/reorder/orderers/explicit_orderer.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/reorder/order_generator_test.h"

namespace reorder {
namespace orderers {

namespace {

using block_graph::BlockGraph;
using block_graph::OrderedBlockGraph;
using block_graph::ConstBlockVector;
using testing::ContainerEq;

typedef Reorderer::Order::BlockSpec BlockSpec;
typedef Reorderer::Order::BlockSpecVector BlockSpecVector;

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
ConstBlockVector ToBlockVector(const Container& container) {
  return ConstBlockVector(container.begin(), container.end());
}

template<>
ConstBlockVector ToBlockVector<BlockSpecVector>(
    const BlockSpecVector& container) {
  ConstBlockVector result;
  result.reserve(container.size());
  for (size_t i = 0; i < container.size(); ++i)
    result.push_back(container[i].block);
  return result;
}

}  // namespace

TEST_F(ExplicitOrdererTest, FailsWithInvalidSection) {
  order_.sections.resize(1);
  order_.sections[0].id = 0xCCCCCCCC;
  order_.sections[0].name = sections_[0]->name();
  order_.sections[0].characteristics = sections_[0]->characteristics();
  order_.sections[0].blocks.push_back(BlockSpec(blocks_[0]));

  OrderedBlockGraph obg(&block_graph_);
  ExplicitOrderer orderer(&order_);
  EXPECT_FALSE(orderer.OrderBlockGraph(&obg, NULL));
}

TEST_F(ExplicitOrdererTest, FailsWithInvalidBlock) {
  order_.sections.resize(1);
  order_.sections[0].id = sections_[0]->id();
  order_.sections[0].name = sections_[0]->name();
  order_.sections[0].characteristics = sections_[0]->characteristics();
  order_.sections[0].blocks.push_back(BlockSpec(blocks_[0]));
  order_.sections[0].blocks.push_back(
      BlockSpec(reinterpret_cast<BlockGraph::Block*>(0xCCCCCCCC)));

  OrderedBlockGraph obg(&block_graph_);
  ExplicitOrderer orderer(&order_);
  EXPECT_FALSE(orderer.OrderBlockGraph(&obg, NULL));
}

TEST_F(ExplicitOrdererTest, OrderIsAsExpected) {
  order_.sections.resize(2);

  order_.sections[0].id = sections_[0]->id();
  order_.sections[0].name = sections_[0]->name();
  order_.sections[0].characteristics = sections_[0]->characteristics();
  order_.sections[0].blocks.push_back(BlockSpec(blocks_[2]));
  order_.sections[0].blocks.push_back(BlockSpec(blocks_[3]));
  order_.sections[0].blocks.push_back(BlockSpec(blocks_[1]));

  order_.sections[1].id = sections_[1]->id();
  order_.sections[1].name = sections_[1]->name();
  order_.sections[1].characteristics = sections_[1]->characteristics();
  order_.sections[1].blocks.push_back(BlockSpec(blocks_[0]));

  OrderedBlockGraph obg(&block_graph_);
  ExplicitOrderer orderer(&order_);
  ASSERT_TRUE(orderer.OrderBlockGraph(&obg, NULL));

  EXPECT_THAT(ToBlockVector(order_.sections[0].blocks),
              ContainerEq(ToBlockVector(
                  obg.ordered_section(sections_[0]).ordered_blocks())));
  EXPECT_THAT(ToBlockVector(order_.sections[1].blocks),
              ContainerEq(ToBlockVector(
                  obg.ordered_section(sections_[1]).ordered_blocks())));
}

TEST_F(ExplicitOrdererTest, BasicBlockOrderFails) {
  order_.sections.resize(1);

  order_.sections[0].id = sections_[0]->id();
  order_.sections[0].name = sections_[0]->name();
  order_.sections[0].characteristics = sections_[0]->characteristics();
  order_.sections[0].blocks.push_back(BlockSpec(blocks_[2]));
  order_.sections[0].blocks[0].basic_block_offsets.push_back(0);
  order_.sections[0].blocks[0].basic_block_offsets.push_back(10);

  OrderedBlockGraph obg(&block_graph_);
  ExplicitOrderer orderer(&order_);
  ASSERT_FALSE(orderer.OrderBlockGraph(&obg, NULL));
}

}  // namespace orderers
}  // namespace reorder
