// Copyright 2013 Google Inc. All Rights Reserved.
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

#include "syzygy/block_graph/orderer.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace block_graph {

namespace {

using testing::Return;

class LenientMockBlockGraphOrderer : public BlockGraphOrdererInterface {
 public:
  virtual ~LenientMockBlockGraphOrderer() { }
  virtual const char* name() const { return "MockBlockGraphOrderer"; }

  MOCK_METHOD2(OrderBlockGraph, bool(OrderedBlockGraph*, BlockGraph::Block*));
};
typedef testing::StrictMock<LenientMockBlockGraphOrderer>
    MockBlockGraphOrderer;

class BlockGraphOrdererTest : public testing::Test {
 public:
  virtual void SetUp() {
    header_block_ = block_graph_.AddBlock(BlockGraph::DATA_BLOCK, 1, "header");

    BlockGraph::Section* text = block_graph_.AddSection(".text", 0);
    BlockGraph::Section* rdata = block_graph_.AddSection(".rdata", 0);

    BlockGraph::Block* code = block_graph_.AddBlock(
        BlockGraph::CODE_BLOCK, 3, "code");
    BlockGraph::Block* data = block_graph_.AddBlock(
        BlockGraph::DATA_BLOCK, 2, "data");

    code->set_section(text->id());
    data->set_section(rdata->id());

    // Create the ordered block graph. This can only be created after the
    // block graph is set up.
    ordered_block_graph_.reset(new OrderedBlockGraph(&block_graph_));
  }

  BlockGraph block_graph_;
  BlockGraph::Block* header_block_;

  scoped_ptr<OrderedBlockGraph> ordered_block_graph_;
};

}  // namespace

TEST_F(BlockGraphOrdererTest, ApplyOrderersSucceeds) {
  MockBlockGraphOrderer o1, o2, o3;
  std::vector<BlockGraphOrdererInterface*> orderers;
  orderers.push_back(&o1);
  orderers.push_back(&o2);
  orderers.push_back(&o3);

  EXPECT_CALL(o1, OrderBlockGraph(ordered_block_graph_.get(), header_block_))
      .WillOnce(Return(true));
  EXPECT_CALL(o2, OrderBlockGraph(ordered_block_graph_.get(), header_block_))
      .WillOnce(Return(true));
  EXPECT_CALL(o3, OrderBlockGraph(ordered_block_graph_.get(), header_block_))
      .WillOnce(Return(true));

  EXPECT_TRUE(ApplyBlockGraphOrderers(
      orderers, ordered_block_graph_.get(), header_block_));
}

TEST_F(BlockGraphOrdererTest, ApplyOrderersFails) {
  MockBlockGraphOrderer o1, o2, o3;
  std::vector<BlockGraphOrdererInterface*> orderers;
  orderers.push_back(&o1);
  orderers.push_back(&o2);
  orderers.push_back(&o3);

  EXPECT_CALL(o1, OrderBlockGraph(ordered_block_graph_.get(), header_block_))
      .WillOnce(Return(true));
  EXPECT_CALL(o2, OrderBlockGraph(ordered_block_graph_.get(), header_block_))
      .WillOnce(Return(false));

  EXPECT_FALSE(ApplyBlockGraphOrderers(
      orderers, ordered_block_graph_.get(), header_block_));
}

}  // namespace block_graph
