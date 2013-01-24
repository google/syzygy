// Copyright 2011 Google Inc. All Rights Reserved.
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
// Unittests for iteration primitives.

#include "syzygy/block_graph/iterate.h"

#include "base/bind.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace block_graph {

using testing::_;
using testing::Invoke;
using testing::Return;
using testing::StrictMock;

namespace {

class IterationTest : public testing::Test {
 public:
  virtual void SetUp() {
    header_block_ = block_graph_.AddBlock(BlockGraph::DATA_BLOCK, 10, "Header");

    // Create a text section with some blocks.
    BlockGraph::Section* section = block_graph_.AddSection(".text", 0);
    BlockGraph::Block* block = block_graph_.AddBlock(
        BlockGraph::CODE_BLOCK, 10, "FunctionA");
    block->set_section(section->id());

    // Create a data section with some blocks.
    section = block_graph_.AddSection(".data", 0);
    block = block_graph_.AddBlock(
        BlockGraph::DATA_BLOCK, 10, "DatumA");
    block->set_section(section->id());
  }

 protected:
  BlockGraph block_graph_;
  BlockGraph::Block* header_block_;
};

class MockIterationCallback {
 public:
  MOCK_METHOD2(OnBlock, bool(BlockGraph* block_graph,
                             BlockGraph::Block* block));

  bool DeleteBlock(BlockGraph* block_graph, BlockGraph::Block* block) {
    return block_graph->RemoveBlock(block);
  }

  bool AddBlock(BlockGraph* block_graph, BlockGraph::Block* block) {
    BlockGraph::Block* new_block = block_graph->AddBlock(
        block->type(), 10, "New block");
    return new_block != NULL;
  }
};

}  // namespace

TEST_F(IterationTest, Iterate) {
  StrictMock<MockIterationCallback> callback;

  EXPECT_CALL(callback, OnBlock(_, _)).Times(3).
      WillRepeatedly(Return(true));

  EXPECT_TRUE(IterateBlockGraph(
      base::Bind(&MockIterationCallback::OnBlock,
                 base::Unretained(&callback)),
      &block_graph_));
  EXPECT_EQ(3u, block_graph_.blocks().size());
}

TEST_F(IterationTest, IterateDelete) {
  StrictMock<MockIterationCallback> callback;

  EXPECT_CALL(callback, OnBlock(_, _)).Times(3).
      WillOnce(Return(true)).
      WillOnce(Invoke(&callback, &MockIterationCallback::DeleteBlock)).
      WillOnce(Return(true));

  EXPECT_TRUE(IterateBlockGraph(
      base::Bind(&MockIterationCallback::OnBlock,
                 base::Unretained(&callback)),
      &block_graph_));
  EXPECT_EQ(2u, block_graph_.blocks().size());
}

TEST_F(IterationTest, IterateAdd) {
  StrictMock<MockIterationCallback> callback;

  EXPECT_CALL(callback, OnBlock(_, _)).Times(3).
      WillOnce(Return(true)).
      WillOnce(Invoke(&callback, &MockIterationCallback::AddBlock)).
      WillOnce(Return(true));

  EXPECT_TRUE(IterateBlockGraph(
      base::Bind(&MockIterationCallback::OnBlock,
                 base::Unretained(&callback)),
      &block_graph_));
  EXPECT_EQ(4u, block_graph_.blocks().size());
}

TEST_F(IterationTest, IterateDeleteAdd) {
  StrictMock<MockIterationCallback> callback;

  EXPECT_CALL(callback, OnBlock(_, _)).Times(3).
      WillOnce(Invoke(&callback, &MockIterationCallback::DeleteBlock)).
      WillOnce(Invoke(&callback, &MockIterationCallback::AddBlock)).
      WillOnce(Return(true));

  EXPECT_TRUE(IterateBlockGraph(
      base::Bind(&MockIterationCallback::OnBlock,
                 base::Unretained(&callback)),
      &block_graph_));
  EXPECT_EQ(3u, block_graph_.blocks().size());
}

}  // namespace block_graph
