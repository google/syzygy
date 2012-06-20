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
// Unittests for BlockGraph transform wrapper.

#include "syzygy/block_graph/transform.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace block_graph {

using testing::_;
using testing::Invoke;
using testing::Return;

namespace {

class ApplyBlockGraphTransformTest : public testing::Test {
 public:
  virtual void SetUp() {
    header_block_ = block_graph_.AddBlock(BlockGraph::DATA_BLOCK, 10, "Header");
  }

 protected:
  BlockGraph block_graph_;
  BlockGraph::Block* header_block_;
};

class MockBlockGraphTransform : public BlockGraphTransformInterface {
 public:
  virtual ~MockBlockGraphTransform() { }

  virtual const char* name() const { return "MockBlockGraphTransform"; }

  MOCK_METHOD2(TransformBlockGraph, bool(BlockGraph*, BlockGraph::Block*));

  bool DeleteHeader(BlockGraph* block_graph,
                    BlockGraph::Block* header_block) {
    CHECK(block_graph->RemoveBlock(header_block));
    return true;
  }
};

class ApplyBasicBlockSubGraphTransformTest : public testing::Test {
 public:
  virtual void SetUp() {
    header_block_ = block_graph_.AddBlock(BlockGraph::DATA_BLOCK, 10, "Header");
    code_block_ = block_graph_.AddBlock(BlockGraph::CODE_BLOCK, 10, "Code");
  }

 protected:
  BlockGraph block_graph_;
  BlockGraph::Block* header_block_;
  BlockGraph::Block* code_block_;
};

class MockBasicBlockSubGraphTransform :
    public BasicBlockSubGraphTransformInterface {
 public:
  virtual ~MockBasicBlockSubGraphTransform() { }

  virtual const char* name() const { return "MockBasicBlockSubGraphTransform"; }

  MOCK_METHOD2(TransformBasicBlockSubGraph,
               bool(BlockGraph*, BasicBlockSubGraph*));
};

}  // namespace

TEST_F(ApplyBlockGraphTransformTest, NormalTransformSucceeds) {
  MockBlockGraphTransform transform;
  EXPECT_CALL(transform, TransformBlockGraph(_, _)).Times(1).
      WillOnce(Return(true));
  EXPECT_TRUE(ApplyBlockGraphTransform(&transform,
                                       &block_graph_,
                                       header_block_));
}

TEST_F(ApplyBlockGraphTransformTest, DeletingHeaderFails) {
  MockBlockGraphTransform transform;
  EXPECT_CALL(transform, TransformBlockGraph(_, _)).Times(1).WillOnce(
      Invoke(&transform, &MockBlockGraphTransform::DeleteHeader));
  EXPECT_FALSE(ApplyBlockGraphTransform(&transform,
                                        &block_graph_,
                                        header_block_));
}

TEST_F(ApplyBasicBlockSubGraphTransformTest, TransformFails) {
  // TODO(chrisha): Make proper unittests once the implementation has been
  //     fleshed out.
  MockBasicBlockSubGraphTransform transform;
  EXPECT_CALL(transform, TransformBasicBlockSubGraph(_, _)).Times(1).
      WillOnce(Return(true));
  EXPECT_FALSE(ApplyBasicBlockSubGraphTransform(&transform,
                                                &block_graph_,
                                                code_block_));
}

}  // namespace block_graph
