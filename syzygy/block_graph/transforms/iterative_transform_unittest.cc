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
// Unittests for iteration primitives.

#include "syzygy/block_graph/transforms/iterative_transform.h"

#include "base/bind.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/block_graph/unittest_util.h"

namespace block_graph {
namespace transforms {

namespace {

using testing::_;
using testing::Invoke;
using testing::Return;
using testing::StrictMock;

class IterativeTransformTest : public testing::Test {
 public:
  IterativeTransformTest() : header_block_(NULL) { }

  virtual void SetUp() {
    header_block_ = block_graph_.AddBlock(BlockGraph::DATA_BLOCK, 10, "Header");
    BlockGraph::Block* block =
        block_graph_.AddBlock(BlockGraph::DATA_BLOCK, 10, "Data");
    ASSERT_TRUE(block != NULL);
  }

 protected:
  testing::DummyTransformPolicy policy_;
  BlockGraph block_graph_;
  BlockGraph::Block* header_block_;
};

class MockIterativeTransform
    : public IterativeTransformImpl<MockIterativeTransform> {
 public:
  MOCK_METHOD3(PreBlockGraphIteration,
               bool(const TransformPolicyInterface*,
                    BlockGraph*,
                    BlockGraph::Block*));
  MOCK_METHOD3(OnBlock,
               bool(const TransformPolicyInterface*,
                    BlockGraph*,
                    BlockGraph::Block*));
  MOCK_METHOD3(PostBlockGraphIteration,
               bool(const TransformPolicyInterface*,
                    BlockGraph*,
                    BlockGraph::Block*));

  bool DeleteBlock(const TransformPolicyInterface* policy,
                   BlockGraph* block_graph,
                   BlockGraph::Block* block) {
    return block_graph->RemoveBlock(block);
  }

  bool AddBlock(const TransformPolicyInterface* policy,
                BlockGraph* block_graph,
                BlockGraph::Block* block) {
    BlockGraph::Block* new_block =
        block_graph->AddBlock(BlockGraph::DATA_BLOCK, 10, "Added");
    return new_block != NULL;
  }

  static const char kTransformName[];
};

const char MockIterativeTransform::kTransformName[] =
    "MockIterativeTransform";

}  // namespace

TEST_F(IterativeTransformTest, PreBlockGraphIterationFails) {
  StrictMock<MockIterativeTransform> transform;
  EXPECT_CALL(transform, PreBlockGraphIteration(_, _, _)).Times(1).
      WillOnce(Return(false));
  EXPECT_CALL(transform, OnBlock(_, _, _)).Times(0);
  EXPECT_CALL(transform, PostBlockGraphIteration(_, _, _)).Times(0);
  EXPECT_FALSE(transform.TransformBlockGraph(
      &policy_, &block_graph_, header_block_));
  EXPECT_EQ(2u, block_graph_.blocks().size());
}

TEST_F(IterativeTransformTest, OnBlockFails) {
  StrictMock<MockIterativeTransform> transform;
  EXPECT_CALL(transform, PreBlockGraphIteration(_, _, _)).Times(1).
      WillOnce(Return(true));
  EXPECT_CALL(transform, OnBlock(_, _, _)).Times(1).WillOnce(Return(false));
  EXPECT_CALL(transform, PostBlockGraphIteration(_, _, _)).Times(0);
  EXPECT_FALSE(transform.TransformBlockGraph(
      &policy_, &block_graph_, header_block_));
  EXPECT_EQ(2u, block_graph_.blocks().size());
}

TEST_F(IterativeTransformTest, PostBlockGraphIterationFails) {
  StrictMock<MockIterativeTransform> transform;
  EXPECT_CALL(transform, PreBlockGraphIteration(_, _, _)).Times(1).
      WillOnce(Return(true));
  EXPECT_CALL(transform, OnBlock(_, _, _)).Times(2).
      WillRepeatedly(Return(true));
  EXPECT_CALL(transform, PostBlockGraphIteration(_, _, _)).Times(1).
      WillOnce(Return(false));
  EXPECT_FALSE(transform.TransformBlockGraph(
      &policy_, &block_graph_, header_block_));
  EXPECT_EQ(2u, block_graph_.blocks().size());
}

TEST_F(IterativeTransformTest, Normal) {
  StrictMock<MockIterativeTransform> transform;
  EXPECT_CALL(transform, PreBlockGraphIteration(_, _, _)).Times(1).
      WillOnce(Return(true));
  EXPECT_CALL(transform, OnBlock(_, _, _)).Times(2).
      WillRepeatedly(Return(true));
  EXPECT_CALL(transform, PostBlockGraphIteration(_, _, _)).Times(1).
      WillOnce(Return(true));
  EXPECT_TRUE(transform.TransformBlockGraph(
      &policy_, &block_graph_, header_block_));
  EXPECT_EQ(2u, block_graph_.blocks().size());
}

TEST_F(IterativeTransformTest, Add) {
  StrictMock<MockIterativeTransform> transform;
  EXPECT_CALL(transform, PreBlockGraphIteration(_, _, _)).Times(1).
      WillOnce(Return(true));
  EXPECT_CALL(transform, PostBlockGraphIteration(_, _, _)).Times(1).
      WillOnce(Return(true));

  EXPECT_CALL(transform, OnBlock(_, _, _)).Times(2).WillOnce(Return(true)).
      WillOnce(Invoke(&transform, &MockIterativeTransform::AddBlock));

  EXPECT_TRUE(transform.TransformBlockGraph(
      &policy_, &block_graph_, header_block_));
  EXPECT_EQ(3u, block_graph_.blocks().size());
}

TEST_F(IterativeTransformTest, Delete) {
  StrictMock<MockIterativeTransform> transform;
  EXPECT_CALL(transform, PreBlockGraphIteration(_, _, _)).Times(1).
      WillOnce(Return(true));
  EXPECT_CALL(transform, PostBlockGraphIteration(_, _, _)).Times(1).
      WillOnce(Return(true));

  EXPECT_CALL(transform, OnBlock(_, _, _)).Times(2).WillOnce(Return(true)).
      WillOnce(Invoke(&transform, &MockIterativeTransform::DeleteBlock));

  EXPECT_TRUE(transform.TransformBlockGraph(
      &policy_, &block_graph_, header_block_));
  EXPECT_EQ(1u, block_graph_.blocks().size());
}

TEST_F(IterativeTransformTest, AddAndDelete) {
  StrictMock<MockIterativeTransform> transform;
  EXPECT_CALL(transform, PreBlockGraphIteration(_, _, _)).Times(1).
      WillOnce(Return(true));
  EXPECT_CALL(transform, PostBlockGraphIteration(_, _, _)).Times(1).
      WillOnce(Return(true));

  EXPECT_CALL(transform, OnBlock(_, _, _)).Times(2).
      WillOnce(Invoke(&transform, &MockIterativeTransform::AddBlock)).
      WillOnce(Invoke(&transform, &MockIterativeTransform::DeleteBlock));

  EXPECT_TRUE(transform.TransformBlockGraph(
      &policy_, &block_graph_, header_block_));
  EXPECT_EQ(2u, block_graph_.blocks().size());
}

}  // namespace transforms
}  // namespace block_graph
