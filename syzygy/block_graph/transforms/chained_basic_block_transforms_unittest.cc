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
//
// Unittests for ChainedBasicBlockTransforms.

#include "syzygy/block_graph/transforms/chained_basic_block_transforms.h"

#include "gtest/gtest.h"
#include "syzygy/block_graph/basic_block.h"
#include "syzygy/block_graph/basic_block_assembler.h"
#include "syzygy/block_graph/basic_block_decomposer.h"
#include "syzygy/block_graph/basic_block_subgraph.h"
#include "syzygy/block_graph/block_graph.h"
#include "syzygy/block_graph/transform.h"
#include "syzygy/block_graph/unittest_util.h"

#include "mnemonics.h"  // NOLINT

namespace block_graph {
namespace transforms {
namespace {

class TestChainedBasicBlockTransforms : public ChainedBasicBlockTransforms {
 public:
  using ChainedBasicBlockTransforms::transforms_;
};

const uint8 kData1Data[] =
    { 1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, 16 };

// kNop9 + kRet
const uint8 kCode1Data[] =
    { 0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC3 };
// kRet
const uint8 kCode2Data[] = { 0xC3 };

class ChainedBasicBlockTransformsTest : public testing::Test {
 public:
  virtual void SetUp() {
    BlockGraph::Block* d1 =
        block_graph_.AddBlock(BlockGraph::DATA_BLOCK, sizeof(kData1Data), "d1");
    ASSERT_NE(reinterpret_cast<BlockGraph::Block*>(NULL), d1);
    d1->SetData(kData1Data, sizeof(kData1Data));

    BlockGraph::Block* c1 =
        block_graph_.AddBlock(BlockGraph::CODE_BLOCK, sizeof(kCode1Data), "c1");
    ASSERT_NE(reinterpret_cast<BlockGraph::Block*>(NULL), c1);
    c1->SetData(kCode1Data, sizeof(kCode1Data));

    BlockGraph::Block* c2 =
        block_graph_.AddBlock(BlockGraph::CODE_BLOCK, sizeof(kCode2Data), "c2");
    ASSERT_NE(reinterpret_cast<BlockGraph::Block*>(NULL), c2);
    c2->SetData(kCode2Data, sizeof(kCode2Data));

    header_ = d1;
  }

  bool Relink(TestChainedBasicBlockTransforms* transform) {
    DCHECK_NE(reinterpret_cast<TestChainedBasicBlockTransforms*>(NULL),
              transform);
    return ApplyBlockGraphTransform(transform,
                                    &policy_,
                                    &block_graph_,
                                    header_);
  }

 protected:
  testing::DummyTransformPolicy policy_;
  BlockGraph block_graph_;
  BlockGraph::Block* header_;
};

class InsertOrRemoveBasicBlockTransform
    : public block_graph::transforms::NamedBasicBlockSubGraphTransformImpl<
                 InsertOrRemoveBasicBlockTransform> {
 public:
  InsertOrRemoveBasicBlockTransform(std::set<std::string>* blocks,
                                    bool insert)
      : blocks_(blocks), insert_(insert) {
  }

  bool TransformBasicBlockSubGraph(
      const TransformPolicyInterface* policy,
      BlockGraph* block_graph,
      BasicBlockSubGraph* basic_block_subgraph) OVERRIDE;

  static const char InsertOrRemoveBasicBlockTransform::kTransformName[];

  bool insert_;
  std::set<std::string>* blocks_;
};

bool InsertOrRemoveBasicBlockTransform::TransformBasicBlockSubGraph(
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BasicBlockSubGraph* subgraph) {
  DCHECK_NE(reinterpret_cast<TransformPolicyInterface*>(NULL), policy);
  DCHECK_NE(reinterpret_cast<BlockGraph*>(NULL), block_graph);
  DCHECK_NE(reinterpret_cast<BasicBlockSubGraph*>(NULL), subgraph);

  if (insert_) {
    blocks_->insert(subgraph->original_block()->name());
  } else {
    blocks_->erase(subgraph->original_block()->name());
  }

  return true;
}

const char InsertOrRemoveBasicBlockTransform::kTransformName[] =
    "InsertOrRemoveBasicBlockTransform";

}  // namespace

TEST_F(ChainedBasicBlockTransformsTest, NoTransforms) {
  TestChainedBasicBlockTransforms chains;
  EXPECT_EQ(std::string("ChainedBasicBlockTransforms"), chains.name());
  EXPECT_TRUE(chains.transforms_.empty());
}

TEST_F(ChainedBasicBlockTransformsTest, AppendTransforms) {
  std::set<std::string> blocks;
  InsertOrRemoveBasicBlockTransform insert(&blocks, true);
  InsertOrRemoveBasicBlockTransform remove(&blocks, false);

  // Validate AppendTransform.
  TestChainedBasicBlockTransforms chains;
  EXPECT_TRUE(chains.transforms_.empty());
  chains.AppendTransform(&insert);
  EXPECT_EQ(1U, chains.transforms_.size());
  chains.AppendTransform(&remove);
  EXPECT_EQ(2U, chains.transforms_.size());
}

TEST_F(ChainedBasicBlockTransformsTest, SingleTransforms) {
  std::set<std::string> blocks;
  InsertOrRemoveBasicBlockTransform insert(&blocks, true);

  TestChainedBasicBlockTransforms chains;
  chains.AppendTransform(&insert);
  EXPECT_TRUE(Relink(&chains));

  // Validate that the data block are ignored.
  EXPECT_TRUE(blocks.find("d1") == blocks.end());

  // Validate that code block are present.
  EXPECT_TRUE(blocks.find("c1") != blocks.end());
  EXPECT_TRUE(blocks.find("c2") != blocks.end());

  // Validate that insert pass was executed.
  EXPECT_EQ(2U, blocks.size());
}

TEST_F(ChainedBasicBlockTransformsTest, FullTransforms) {
  std::set<std::string> blocks;
  InsertOrRemoveBasicBlockTransform insert(&blocks, true);
  InsertOrRemoveBasicBlockTransform remove(&blocks, false);

  TestChainedBasicBlockTransforms chains;
  chains.AppendTransform(&insert);
  chains.AppendTransform(&remove);
  EXPECT_TRUE(Relink(&chains));

  // Validate that both passes were executed.
  EXPECT_TRUE(blocks.empty());
}

}  // namespace transforms
}  // namespace block_graph
