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

#include "syzygy/optimize/transforms/block_alignment_transform.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/block_graph/basic_block_decomposer.h"
#include "syzygy/block_graph/block_builder.h"
#include "syzygy/block_graph/block_graph.h"
#include "syzygy/pe/pe_transform_policy.h"

namespace optimize {
namespace transforms {

namespace {

using block_graph::BasicBlockDecomposer;
using block_graph::BlockBuilder;
using block_graph::BlockGraph;
using block_graph::BasicBlockSubGraph;
using optimize::ApplicationProfile;
using optimize::SubGraphProfile;
using pe::ImageLayout;

// Dummy code body.
const uint8 kCodeBody1[] = { 0x74, 0x02, 0x33, 0xC0, 0xC3 };
const uint8 kCodeBody2[] = { 0x0B, 0xC0, 0x75, 0xFC, 0xC3 };

class BlockAlignmentTransformTest : public testing::Test {
 public:
  BlockAlignmentTransformTest()
      : code1_(NULL), code2_(NULL), image_(&block_graph_), profile_(&image_) {
  }

  virtual void SetUp() {
    code1_ = block_graph_.AddBlock(BlockGraph::CODE_BLOCK,
                                   sizeof(kCodeBody1),
                                   "code1");
    DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), code1_);
    code1_->SetData(kCodeBody1, code1_->size());

    code2_ = block_graph_.AddBlock(BlockGraph::CODE_BLOCK,
                                   sizeof(kCodeBody2),
                                   "code2");
    DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), code2_);
    code2_->SetData(kCodeBody2, code2_->size());
  }

  void ApplyTransform(BlockGraph::Block** block);

 protected:
  pe::PETransformPolicy policy_;
  BlockGraph block_graph_;
  BlockGraph::Block* code1_;
  BlockGraph::Block* code2_;
  BlockAlignmentTransform tx_;
  ImageLayout image_;
  ApplicationProfile profile_;
  SubGraphProfile subgraph_profile_;
};

void BlockAlignmentTransformTest::ApplyTransform(BlockGraph::Block** block) {
  // Decompose to subgraph.
  BasicBlockSubGraph subgraph;
  BasicBlockDecomposer decomposer(*block, &subgraph);
  ASSERT_TRUE(decomposer.Decompose());

  // Apply block alignment transform.
  ASSERT_TRUE(
      tx_.TransformBasicBlockSubGraph(&policy_, &block_graph_, &subgraph,
                                      &profile_, &subgraph_profile_));

  // Rebuild block.
  BlockBuilder builder(&block_graph_);
  ASSERT_TRUE(builder.Merge(&subgraph));
  CHECK_EQ(1u, builder.new_blocks().size());
  *block = *builder.new_blocks().begin();
}

}  // namespace

TEST_F(BlockAlignmentTransformTest, AlignmentTest) {
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), code1_);
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), code2_);

  ApplyTransform(&code1_);
  EXPECT_EQ(32U, code1_->alignment());

  code2_->set_alignment(2);
  ApplyTransform(&code2_);
  EXPECT_EQ(2U, code2_->alignment());
}

}  // namespace transforms
}  // namespace optimize
