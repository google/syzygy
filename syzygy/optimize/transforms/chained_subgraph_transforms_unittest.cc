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

#include "syzygy/optimize/transforms/chained_subgraph_transforms.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/block_graph/basic_block.h"
#include "syzygy/block_graph/basic_block_subgraph.h"
#include "syzygy/optimize/application_profile.h"
#include "syzygy/pe/pe_transform_policy.h"

namespace optimize {
namespace transforms {
namespace {

using block_graph::BlockGraph;
using block_graph::BasicBlockSubGraph;
using optimize::transforms::ChainedSubgraphTransforms;
using pe::ImageLayout;
using testing::_;
using testing::NotNull;
using testing::Property;
using testing::Return;

// _asm ret
const uint8 kCodeRet[] = { 0xC3 };

// Dummy data.
const uint8 kData[] = { 0x01, 0x02, 0x03, 0x04 };

class MockSubGraphTransformInterface : public SubGraphTransformInterface {
 public:
  MOCK_METHOD5(TransformBasicBlockSubGraph,
               bool(const TransformPolicyInterface*,
                    BlockGraph*,
                    BasicBlockSubGraph*,
                    ApplicationProfile*,
                    SubGraphProfile*));
};

class TestChainedBasicBlockTransforms: public ChainedSubgraphTransforms {
 public:
  explicit TestChainedBasicBlockTransforms(ApplicationProfile* profile)
      : ChainedSubgraphTransforms(profile) {
  }

  using ChainedSubgraphTransforms::profile_;
  using ChainedSubgraphTransforms::transforms_;
};

class ChainedSubgraphTransformsTest : public testing::Test {
 public:
  ChainedSubgraphTransformsTest()
      : block_header_(NULL), image_(&block_graph_), profile_(&image_) {
  }

  virtual void SetUp() {
    // Create the blocks.
    block1_ =
        block_graph_.AddBlock(BlockGraph::CODE_BLOCK, sizeof(kCodeRet), "b1");
    DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), block1_);
    block1_->SetData(kCodeRet, sizeof(kCodeRet));
    block1_->SetLabel(0, "code", BlockGraph::CODE_LABEL);

    block2_ =
        block_graph_.AddBlock(BlockGraph::CODE_BLOCK, sizeof(kCodeRet), "b2");
    DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), block2_);
    block2_->SetData(kCodeRet, sizeof(kCodeRet));
    block2_->SetLabel(0, "code", BlockGraph::CODE_LABEL);

    block3_ =
        block_graph_.AddBlock(BlockGraph::CODE_BLOCK, sizeof(kCodeRet), "b3");
    DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), block3_);
    block3_->SetData(kCodeRet, sizeof(kCodeRet));
    block3_->SetLabel(0, "code", BlockGraph::CODE_LABEL);

    block_header_ = block_graph_.AddBlock(BlockGraph::DATA_BLOCK,
                                          sizeof(kData),
                                          "header");
    DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), block_header_);
    block_header_->SetData(kData, sizeof(kData));

    // Create the text section.
    BlockGraph::Section* section = block_graph_.AddSection(".text", 0);
    pe::ImageLayout::SectionInfo section_info = {};
    section_info.name = section->name();
    section_info.addr = core::RelativeAddress(0x1000);
    section_info.size = 0x1000;
    section_info.data_size = 0x1000;
    image_.sections.push_back(section_info);

    // Create the layout information.
    block_header_->set_section(section->id());
    block1_->set_section(section->id());
    block2_->set_section(section->id());
    block3_->set_section(section->id());
    image_.blocks.InsertBlock(section_info.addr, block_header_);
    image_.blocks.InsertBlock(section_info.addr + 100, block1_);
    image_.blocks.InsertBlock(section_info.addr + 200, block2_);
    image_.blocks.InsertBlock(section_info.addr + 300, block3_);
  }

 protected:
  pe::PETransformPolicy policy_;
  BlockGraph block_graph_;
  BlockGraph::Block* block_header_;
  BlockGraph::Block* block1_;
  BlockGraph::Block* block2_;
  BlockGraph::Block* block3_;
  ImageLayout image_;
  ApplicationProfile profile_;
  scoped_ptr<SubGraphProfile> subgraph_profile_;
};

}  // namespace

TEST_F(ChainedSubgraphTransformsTest, Constructor) {
  TestChainedBasicBlockTransforms tx(&profile_);
  EXPECT_EQ(&profile_, tx.profile_);
}

TEST_F(ChainedSubgraphTransformsTest, TransformBlockGraphWithoutTransforms) {
  TestChainedBasicBlockTransforms tx(&profile_);
  ASSERT_TRUE(
      ApplyBlockGraphTransform(&tx, &policy_, &block_graph_, block_header_));
}

TEST_F(ChainedSubgraphTransformsTest, TransformBlockGraph) {
  TestChainedBasicBlockTransforms tx(&profile_);
  MockSubGraphTransformInterface transform1;
  MockSubGraphTransformInterface transform2;
  tx.AppendTransform(&transform1);
  tx.AppendTransform(&transform2);

  // Expect each transform to be applied to each block.
  BlockGraph::Block* blocks[] = { block1_, block2_, block3_ };
  MockSubGraphTransformInterface* transforms[] = { &transform1, &transform2 };

  for (size_t i = 0; i < arraysize(blocks); ++i) {
    for (size_t j = 0; j < arraysize(transforms); ++j) {
      EXPECT_CALL(
          *transforms[j],
          TransformBasicBlockSubGraph(&policy_,
                                      &block_graph_,
                                      Property(
                                          &BasicBlockSubGraph::original_block,
                                          blocks[i]),
                                      &profile_,
                                      NotNull()))
          .WillOnce(Return(true));
    }
  }

  ASSERT_TRUE(
      ApplyBlockGraphTransform(&tx, &policy_, &block_graph_, block_header_));
}

}  // namespace transforms
}  // namespace optimize
