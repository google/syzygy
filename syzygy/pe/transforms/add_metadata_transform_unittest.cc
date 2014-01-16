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

#include "syzygy/pe/transforms/add_metadata_transform.h"

#include "gtest/gtest.h"
#include "syzygy/block_graph/unittest_util.h"
#include "syzygy/common/defs.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/metadata.h"
#include "syzygy/pe/pe_utils.h"
#include "syzygy/pe/unittest_util.h"

namespace pe {
namespace transforms {

using block_graph::BlockGraph;
using block_graph::ApplyBlockGraphTransform;

namespace {

class AddMetadataTransformTest : public testing::PELibUnitTest {
 public:
  AddMetadataTransformTest()
      : module_path_(testing::GetExeRelativePath(testing::kTestDllName)),
        header_block_(NULL),
        metadata_block_(NULL) {
  }

  virtual void SetUp() OVERRIDE {
    testing::PELibUnitTest::SetUp();

    block_graph_.set_image_format(BlockGraph::PE_IMAGE);
    header_block_ = block_graph_.AddBlock(BlockGraph::DATA_BLOCK,
                                          10,
                                          "Header");
    ASSERT_TRUE(header_block_ != NULL);
  }

  void AddMetadataBlock() {
    BlockGraph::Section* section = block_graph_.FindOrAddSection(
        common::kSyzygyMetadataSectionName, kReadOnlyDataCharacteristics);
    ASSERT_TRUE(section != NULL);

    BlockGraph::Block* block = block_graph_.AddBlock(
        BlockGraph::DATA_BLOCK, 10, "Metadata");
    ASSERT_TRUE(block != NULL);
    block->set_section(section->id());

    metadata_block_ = block;
  }

  base::FilePath module_path_;
  testing::DummyTransformPolicy policy_;
  BlockGraph block_graph_;
  BlockGraph::Block* header_block_;
  BlockGraph::Block* metadata_block_;
};

}  // namespace

TEST_F(AddMetadataTransformTest, SucceedsWhenNoMetadata) {
  AddMetadataTransform transform(module_path_);
  EXPECT_TRUE(ApplyBlockGraphTransform(
      &transform, &policy_, &block_graph_, header_block_));
  EXPECT_TRUE(transform.metadata_block() != NULL);

  // Expect the metadata to decode.
  Metadata metadata;
  EXPECT_TRUE(metadata.LoadFromBlock(transform.metadata_block()));
  EXPECT_EQ(module_path_.value(), metadata.module_signature().path);
}

TEST_F(AddMetadataTransformTest, ReplaceSucceeds) {
  AddMetadataTransform transform(module_path_);
  AddMetadataBlock();
  EXPECT_TRUE(ApplyBlockGraphTransform(
      &transform, &policy_, &block_graph_, header_block_));
  EXPECT_EQ(metadata_block_, transform.metadata_block());

  // Expect the metadata to decode.
  Metadata metadata;
  EXPECT_TRUE(metadata.LoadFromBlock(transform.metadata_block()));
  EXPECT_EQ(module_path_.value(), metadata.module_signature().path);
}

TEST_F(AddMetadataTransformTest, FailsIfMultipleMetadataBlocks) {
  AddMetadataTransform transform(module_path_);
  AddMetadataBlock();
  AddMetadataBlock();
  EXPECT_FALSE(ApplyBlockGraphTransform(
      &transform, &policy_, &block_graph_, header_block_));
  EXPECT_EQ(NULL, transform.metadata_block());
}

}  // namespace transforms
}  // namespace pe
