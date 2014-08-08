// Copyright 2014 Google Inc. All Rights Reserved.
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

#include "syzygy/optimize/transforms/unreachable_block_transform.h"

#include "base/files/scoped_temp_dir.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/block_graph/block_graph.h"
#include "syzygy/optimize/application_profile.h"
#include "syzygy/pe/pe_transform_policy.h"

namespace optimize {
namespace transforms {

namespace {

using block_graph::BlockGraph;
using pe::ImageLayout;

// Dummy code body.
const uint8 kCodeBody1[] = { 0x74, 0x02, 0x33, 0xC0, 0xC3 };
const uint8 kCodeBody2[] = { 0x0B, 0xC0, 0x75, 0xFC, 0xC3 };

class UnreachableBlockTransformTest : public testing::Test {
 public:
  UnreachableBlockTransformTest()
      : code1_(NULL), code2_(NULL), image_(&block_graph_) {
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

    code3_ = block_graph_.AddBlock(BlockGraph::CODE_BLOCK,
                                   sizeof(kCodeBody2),
                                   "code3");
    DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), code3_);
    code3_->SetData(kCodeBody2, code2_->size());


    // Add a reference so that code1 is calling code2.
    code1_->SetReference(1, BlockGraph::Reference(BlockGraph::RELATIVE_REF,
                                BlockGraph::Reference::kMaximumSize,
                                code2_, 0, 0));

    // Keep track of the original blocks id.
    code1_id_ = code1_->id();
    code2_id_ = code2_->id();
    code3_id_ = code3_->id();
  }

 protected:
  pe::PETransformPolicy policy_;
  BlockGraph block_graph_;
  BlockGraph::Block* code1_;
  BlockGraph::Block* code2_;
  BlockGraph::Block* code3_;
  BlockGraph::BlockId code1_id_;
  BlockGraph::BlockId code2_id_;
  BlockGraph::BlockId code3_id_;
  UnreachableBlockTransform tx_;
  ImageLayout image_;
};

}  // namespace

TEST_F(UnreachableBlockTransformTest, UnusedBlockFromCode1) {
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), code1_);
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), code2_);
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), code3_);

  // Apply the unreachable transform.
  EXPECT_TRUE(tx_.TransformBlockGraph(&policy_, &block_graph_, code1_));

  // Validates that code1_ and code2_ are still present and code3_ has been
  // removed by the transform.
  EXPECT_EQ(code1_, block_graph_.GetBlockById(code1_id_));
  EXPECT_EQ(code2_, block_graph_.GetBlockById(code2_id_));
  EXPECT_EQ(NULL, block_graph_.GetBlockById(code3_id_));
}

TEST_F(UnreachableBlockTransformTest, UnusedBlockFromCode3) {
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), code1_);
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), code2_);
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), code3_);

  // Apply the unreachable transform.
  EXPECT_TRUE(tx_.TransformBlockGraph(&policy_, &block_graph_, code3_));

  // Validates that code3_ is still present and other blocks have been
  // removed by the transform.
  EXPECT_EQ(NULL, block_graph_.GetBlockById(code1_id_));
  EXPECT_EQ(NULL, block_graph_.GetBlockById(code2_id_));
  EXPECT_EQ(code3_, block_graph_.GetBlockById(code3_id_));
}

TEST_F(UnreachableBlockTransformTest, UsedPEParsedBlock) {
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), code1_);
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), code2_);
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), code3_);

  // Set code3_ as a root.
  code3_->set_attribute(BlockGraph::PE_PARSED);

  // Apply the unreachable transform.
  EXPECT_TRUE(tx_.TransformBlockGraph(&policy_, &block_graph_, code1_));

  // Validates that all blocks are still present.
  EXPECT_EQ(code1_, block_graph_.GetBlockById(code1_id_));
  EXPECT_EQ(code2_, block_graph_.GetBlockById(code2_id_));
  EXPECT_EQ(code3_, block_graph_.GetBlockById(code3_id_));
}

TEST_F(UnreachableBlockTransformTest, UnreachableGraphProduced) {
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), code1_);
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), code2_);
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), code3_);

  // Set the target path to dump the unreachable graph.
  base::ScopedTempDir temp_dir;
  EXPECT_TRUE(temp_dir.CreateUniqueTempDir());
  base::FilePath temp_path = temp_dir.path().Append(L"deadcode.cachegrind");
  tx_.set_unreachable_graph_path(temp_path);

  // Apply the unreachable transform.
  EXPECT_TRUE(tx_.TransformBlockGraph(&policy_, &block_graph_, code1_));

  // Read the contents of the produced file.
  std::string contents;
  base::ReadFileToString(temp_path, &contents);

  // Validate the output.
  const char expected[] = "events: Size Count\nob=\nfn=code3\n3 5 1\n\n";
  EXPECT_STREQ(expected, contents.c_str());
}


}  // namespace transforms
}  // namespace optimize
