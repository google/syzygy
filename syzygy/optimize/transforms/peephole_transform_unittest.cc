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

#include "syzygy/optimize/transforms/peephole_transform.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/block_graph/basic_block_decomposer.h"
#include "syzygy/block_graph/basic_block_subgraph.h"
#include "syzygy/block_graph/block_builder.h"
#include "syzygy/block_graph/block_graph.h"
#include "syzygy/optimize/application_profile.h"
#include "syzygy/pe/pe_transform_policy.h"

namespace optimize {
namespace transforms {

namespace {

using block_graph::BasicBlock;
using block_graph::BasicBlockDecomposer;
using block_graph::BasicBlockSubGraph;
using block_graph::BasicCodeBlock;
using block_graph::BlockBuilder;
using block_graph::BlockGraph;
using pe::ImageLayout;
using testing::ElementsAreArray;
typedef BasicBlock::Instructions Instructions;

// _asm push ebp
// _asm mov ebp, esp
// _asm pop ebp
// _asm xor eax, eax
// _asm ret
const uint8 kPrologEpilog[] = { 0x55, 0x8B, 0xEC, 0x5D, 0x33, 0xC0, 0xC3 };

const uint8 kTwicePrologEpilog[] =
    { 0x55, 0x8B, 0xEC, 0x5D, 0x55, 0x8B, 0xEC, 0x5D, 0x33, 0xC0, 0xC3 };

// _asm ret
const uint8 kRet[] = { 0xC3 };

// _asm xor eax, eax
// _asm ret
const uint8 kRet0[] = { 0x33, 0xC0, 0xC3 };

// _asm mov ecx, ecx
// _asm ret
const uint8 kMovIdentity[] = { 0x8B, 0xC9, 0xC3 };

enum TransformKind {
  ktransformBlock,
  ktransformSubgraph
};

class PeepholeTransformTest : public testing::Test {
 public:
  PeepholeTransformTest()
      : image_(&block_graph_),
        profile_(&image_),
        block_(NULL) {
  }

  void TransformBlock(TransformKind kind, const uint8* data, size_t length);

 protected:
  pe::PETransformPolicy policy_;
  BlockGraph block_graph_;
  ImageLayout image_;
  BlockGraph::Block* block_;
  PeepholeTransform tx_;
  ApplicationProfile profile_;
  SubGraphProfile subgraph_profile_;
};

void PeepholeTransformTest::TransformBlock(TransformKind kind,
                                           const uint8* data,
                                           size_t length) {
  DCHECK_NE(reinterpret_cast<const uint8*>(NULL), data);

  // Create a dummy block.
  block_ = block_graph_.AddBlock(BlockGraph::CODE_BLOCK, length, "test");
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), block_);
  block_->SetData(data, length);
  block_->SetLabel(0, "code", BlockGraph::CODE_LABEL);

  // Decompose to subgraph.
  BasicBlockSubGraph subgraph;
  BasicBlockDecomposer decomposer(block_, &subgraph);
  ASSERT_TRUE(decomposer.Decompose());

  switch (kind) {
    case ktransformBlock: {
      // Apply peephole transform.
      PeepholeTransform tx;
      ASSERT_TRUE(
          tx_.TransformBasicBlockSubGraph(&policy_, &block_graph_, &subgraph,
                                          &profile_, &subgraph_profile_));
      break;
    }
    case ktransformSubgraph: {
      // Apply peephole simplification on subgraph.
      ASSERT_TRUE(PeepholeTransform::SimplifySubgraph(&subgraph));
      break;
    }
  }

  // Rebuild block.
  BlockBuilder builder(&block_graph_);
  ASSERT_TRUE(builder.Merge(&subgraph));
  CHECK_EQ(1u, builder.new_blocks().size());
  block_ = *builder.new_blocks().begin();
};

}  // namespace

TEST_F(PeepholeTransformTest, SimplifyEmptyPrologEpilogBlock) {
  ASSERT_NO_FATAL_FAILURE(
      TransformBlock(ktransformBlock, kPrologEpilog, sizeof(kPrologEpilog)));
  EXPECT_THAT(kRet0, ElementsAreArray(block_->data(), block_->size()));
}

TEST_F(PeepholeTransformTest, SimplifyEmptyPrologEpilogSubgraph) {
  ASSERT_NO_FATAL_FAILURE(
      TransformBlock(ktransformSubgraph, kPrologEpilog, sizeof(kPrologEpilog)));
  EXPECT_THAT(kRet0, ElementsAreArray(block_->data(), block_->size()));
}

TEST_F(PeepholeTransformTest, SimplifyEmptyPrologEpilogTwice) {
  ASSERT_NO_FATAL_FAILURE(
      TransformBlock(ktransformBlock,
                     kTwicePrologEpilog,
                     sizeof(kTwicePrologEpilog)));
  EXPECT_THAT(kRet0, ElementsAreArray(block_->data(), block_->size()));
}

TEST_F(PeepholeTransformTest, SimplifyIdentityMov) {
  ASSERT_NO_FATAL_FAILURE(
      TransformBlock(ktransformBlock,
                     kMovIdentity,
                     sizeof(kMovIdentity)));
  EXPECT_THAT(kRet, ElementsAreArray(block_->data(), block_->size()));
}

}  // namespace transforms
}  // namespace optimize
