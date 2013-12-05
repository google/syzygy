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

#include "syzygy/optimize/transforms/basic_block_reordering_transform.h"

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
using pe::ImageLayout;

class BasicBlockReorderingTransformTest : public testing::Test {
 public:
  BasicBlockReorderingTransformTest()
      : image_(&block_graph_),
        profile_(&image_) {
  }

  void ApplyTransform(BlockGraph::Block** block);

 protected:
  pe::PETransformPolicy policy_;
  BlockGraph block_graph_;
  ImageLayout image_;
  BasicBlockReorderingTransform tx_;
  ApplicationProfile profile_;
  SubGraphProfile subgraph_profile_;
};

void BasicBlockReorderingTransformTest::ApplyTransform(
    BlockGraph::Block** block) {
  // Decompose to subgraph.
  BasicBlockSubGraph subgraph;
  BasicBlockDecomposer decomposer(*block, &subgraph);
  ASSERT_TRUE(decomposer.Decompose());

  // Apply block transform.
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

}  // namespace transforms
}  // namespace optimize
