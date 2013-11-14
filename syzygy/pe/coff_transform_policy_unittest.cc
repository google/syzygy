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

#include "syzygy/pe/coff_transform_policy.h"

#include "gtest/gtest.h"
#include "syzygy/block_graph/block_graph.h"

namespace pe {

namespace {

using block_graph::BlockGraph;

}  // namespace

TEST(CoffTransformPolicyTest, CodeBlockIsSafeToBasicBlockDecomposeSimple) {
  CoffTransformPolicy policy;
  BlockGraph bg;
  BlockGraph::Block* b = bg.AddBlock(BlockGraph::CODE_BLOCK, 1, "");
  b->SetLabel(0, "code", BlockGraph::CODE_LABEL);
  EXPECT_TRUE(policy.BlockIsSafeToBasicBlockDecompose(b));
}

TEST(CoffTransformPolicyTest, ReferenceIsSafeToRedirect) {
  CoffTransformPolicy policy;
  BlockGraph bg;
  BlockGraph::Block* b = bg.AddBlock(BlockGraph::CODE_BLOCK, 1, "");
  BlockGraph::Reference ref(BlockGraph::ABSOLUTE_REF, 4, b, 0, 0);
  EXPECT_TRUE(policy.ReferenceIsSafeToRedirect(b, ref));
}

}  // namespace pe
