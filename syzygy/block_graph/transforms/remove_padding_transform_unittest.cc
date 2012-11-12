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

#include "syzygy/block_graph/transforms/remove_padding_transform.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace block_graph {
namespace transforms {

TEST(RemovePaddingTransformTest, PaddingIsRemoved) {
  BlockGraph bg;
  BlockGraph::Block* b1 = bg.AddBlock(BlockGraph::CODE_BLOCK, 10, "b1");
  BlockGraph::Block* b2 = bg.AddBlock(BlockGraph::CODE_BLOCK, 10, "b2");
  BlockGraph::Block* b3 = bg.AddBlock(BlockGraph::DATA_BLOCK, 10, "b3");
  BlockGraph::Block* b4 = bg.AddBlock(BlockGraph::DATA_BLOCK, 10, "b3");
  EXPECT_EQ(4u, bg.blocks().size());

  b2->set_attribute(BlockGraph::PADDING_BLOCK);
  b3->set_attribute(BlockGraph::PADDING_BLOCK);

  RemovePaddingTransform rm_pad_tx;
  EXPECT_TRUE(rm_pad_tx.TransformBlockGraph(&bg, b1));
  EXPECT_EQ(2u, bg.blocks().size());

  std::set<const BlockGraph::Block*> actual_blocks, expected_blocks;
  expected_blocks.insert(b1);
  expected_blocks.insert(b4);

  BlockGraph::BlockMap::const_iterator block_it = bg.blocks().begin();
  for (; block_it != bg.blocks().end(); ++block_it) {
    const BlockGraph::Block* block = &(block_it->second);
    actual_blocks.insert(block);
  }
  EXPECT_THAT(expected_blocks, testing::ContainerEq(actual_blocks));
}

}  // namespace transforms
}  // namespace block_graph
