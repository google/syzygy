// Copyright 2012 Google Inc.
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

#include "syzygy/block_graph/transforms/trim_transform.h"

#include "gtest/gtest.h"

namespace block_graph {
namespace transforms {

namespace {

static const size_t kPtrSize = 4;
static const uint8 kDummyData[] = { 0xaa, 0xbb, 0xcc, 0xdd };

}  // namespace

TEST(TrimTransformTest, BlocksAreTrimmed) {
  BlockGraph bg;

  // These blocks have no references. The first should be trimmed and the
  // second left alone.
  BlockGraph::Block* b1 = bg.AddBlock(BlockGraph::CODE_BLOCK, 10, "b1");
  BlockGraph::Block* b2 = bg.AddBlock(BlockGraph::CODE_BLOCK, 10, "b2");
  b1->SetData(kDummyData, sizeof(kDummyData));
  b1->ResizeData(10);
  b2->SetData(kDummyData, sizeof(kDummyData));

  // These blocks have references. The first should be trimmed, the second
  // left alone and the third should be extended.
  BlockGraph::Block* b3 = bg.AddBlock(BlockGraph::CODE_BLOCK, 10, "b3");
  BlockGraph::Block* b4 = bg.AddBlock(BlockGraph::CODE_BLOCK, 10, "b4");
  BlockGraph::Block* b5 = bg.AddBlock(BlockGraph::CODE_BLOCK, 10, "b5");
  b3->ResizeData(10);
  b3->SetReference(0, BlockGraph::Reference(BlockGraph::RELATIVE_REF,
                                            kPtrSize, b1, 0));
  b4->ResizeData(kPtrSize);
  b4->SetReference(0, BlockGraph::Reference(BlockGraph::RELATIVE_REF,
                                            kPtrSize, b1, 0));
  b5->SetReference(0, BlockGraph::Reference(BlockGraph::RELATIVE_REF,
                                            kPtrSize, b1, 0));

  TrimTransform trim_transform;
  EXPECT_TRUE(ApplyTransform(&trim_transform, &bg, b1));
  EXPECT_EQ(sizeof(kDummyData), b1->data_size());
  EXPECT_EQ(sizeof(kDummyData), b2->data_size());
  EXPECT_EQ(kPtrSize, b3->data_size());
  EXPECT_EQ(kPtrSize, b4->data_size());
  EXPECT_EQ(kPtrSize, b5->data_size());
}

}  // namespace transforms
}  // namespace block_graph
