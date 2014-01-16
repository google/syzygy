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

#include "syzygy/pe/transforms/coff_convert_legacy_code_references_transform.h"

#include "gtest/gtest.h"
#include "syzygy/block_graph/unittest_util.h"

namespace pe {
namespace transforms {

namespace {

using block_graph::BlockGraph;

}  // namespace

TEST(CoffConvertLegacyCodeReferencesTransformTest, Succeeds) {
  testing::DummyTransformPolicy policy;
  BlockGraph bg;
  bg.set_image_format(BlockGraph::COFF_IMAGE);
  BlockGraph::Block* b0 = bg.AddBlock(BlockGraph::DATA_BLOCK, 10, "b0");
  BlockGraph::Block* b1 = bg.AddBlock(BlockGraph::CODE_BLOCK, 10, "b1");
  BlockGraph::Block* b2 = bg.AddBlock(BlockGraph::CODE_BLOCK, 10, "b2");

  b1->SetReference(0, BlockGraph::Reference(BlockGraph::ABSOLUTE_REF,
                                            BlockGraph::Reference::kMaximumSize,
                                            b2,
                                            0,
                                            0));

  CoffConvertLegacyCodeReferencesTransform tx;
  EXPECT_TRUE(tx.TransformBlockGraph(&policy, &bg, b0));

  // The reference type should have changed.
  BlockGraph::Reference ref;
  ASSERT_TRUE(b1->GetReference(0, &ref));
  ASSERT_EQ(BlockGraph::RELOC_ABSOLUTE_REF, ref.type());
}

}  // namespace transforms
}  // namespace pe
