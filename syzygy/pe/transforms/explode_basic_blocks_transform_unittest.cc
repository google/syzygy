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

#include "syzygy/pe/transforms/explode_basic_blocks_transform.h"

#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/decomposer.h"
#include "syzygy/pe/unittest_util.h"

namespace pe {
namespace transforms {

using block_graph::BlockGraph;

namespace {

class ExplodeBasicBlocksTransformTest : public testing::PELibUnitTest {
 public:
  ExplodeBasicBlocksTransformTest()
      : image_layout_(&block_graph_),
        dos_header_block_(NULL) {
  }

  BlockGraph block_graph_;
  ImageLayout image_layout_;
  BlockGraph::Block* dos_header_block_;
};

}  // namespace

TEST_F(ExplodeBasicBlocksTransformTest, Apply) {
  PEFile pe_file;
  ASSERT_TRUE(pe_file.Init(testing::GetExeRelativePath(kDllName)));

  Decomposer decomposer(pe_file);
  ASSERT_TRUE(decomposer.Decompose(&image_layout_));

  dos_header_block_ = image_layout_.blocks.GetBlockByAddress(
      core::RelativeAddress(0));
  ASSERT_TRUE(dos_header_block_ != NULL);

  ExplodeBasicBlocksTransform transform;
  EXPECT_TRUE(block_graph::ApplyBlockGraphTransform(&transform,
                                                    &block_graph_,
                                                    dos_header_block_));

  // TODO(rogerm): Flesh out with validations.
}

}  // namespace transforms
}  // namespace pe
