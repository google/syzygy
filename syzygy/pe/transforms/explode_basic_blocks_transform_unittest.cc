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

#include "syzygy/pe/transforms/explode_basic_blocks_transform.h"

#include "gtest/gtest.h"
#include "syzygy/block_graph/orderers/random_orderer.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/decomposer.h"
#include "syzygy/pe/pe_relinker.h"
#include "syzygy/pe/unittest_util.h"

namespace pe {
namespace transforms {

using block_graph::BlockGraph;

namespace {

class ExplodeBasicBlocksTransformTest : public testing::PELibUnitTest {
 public:
  ExplodeBasicBlocksTransformTest()
      : image_layout_(&block_graph_),
        dos_header_block_(NULL),
        input_path_(testing::GetExeRelativePath(testing::kTestDllName)) {
  }

  virtual void SetUp() override {
    this->CreateTemporaryDir(&temp_dir_);
    output_path_ = temp_dir_.Append(testing::kTestDllName);
  }

  void PerformRandomizationTest(ExplodeBasicBlocksTransform* transform) {
    pe::PETransformPolicy policy;
    pe::PERelinker relinker(&policy);
    relinker.set_input_path(input_path_);
    relinker.set_output_path(output_path_);
    relinker.set_padding(8);
    relinker.set_add_metadata(true);
    relinker.set_allow_overwrite(true);
    relinker.set_augment_pdb(true);
    ASSERT_TRUE(relinker.Init());

    relinker.AppendTransform(transform);

    block_graph::orderers::RandomOrderer orderer(true, 123456);
    relinker.AppendOrderer(&orderer);

    // Perform the actual relink.
    ASSERT_TRUE(relinker.Relink());

    // Validate that the binary still loads.
    ASSERT_NO_FATAL_FAILURE(CheckTestDll(output_path_));
  }

  BlockGraph block_graph_;
  ImageLayout image_layout_;
  BlockGraph::Block* dos_header_block_;
  base::FilePath input_path_;
  base::FilePath temp_dir_;
  base::FilePath output_path_;
};

class DllMainRandomizer : public ExplodeBasicBlocksTransform {
 protected:
  bool SkipThisBlock(const BlockGraph::Block* candidate) override {
    return candidate->name() != "DllMain";
  }
};

}  // namespace

TEST_F(ExplodeBasicBlocksTransformTest, RandomizeDllMain) {
  DllMainRandomizer transform;
  PerformRandomizationTest(&transform);
}

TEST_F(ExplodeBasicBlocksTransformTest, RandomizeAllBasicBlocks) {
  ExplodeBasicBlocksTransform transform;
  PerformRandomizationTest(&transform);
}

TEST_F(ExplodeBasicBlocksTransformTest, RandomizeAllBasicBlocksNoPadding) {
  ExplodeBasicBlocksTransform transform;
  transform.set_exclude_padding(true);
  PerformRandomizationTest(&transform);
}

}  // namespace transforms
}  // namespace pe
