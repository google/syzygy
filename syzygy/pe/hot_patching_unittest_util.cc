// Copyright 2015 Google Inc. All Rights Reserved.
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

#include "syzygy/pe/hot_patching_unittest_util.h"

#include "syzygy/pe/transforms/pe_hot_patching_basic_block_transform.h"

namespace testing {

const char TestHotPatchingTransform::kTransformName[] =
    "TestHotPatchingTransform";

TestHotPatchingTransform::TestHotPatchingTransform() { }

TestHotPatchingTransform::~TestHotPatchingTransform() { }

bool TestHotPatchingTransform::OnBlock(const TransformPolicyInterface* policy,
                                       BlockGraph* block_graph,
                                       BlockGraph::Block* block) {
  DCHECK_NE(static_cast<TransformPolicyInterface*>(nullptr), policy);
  DCHECK_NE(static_cast<BlockGraph*>(nullptr), block_graph);
  DCHECK_NE(static_cast<BlockGraph::Block*>(nullptr), block);

  if (!policy->BlockIsSafeToBasicBlockDecompose(block))
    return true;

  // Apply the basic block transform to make the block hot patchable.
  pe::transforms::PEHotPatchingBasicBlockTransform transform;
  block_graph::BlockVector new_blocks;
  if (!ApplyBasicBlockSubGraphTransform(
          &transform, policy, block_graph, block, &new_blocks)) {
    return false;
  }

  // One new code block should be created.
  DCHECK_EQ(1U, new_blocks.size());

  // Collect transformed blocks.
  blocks_prepared_.push_back(new_blocks[0]);

  return true;
}

bool TestHotPatchingTransform::PostBlockGraphIteration(
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BlockGraph::Block* header_block) {
  DCHECK_NE(static_cast<TransformPolicyInterface*>(nullptr), policy);
  DCHECK_NE(static_cast<BlockGraph*>(nullptr), block_graph);
  DCHECK_NE(static_cast<BlockGraph::Block*>(nullptr), header_block);

  // Insert the hot patching metadata section.
  pe::transforms::AddHotPatchingMetadataTransform hp_metadata_transform;
  hp_metadata_transform.set_blocks_prepared(&blocks_prepared_);
  if (!ApplyBlockGraphTransform(&hp_metadata_transform, policy,
                                block_graph, header_block)) {
    return false;
  }

  return true;
}

HotPatchingTestDllTest::HotPatchingTestDllTest()
    : relinker_(&policy_),
      test_dll_path_(testing::GetExeRelativePath(testing::kTestDllName)) {
}

HotPatchingTestDllTest::~HotPatchingTestDllTest() { }

void HotPatchingTestDllTest::HotPatchInstrumentTestDll() {
  // Set up relinker.
  relinker_.set_input_path(test_dll_path_);
  relinker_.set_output_path(hp_test_dll_path_);
  relinker_.set_allow_overwrite(true);
  ASSERT_TRUE(relinker_.Init());

  // Make test.dll hot patchable.
  relinker_.AppendTransform(&hp_transform_);

  // Perform the actual relink.
  ASSERT_TRUE(relinker_.Relink());

  // Validate that the binary still loads.
  ASSERT_NO_FATAL_FAILURE(CheckTestDll(hp_test_dll_path_));
}

void HotPatchingTestDllTest::SetUp() {
  this->CreateTemporaryDir(&temp_dir_);
  hp_test_dll_path_ = temp_dir_.Append(testing::kTestDllName);
}

}  // namespace testing
