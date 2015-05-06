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

#ifndef SYZYGY_PE_HOT_PATCHING_UNITTEST_UTIL_H_
#define SYZYGY_PE_HOT_PATCHING_UNITTEST_UTIL_H_

#include "base/files/file_path.h"
#include "gtest/gtest.h"
#include "syzygy/block_graph/transforms/iterative_transform.h"
#include "syzygy/pe/pe_relinker.h"
#include "syzygy/pe/unittest_util.h"
#include "syzygy/pe/transforms/add_hot_patching_metadata_transform.h"

namespace testing {

// Prepares every code block of a module for hot patching.
class TestHotPatchingTransform
    : public block_graph::transforms::IterativeTransformImpl<
          TestHotPatchingTransform> {
 public:
  typedef block_graph::BlockGraph BlockGraph;
  typedef block_graph::TransformPolicyInterface TransformPolicyInterface;
  typedef pe::transforms::AddHotPatchingMetadataTransform::BlockVector
      BlockVector;

  // The transform name.
  static const char kTransformName[];

  TestHotPatchingTransform();
  ~TestHotPatchingTransform();

  // After the transform has run, this function returns the blocks that have
  // been prepared for hot patching.
  const BlockVector& blocks_prepared() const {
    return blocks_prepared_;
  }

  // @name IterativeTransformImpl implementation.
  // @{
  // Prepare every safe-to-decompose block for hot patching.
  // @param policy The policy object restricting how the transform is applied.
  // @param block_graph The block graph being modified.
  // @param block The block to explode, this must be in @p block_graph.
  // @returns true.
  bool OnBlock(const TransformPolicyInterface* policy,
               BlockGraph* block_graph,
               BlockGraph::Block* block);

  // Add the metadata stream to the BlockGraph.
  // @param policy The policy object restricting how the transform is applied.
  // @param block_graph the block graph being transformed.
  // @param header_block the header block.
  // @returns true on success, false otherwise.
  bool PostBlockGraphIteration(const TransformPolicyInterface* policy,
                               BlockGraph* block_graph,
                               BlockGraph::Block* header_block);
  // @}

 private:
  // Store the blocks that have been prepared for hot patching. This is used
  // to generate the metadata.
  BlockVector blocks_prepared_;

  DISALLOW_COPY_AND_ASSIGN(TestHotPatchingTransform);
};

// An unit test fixture that relinks the test_dll.dll with hot patching
// information.
class HotPatchingTestDllTest : public testing::PELibUnitTest {
 public:
  HotPatchingTestDllTest();
  ~HotPatchingTestDllTest();

  // Relinks test_dll.dll using TestHotPatchingTransform that prepares the
  // blocks for hot patching and adds hot patching metadata.
  void HotPatchInstrumentTestDll();

  // Creates a temporary directory for the transformed DLL.
  virtual void SetUp() override;

 protected:
  pe::PETransformPolicy policy_;
  pe::PERelinker relinker_;

  // Path of the original test_dll.dll.
  base::FilePath test_dll_path_;
  // Path of the temporary directory where the hot patchable DLL will be saved.
  base::FilePath temp_dir_;
  // Path of the hot patchable test_dll.dll.
  base::FilePath hp_test_dll_path_;

  // The transform used to make test_dll.dll hot patchable.
  TestHotPatchingTransform hp_transform_;

  DISALLOW_COPY_AND_ASSIGN(HotPatchingTestDllTest);
};

}  // namespace testing

#endif  // SYZYGY_PE_HOT_PATCHING_UNITTEST_UTIL_H_
