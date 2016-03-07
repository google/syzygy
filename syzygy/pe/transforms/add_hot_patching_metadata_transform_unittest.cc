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

#include "syzygy/pe/transforms/add_hot_patching_metadata_transform.h"

#include <unordered_set>

#include "gtest/gtest.h"
#include "syzygy/block_graph/hot_patching_metadata.h"
#include "syzygy/common/defs.h"
#include "syzygy/instrument/transforms/unittest_util.h"

namespace pe {
namespace transforms {

namespace {

using block_graph::BlockGraph;

// Expose the function needed for unittesting.
class TestAddHotPatchingMetadataTransform
    : public AddHotPatchingMetadataTransform {
 public:
  using AddHotPatchingMetadataTransform::CalculateCodeSize;
};

// Inserts all blocks that are safe to decompose into a container.
// @param block_container The blocks will be inserted into this container.
void BuildListOfDecomposableBlocks(
    const block_graph::TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    AddHotPatchingMetadataTransform::BlockVector* block_container) {
  // Make sure that test.dll has been decomposed first.
  ASSERT_NE(0U, block_graph->blocks().size());

  // Collect decomposable code blocks to test_blocks_ vector.
  for (auto &entry : block_graph->blocks_mutable()) {
    BlockGraph::Block* block = &entry.second;

    if (policy->BlockIsSafeToBasicBlockDecompose(block))
      block_container->push_back(block);
  }

  // Check that there are decomposable code blocks.
  EXPECT_NE(0U, block_container->size());
}

// A test fixture which knows how to decompose the "standard" test dll.
class AddHotPatchingMetadataTransformTest : public testing::PELibUnitTest {
 public:
  AddHotPatchingMetadataTransformTest() : layout_(&block_graph_) {}

  // The block graph for test_dll.dll.
  BlockGraph block_graph_;

  // The layout of test_dll.dll.
  pe::ImageLayout layout_;

  // The policy objects restricting how the transform is applied.
  pe::PETransformPolicy pe_policy_;

  // The PEFile instance referring to test_dll.
  pe::PEFile pe_file_;
};

}  // namespace

TEST(AddHotPatchingMetadataTransformSimpleTest, SetBlocksPrepared) {
  // Create an empty container.
  AddHotPatchingMetadataTransform::BlockVector cont;

  // Test set_blocks_prepared.
  AddHotPatchingMetadataTransform hpt;
  EXPECT_EQ(nullptr, hpt.blocks_prepared());
  hpt.set_blocks_prepared(&cont);
  EXPECT_EQ(&cont, hpt.blocks_prepared());
}

TEST(AddHotPatchingMetadataTransformSimpleTest, CalculateCodeSize) {
  BlockGraph block_graph;
  BlockGraph::Block* block = block_graph.AddBlock(BlockGraph::CODE_BLOCK,
                                                  100U,
                                                  "dummy");

  // Add some data to the block.
  static const uint8_t buffer[50];
  block->SetData(buffer, sizeof(buffer));

  // The whole data should be considered as code if there are no labels.
  ASSERT_EQ(50U, TestAddHotPatchingMetadataTransform::CalculateCodeSize(block));

  // A code label should not change the code size.
  block->SetLabel(20U, "CODE", BlockGraph::CODE_LABEL);
  ASSERT_EQ(50U, TestAddHotPatchingMetadataTransform::CalculateCodeSize(block));

  // A data label should limit the code size.
  block->SetLabel(30U, "DATA", BlockGraph::DATA_LABEL);
  ASSERT_EQ(30U, TestAddHotPatchingMetadataTransform::CalculateCodeSize(block));

  // A data label with other attributes set should limit the code size.
  block->SetLabel(29U,
                  "DATA",
                  BlockGraph::DATA_LABEL | BlockGraph::JUMP_TABLE_LABEL);
  ASSERT_EQ(29U, TestAddHotPatchingMetadataTransform::CalculateCodeSize(block));

  // A debug-end label at the end should be ignored.
  block->SetLabel(49U, "DEBUG-END", BlockGraph::DEBUG_END_LABEL);
  ASSERT_EQ(29U, TestAddHotPatchingMetadataTransform::CalculateCodeSize(block));
}

TEST_F(AddHotPatchingMetadataTransformTest, TransformBlockGraph) {
  DecomposeTestDll(&pe_file_, &layout_);

  BlockGraph::Block* header_block = layout_.blocks.GetBlockByAddress(
      core::RelativeAddress(0));
  ASSERT_NE(nullptr, header_block);

  // Save section and block map size for comparison later.
  size_t sections_before_size = block_graph_.sections().size();
  size_t blocks_before_size = block_graph_.blocks().size();

  // Create the transform.
  AddHotPatchingMetadataTransform hpt;

  // Initialize a blocks_prepared with some sample blocks
  AddHotPatchingMetadataTransform::BlockVector cont;
  BuildListOfDecomposableBlocks(&pe_policy_, &block_graph_, &cont);
  hpt.set_blocks_prepared(&cont);

  // Add hot patching section.
  hpt.TransformBlockGraph(&pe_policy_, &block_graph_, header_block);

  // Check that one new section and one new block is created.
  ASSERT_EQ(sections_before_size + 1, block_graph_.sections().size());
  ASSERT_EQ(blocks_before_size + 1, block_graph_.blocks().size());

  // Retrieve the new section.
  BlockGraph::Section* hp_metadata_section =
      block_graph_.FindSection(common::kHotPatchingMetadataSectionName);
  ASSERT_NE(nullptr, hp_metadata_section);

  // Retrieve the new block.
  BlockGraph::Block* hp_metadata_block = nullptr;
  for (auto &item: block_graph_.blocks_mutable()) {
    if (item.second.name() == common::kHotPatchingMetadataSectionName) {
      // This is the new block.
      hp_metadata_block = &item.second;
      break;
    }
  }
  ASSERT_NE(nullptr, hp_metadata_block);

  // Check hot patching metadata header.
  const block_graph::HotPatchingMetadataHeader* hp_metadata_header =
      reinterpret_cast<const block_graph::HotPatchingMetadataHeader*>(
          hp_metadata_block->data());
  ASSERT_NE(nullptr, hp_metadata_header);
  EXPECT_EQ(block_graph::kHotPatchingMetadataVersion,
            hp_metadata_header->version);
  EXPECT_EQ(hpt.blocks_prepared()->size(),
            hp_metadata_header->number_of_blocks);

  // Locate the block metadata array.
  // The (hp_metadata_header + 1) expression is a pointer pointing to the
  // location after the header.
  const block_graph::HotPatchingBlockMetadata* hp_block_metadata_arr =
      reinterpret_cast<const block_graph::HotPatchingBlockMetadata*>(
          hp_metadata_header + 1);

  // The new block should have a reference to each of the test blocks. This test
  // uses the assumption that the references to the blocks will be in the same
  // order as the blocks in blocks_prepared_.
  ASSERT_EQ(hpt.blocks_prepared()->size(),
            hp_metadata_block->references().size());
  int i = 0;
  for (const auto& ref_entry : hp_metadata_block->references()) {
    BlockGraph::Offset ref_offset = ref_entry.first;
    const BlockGraph::Reference& ref = ref_entry.second;

    // Check reference offset.
    EXPECT_EQ(reinterpret_cast<const uint8_t*>(
                  &hp_block_metadata_arr[i].relative_address) -
                  reinterpret_cast<const uint8_t*>(hp_metadata_header),
              ref_offset);

    // Check reference.
    EXPECT_EQ(0, ref.base());
    EXPECT_EQ(0, ref.offset());
    EXPECT_EQ(hpt.blocks_prepared()->operator[](i), ref.referenced());
    EXPECT_EQ(4U, ref.size());
    EXPECT_EQ(BlockGraph::RELATIVE_REF, ref.type());

    // Check if the code and data size information is correct.
    const BlockGraph::Block* original_block =
        hpt.blocks_prepared()->operator[](i);
    EXPECT_EQ(original_block->data_size(),
              hp_block_metadata_arr[i].block_size);
    EXPECT_EQ(TestAddHotPatchingMetadataTransform::CalculateCodeSize(
                  original_block),
              hp_block_metadata_arr[i].code_size);

    ++i;
  }
}

TEST_F(AddHotPatchingMetadataTransformTest, TransformBlockGraphEmpty) {
  DecomposeTestDll(&pe_file_, &layout_);

  BlockGraph::Block* header_block = layout_.blocks.GetBlockByAddress(
      core::RelativeAddress(0));
  ASSERT_NE(nullptr, header_block);

  // Save section and block map size for comparison later.
  size_t sections_before_size = block_graph_.sections().size();
  size_t blocks_before_size = block_graph_.blocks().size();

  // Create the transform.
  AddHotPatchingMetadataTransform hpt;

  // Initialize a blocks_prepared with empty container
  AddHotPatchingMetadataTransform::BlockVector cont;
  hpt.set_blocks_prepared(&cont);

  // Add hot patching section with some sample blocks.
  hpt.TransformBlockGraph(&pe_policy_, &block_graph_, header_block);

  // Check that no sections or blocks have been added.
  EXPECT_EQ(sections_before_size, block_graph_.sections().size());
  EXPECT_EQ(blocks_before_size, block_graph_.blocks().size());
}

}  // namespace transforms
}  // namespace pe
