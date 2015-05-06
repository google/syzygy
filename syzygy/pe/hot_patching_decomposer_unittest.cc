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

// TODO(cseri): Write a test that tests what happens on a relocated .dll

#include "syzygy/pe/hot_patching_decomposer.h"

#include <windows.h>

#include "gtest/gtest.h"
#include "syzygy/block_graph/basic_block_decomposer.h"
#include "syzygy/instrument/transforms/asan_transform.h"
#include "syzygy/pe/hot_patching_unittest_util.h"

using block_graph::BlockGraph;

namespace pe {

namespace {

using core::RelativeAddress;

class HotPatchingDecomposerTest : public testing::HotPatchingTestDllTest {
 public:
  HotPatchingDecomposerTest() {}

  bool IsHotPatchableBlock(const BlockGraph::Block* block) {
    // The in-memory blockgraph contains two kinds of code blocks: the blocks
    // loaded from the metadata stream and the dummy blocks created while
    // parsing references. The latter has the BUILT_BY_UNSUPPORTED_COMPILER flag
    // set.
    return block->type() == BlockGraph::CODE_BLOCK &&
           !(block->attributes() & BlockGraph::BUILT_BY_UNSUPPORTED_COMPILER);
  }

  // Checks if the code and data labels are correctly loaded.
  // @param orig_block The original block.
  // @param block The decomposed block.
  // @param code_end The end of the code is written here.
  void CheckLabels(const BlockGraph::Block* orig_block,
                   const BlockGraph::Block* block,
                   BlockGraph::Offset* code_end) {
    // There should be a code label at position 0:
    ASSERT_EQ(1U, block->labels().count(0));
    EXPECT_TRUE(block->labels().at(0).has_attributes(BlockGraph::CODE_LABEL));

    if (block->labels().size() == 1) {
      // There is no data label, the whole block contains code.
      *code_end = static_cast<BlockGraph::Offset>(block->data_size());
    } else {
      // A data label must be the second label.
      // Recover the data label.
      auto it = ++block->labels().begin();
      EXPECT_TRUE(it->second.has_attributes(BlockGraph::DATA_LABEL));

      // The code size is the offset of the data label.
      *code_end = it->first;
    }

    // Compare recovered labels with the labels of the original block.
    // These must be true:
    // - There should be no DATA_LABEL before |*code_end|
    // - Each JUMP_TABLE_LABEL must be recovered.
    // - Each CASE_TABLE_LABEL must be recovered.
    for (const auto& entry : orig_block->labels()) {
      BlockGraph::Offset label_offset = entry.first;
      const BlockGraph::Label& orig_label = entry.second;

      if (orig_label.has_attributes(BlockGraph::DATA_LABEL)) {
        ASSERT_GE(label_offset, *code_end);
      }
      if (orig_label.has_attributes(BlockGraph::JUMP_TABLE_LABEL)) {
        ASSERT_EQ(1U, block->labels().count(label_offset));
        const BlockGraph::Label& label = block->labels().at(label_offset);

        EXPECT_TRUE(label.has_attributes(BlockGraph::DATA_LABEL));
        EXPECT_TRUE(label.has_attributes(BlockGraph::JUMP_TABLE_LABEL));
      }
      if (orig_label.has_attributes(BlockGraph::CASE_TABLE_LABEL)) {
        ASSERT_EQ(1U, block->labels().count(label_offset));
        const BlockGraph::Label& label = block->labels().at(label_offset);

        EXPECT_TRUE(label.has_attributes(BlockGraph::DATA_LABEL));
        EXPECT_TRUE(label.has_attributes(BlockGraph::CASE_TABLE_LABEL));
      }
    }
  }

  // Checks if the block data is correctly loaded.
  // @param orig_block The original block.
  // @param block The decomposed block.
  void CheckData(const BlockGraph::Block* orig_block,
                 const BlockGraph::Block* block) {
    // Compare the data in the block byte-by-byte.
    for (size_t i = 0; i < orig_block->data_size(); ++i) {
      // Do not compare bytes that belong to inter-block references and
      // in-block absolute references. These references don't have their
      // final value in the original block_graph because they are calculated
      // at a later phase of writing a PE file. Also, absolute references
      // might get relocated.
      auto ref_it = orig_block->references().find(i);
      if (ref_it != orig_block->references().end() &&
          (ref_it->second.referenced() != orig_block ||
              ref_it->second.type() == BlockGraph::ABSOLUTE_REF) ) {
        ASSERT_EQ(4U, ref_it->second.size()); // We expect 4-byte refs.
        i += ref_it->second.size() - 1;
        continue;
      }

      EXPECT_EQ(orig_block->data()[i], block->data()[i]);
    }
  }

  // Checks if the references are correctly loaded.
  // @param orig_block The original block.
  // @param block The decomposed block.
  // @param code_end The end of the code part of the block. A different set of
  //     references are loaded for the code and the data part.
  void CheckReferences(const BlockGraph::Block* orig_block,
                       const BlockGraph::Block* block,
                       BlockGraph::Offset code_end) {
    // Look at the references. The references in the decomposed block
    // must be a subset of the references in the original block.
    size_t found_references = 0U;
    for (const auto& entry : orig_block->references()) {
      BlockGraph::Offset ref_offset = entry.first;
      const BlockGraph::Reference& orig_ref = entry.second;

      BlockGraph::Reference ref;
      bool found = block->GetReference(ref_offset, &ref);

      // There references must be loaded in the code part:
      // - Inter-block PC-relative references.
      // - In-block absolute references, unless they refer a case table.
      if (ref_offset < code_end) {
        if (orig_ref.type() == BlockGraph::PC_RELATIVE_REF &&
            orig_block != orig_ref.referenced()) {
          EXPECT_TRUE(found);
        } else if (orig_ref.type() == BlockGraph::ABSOLUTE_REF &&
            orig_block == orig_ref.referenced()) {
          if (orig_block->labels().count(orig_ref.offset()) &&
              orig_block->labels().at(orig_ref.offset()).has_attributes(
                  BlockGraph::CASE_TABLE_LABEL)) {
          } else {
            EXPECT_TRUE(found);
          }
        }
      } else {
        // Only in-block references are required in the data part.
        if (orig_ref.referenced() == orig_block)
          EXPECT_TRUE(found);
      }

      if (!found)
        continue;

      ++found_references;

      if (IsHotPatchableBlock(ref.referenced())) {
        // Refers a hot patchable block.
        EXPECT_EQ(orig_ref.base(), ref.base());
        EXPECT_EQ(orig_ref.offset(), ref.offset());
        EXPECT_EQ(orig_ref.size(), ref.size());
        EXPECT_EQ(orig_ref.referenced()->addr(),
                  ref.referenced()->addr());
      } else {
        // Refers a code area not in a hot patchable block.
        EXPECT_EQ(0, ref.base());
        EXPECT_EQ(0, ref.offset());
        EXPECT_EQ(orig_ref.size(), ref.size());
        EXPECT_EQ(orig_ref.referenced()->addr() + orig_ref.offset(),
                  ref.referenced()->addr());
      }
      EXPECT_EQ(orig_ref.type(), ref.type());
    }
    // If these are not equal that means that there is a reference not present
    // in the original block.
    ASSERT_EQ(found_references, block->references().size());
  }

  void CheckIfBlockLoadedCorrectly(const BlockGraph::Block* orig_block,
                                   const BlockGraph::Block* block) {

    // Check that they have the same size.
    ASSERT_EQ(orig_block->data_size(), block->data_size());

    BlockGraph::Offset code_end = 0;
    ASSERT_NO_FATAL_FAILURE(CheckLabels(orig_block, block, &code_end));
    ASSERT_GT(code_end, 0);

    ASSERT_NO_FATAL_FAILURE(CheckData(orig_block, block));

    ASSERT_NO_FATAL_FAILURE(CheckReferences(orig_block, block, code_end));
  }

 protected:
  // The block graph containing the result of the in-memory decomposer.
  BlockGraph block_graph_;
};

}  // namespace

TEST_F(HotPatchingDecomposerTest, TestHotPatchingDecomposer) {
  ASSERT_NO_FATAL_FAILURE(HotPatchInstrumentTestDll());

  // Load hot patched library into memory.
  testing::ScopedHMODULE module;
  LoadTestDll(hp_test_dll_path_, &module);

  // Decompose hot patched library into a block graph.
  pe::ImageLayout layout(&block_graph_);
  HotPatchingDecomposer hp_decomposer(module);
  ASSERT_TRUE(hp_decomposer.Decompose(&layout));

  // Count code blocks to check if all of them is present in the decomposed
  // block graph.
  size_t code_block_count = 0;
  for (const auto& entry : block_graph_.blocks()) {
    const BlockGraph::Block* block = &entry.second;

    if (IsHotPatchableBlock(block)) {
      ++code_block_count;
    }
  }
  ASSERT_EQ(hp_transform_.blocks_prepared().size(), code_block_count);

  // Check that there is a corresponding block for each code block in the
  // original image with the same content.
  for (const auto& entry : block_graph_.blocks()) {
    const BlockGraph::Block* block = &entry.second;

    if (IsHotPatchableBlock(block)) {
      // To find the corresponding block we look for a block with that has
      // the same relative address. (The relinker updates the final relative
      // addresses to their final values.)
      int found = 0;
      for (const auto& orig_entry : relinker_.block_graph().blocks()) {
        const BlockGraph::Block* orig_block = &orig_entry.second;

        if (orig_block->addr() == block->addr()) {
          ++found;
          ASSERT_NO_FATAL_FAILURE(CheckIfBlockLoadedCorrectly(orig_block,
                                                              block));
        }
      }
      ASSERT_EQ(1, found);

      // Test if the decomposed block can be basic block decomposed. This test
      // ensures that we load all data needed for basic block decomposition.
      // Note: As the hot patching transformation uses a basic block
      // decomposer, all hot patchable blocks must be basic block
      // decomposable.
      block_graph::BasicBlockSubGraph subgraph;
      block_graph::BasicBlockDecomposer dec(block, &subgraph);
      ASSERT_TRUE(dec.Decompose());
    }
  }
}

}  // namespace pe
