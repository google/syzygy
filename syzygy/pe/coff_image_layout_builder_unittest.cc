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

#include "syzygy/pe/coff_image_layout_builder.h"

#include <cstring>

#include "gtest/gtest.h"
#include "syzygy/block_graph/typed_block.h"
#include "syzygy/block_graph/orderers/original_orderer.h"
#include "syzygy/common/align.h"
#include "syzygy/core/random_number_generator.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/coff_decomposer.h"
#include "syzygy/pe/coff_file.h"
#include "syzygy/pe/coff_file_writer.h"
#include "syzygy/pe/pe_utils.h"
#include "syzygy/pe/unittest_util.h"

namespace pe {
namespace {

using block_graph::BlockGraph;
using block_graph::ConstTypedBlock;
using block_graph::OrderedBlockGraph;
using core::RelativeAddress;

class ShuffleOrderer : public block_graph::BlockGraphOrdererInterface {
 public:
  explicit ShuffleOrderer(uint32 seed) : rng_(seed) {
  }

  virtual const char* name() const OVERRIDE {
    return "ShuffleOrderer";
  }

  // Shuffle sections while paying attention to put .debug$S sections at the
  // end, so that they come after the associated sections.
  virtual bool OrderBlockGraph(
      OrderedBlockGraph* ordered_graph,
      BlockGraph::Block* /* headers_block */) OVERRIDE {
    DCHECK(ordered_graph != NULL);
    BlockGraph* graph = ordered_graph->block_graph();
    DCHECK(graph != NULL);

    std::vector<BlockGraph::SectionId> sections;
    for (size_t i = 0; i < graph->sections().size(); ++i)
      sections.push_back(i);

    std::random_shuffle(sections.begin(), sections.end(), rng_);
    for (size_t i = 0; i < sections.size(); ++i) {
      BlockGraph::Section* section = graph->GetSectionById(sections[i]);
      if (section->name() == ".debug$S")
        ordered_graph->PlaceAtTail(section);
      else
        ordered_graph->PlaceAtHead(section);
    }

    return true;
  }

 private:
  core::RandomNumberGenerator rng_;
};

class CoffImageLayoutBuilderTest : public testing::PELibUnitTest {
 public:
  CoffImageLayoutBuilderTest() : image_layout_(&block_graph_) {
  }

  virtual void SetUp() OVERRIDE {
    test_dll_obj_path_ =
        testing::GetExeTestDataRelativePath(testing::kTestDllCoffObjName);
    ASSERT_NO_FATAL_FAILURE(CreateTemporaryDir(&temp_dir_path_));
    new_test_dll_obj_path_ = temp_dir_path_.Append(L"test_dll.obj");
  }

 protected:
  // Decompose, reorder, and lay out test_dll.coff_obj into a new object
  // file, located at new_test_dll_obj_path_.
  void RewriteTestDllObj(block_graph::BlockGraphOrdererInterface* orderer) {
    DCHECK(orderer != NULL);

    // Decompose the original image.
    CoffFile image_file;
    ASSERT_TRUE(image_file.Init(test_dll_obj_path_));

    CoffDecomposer decomposer(image_file);
    ASSERT_TRUE(decomposer.Decompose(&image_layout_));

    // Fetch headers block.
    ConstTypedBlock<IMAGE_FILE_HEADER> file_header;
    BlockGraph::Block* headers_block =
        image_layout_.blocks.GetBlockByAddress(RelativeAddress(0));
    ASSERT_TRUE(headers_block != NULL);
    ASSERT_TRUE(file_header.Init(0, headers_block));

    // Reorder using the specified ordering.
    OrderedBlockGraph ordered_graph(&block_graph_);
    ASSERT_TRUE(orderer->OrderBlockGraph(&ordered_graph, headers_block));

    // Wipe references from headers, so we can remove relocation blocks
    // during laying out.
    ASSERT_TRUE(headers_block->RemoveAllReferences());

    // Lay out new image.
    ImageLayout new_image_layout(&block_graph_);
    CoffImageLayoutBuilder layout_builder(&new_image_layout);
    ASSERT_TRUE(layout_builder.LayoutImage(ordered_graph));

    // Write temporary image file.
    CoffFileWriter writer(&new_image_layout);
    ASSERT_TRUE(writer.WriteImage(new_test_dll_obj_path_));
  }

  base::FilePath test_dll_obj_path_;
  base::FilePath new_test_dll_obj_path_;
  base::FilePath temp_dir_path_;

  // Original image layout and block graph.
  BlockGraph block_graph_;
  ImageLayout image_layout_;
};

}  // namespace

TEST_F(CoffImageLayoutBuilderTest, Redecompose) {
  block_graph::orderers::OriginalOrderer orig_orderer;
  ASSERT_NO_FATAL_FAILURE(RewriteTestDllObj(&orig_orderer));

  // Redecompose.
  CoffFile image_file;
  ASSERT_TRUE(image_file.Init(new_test_dll_obj_path_));

  CoffDecomposer decomposer(image_file);
  block_graph::BlockGraph block_graph;
  pe::ImageLayout image_layout(&block_graph);
  ASSERT_TRUE(decomposer.Decompose(&image_layout));

  // Compare the results of the two decompositions.
  ConstTypedBlock<IMAGE_FILE_HEADER> file_header;
  BlockGraph::Block* headers_block =
      image_layout.blocks.GetBlockByAddress(RelativeAddress(0));
  ASSERT_TRUE(headers_block != NULL);
  ASSERT_TRUE(file_header.Init(0, headers_block));

  EXPECT_EQ(image_layout_.sections.size(), image_layout.sections.size());
  EXPECT_EQ(image_layout_.blocks.size(), image_layout.blocks.size());

  // Expect same sections in the same order, due to original ordering.
  for (size_t i = 0; i < image_layout_.sections.size(); ++i) {
    EXPECT_EQ(image_layout_.sections[i].name, image_layout.sections[i].name);
    EXPECT_EQ(image_layout_.sections[i].characteristics,
              image_layout.sections[i].characteristics);
  }
}

TEST_F(CoffImageLayoutBuilderTest, Shuffle) {
  ShuffleOrderer shuffle_orderer(1234);
  ASSERT_NO_FATAL_FAILURE(RewriteTestDllObj(&shuffle_orderer));

  // Save rounded-up sizes of sections to which symbols point; these should
  // not change even if sections are shuffled.
  std::vector<size_t> symbol_ref_block_sizes;
  BlockGraph::BlockMap::const_iterator it =
      block_graph_.blocks().begin();
  for (; it != block_graph_.blocks().end(); ++it) {
    if ((it->second.attributes() & BlockGraph::COFF_SYMBOL_TABLE) == 0)
      continue;

    BlockGraph::Block::ReferenceMap::const_iterator ref_it =
        it->second.references().begin();
    for (; ref_it != it->second.references().end(); ++ref_it) {
      symbol_ref_block_sizes.push_back(
          common::AlignUp(ref_it->second.referenced()->data_size(), 4));
    }
  }

  // Redecompose.
  CoffFile image_file;
  ASSERT_TRUE(image_file.Init(new_test_dll_obj_path_));

  CoffDecomposer decomposer(image_file);
  block_graph::BlockGraph block_graph;
  pe::ImageLayout image_layout(&block_graph);
  ASSERT_TRUE(decomposer.Decompose(&image_layout));

  // Compare the results of the two decompositions.
  ConstTypedBlock<IMAGE_FILE_HEADER> file_header;
  BlockGraph::Block* headers_block =
      image_layout.blocks.GetBlockByAddress(RelativeAddress(0));
  ASSERT_TRUE(headers_block != NULL);
  ASSERT_TRUE(file_header.Init(0, headers_block));

  EXPECT_EQ(image_layout_.sections.size(), image_layout.sections.size());
  EXPECT_EQ(image_layout_.blocks.size(), image_layout.blocks.size());

  // Expect symbols to point to the same blocks they did in the previous
  // graph, though they will have been shuffled around.
  it = block_graph.blocks().begin();
  for (; it != block_graph.blocks().end(); ++it) {
    if ((it->second.attributes() & BlockGraph::COFF_SYMBOL_TABLE) == 0)
      continue;

    ASSERT_EQ(symbol_ref_block_sizes.size(), it->second.references().size());

    size_t i = 0;
    BlockGraph::Block::ReferenceMap::const_iterator ref_it =
        it->second.references().begin();
    for (; ref_it != it->second.references().end(); ++ref_it) {
      EXPECT_EQ(symbol_ref_block_sizes[i++],
                ref_it->second.referenced()->data_size());
    }
    EXPECT_EQ(symbol_ref_block_sizes.size(), i);
  }
}

}  // namespace pe
