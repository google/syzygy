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

#include "syzygy/pe/decomposer.h"

#include "base/file_util.h"
#include "base/path_service.h"
#include "base/string_util.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/block_graph/unittest_util.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/pe_utils.h"
#include "syzygy/pe/unittest_util.h"

namespace pe {

using block_graph::BlockGraph;
using core::RelativeAddress;

namespace {

class DecomposerTest: public testing::PELibUnitTest {
  // Insert your customizations here.
};

}  // namespace

TEST_F(DecomposerTest, Decompose) {
  FilePath image_path(testing::GetExeRelativePath(kDllName));
  PEFile image_file;

  ASSERT_TRUE(image_file.Init(image_path));

  // Decompose the test image and look at the result.
  Decomposer decomposer(image_file);
  EXPECT_TRUE(decomposer.pdb_path().empty());

  BlockGraph block_graph;
  ImageLayout image_layout(&block_graph);
  ASSERT_TRUE(decomposer.Decompose(&image_layout));
  EXPECT_FALSE(decomposer.pdb_path().empty());

  // Retrieve and validate the DOS header.
  BlockGraph::Block* dos_header_block =
      image_layout.blocks.GetBlockByAddress(RelativeAddress(0));
  ASSERT_TRUE(dos_header_block != NULL);
  ASSERT_TRUE(IsValidDosHeaderBlock(dos_header_block));

  // Retrieve and validate the NT header.
  BlockGraph::Block* nt_headers_block =
      GetNtHeadersBlockFromDosHeaderBlock(dos_header_block);
  ASSERT_TRUE(nt_headers_block != NULL);
  ASSERT_TRUE(IsValidNtHeadersBlock(nt_headers_block));

  // There should be some blocks in the graph and in the layout.
  EXPECT_NE(0U, block_graph.blocks().size());
  EXPECT_NE(0U, image_layout.blocks.address_space_impl().size());

  // All the blocks in the graph should be represented in the address space.
  EXPECT_EQ(block_graph.blocks().size(),
            image_layout.blocks.address_space_impl().size());

  ASSERT_EQ(6, image_layout.sections.size());

  EXPECT_EQ(".text", image_layout.sections[0].name);
  EXPECT_NE(0U, image_layout.sections[0].addr.value());
  EXPECT_NE(0U, image_layout.sections[0].size);
  EXPECT_NE(0U, image_layout.sections[0].data_size);
  EXPECT_EQ(IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
            image_layout.sections[0].characteristics);

  EXPECT_EQ(".rdata", image_layout.sections[1].name);
  EXPECT_NE(0U, image_layout.sections[1].addr.value());
  EXPECT_NE(0U, image_layout.sections[1].size);
  EXPECT_NE(0U, image_layout.sections[1].data_size);
  EXPECT_EQ(IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
            image_layout.sections[1].characteristics);

  EXPECT_EQ(".data", image_layout.sections[2].name);
  EXPECT_NE(0U, image_layout.sections[2].addr.value());
  EXPECT_NE(0U, image_layout.sections[2].size);
  EXPECT_NE(0U, image_layout.sections[2].data_size);
  EXPECT_EQ(
      IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
      image_layout.sections[2].characteristics);

  EXPECT_EQ(".tls", image_layout.sections[3].name);
  EXPECT_NE(0U, image_layout.sections[3].addr.value());
  EXPECT_NE(0U, image_layout.sections[3].size);
  EXPECT_NE(0U, image_layout.sections[3].data_size);
  EXPECT_EQ(
      IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
      image_layout.sections[3].characteristics);

  EXPECT_EQ(".rsrc", image_layout.sections[4].name);
  EXPECT_NE(0U, image_layout.sections[4].addr.value());
  EXPECT_NE(0U, image_layout.sections[4].size);
  EXPECT_NE(0U, image_layout.sections[4].data_size);
  EXPECT_EQ(IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
      image_layout.sections[4].characteristics);

  EXPECT_EQ(".reloc", image_layout.sections[5].name);
  EXPECT_NE(0U, image_layout.sections[5].addr.value());
  EXPECT_NE(0U, image_layout.sections[5].size);
  EXPECT_NE(0U, image_layout.sections[5].data_size);
  EXPECT_EQ(IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_DISCARDABLE |
      IMAGE_SCN_MEM_READ, image_layout.sections[5].characteristics);

  // We expect the ImageLayout sections to agree with the BlockGraph sections
  // in number, id, name and characteristics.
  EXPECT_EQ(block_graph.sections().size(), image_layout.sections.size());
  for (size_t i = 0; i < image_layout.sections.size(); ++i) {
    const BlockGraph::Section* section =
        block_graph.GetSectionById(i);
    ASSERT_TRUE(section != NULL);
    EXPECT_EQ(section->id(), i);
    EXPECT_EQ(section->name(), image_layout.sections[i].name);
    EXPECT_EQ(section->characteristics(),
              image_layout.sections[i].characteristics);
  }

  // We expect every block to be associated with a section, and only two blocks
  // should not be assigned to a section--the two header blocks.
  size_t non_section_blocks = 0;
  BlockGraph::BlockMap::const_iterator it =
      block_graph.blocks().begin();
  for (; it != block_graph.blocks().end(); ++it) {
    const BlockGraph::Block& block = it->second;
    if (block.section() == BlockGraph::kInvalidSectionId) {
      ++non_section_blocks;
    } else {
      // If this is not a header block, it should refer to a valid section id.
      EXPECT_LE(0u, block.section());
      EXPECT_LT(block.section(), block_graph.sections().size());
    }
  }
  EXPECT_EQ(2u, non_section_blocks);
}

TEST_F(DecomposerTest, DecomposeFailsWithNonexistentPdb) {
  FilePath image_path(testing::GetExeRelativePath(kDllName));
  PEFile image_file;

  ASSERT_TRUE(image_file.Init(image_path));

  Decomposer decomposer(image_file);
  decomposer.set_pdb_path(testing::GetExeRelativePath(L"nonexistent.pdb"));

  BlockGraph block_graph;
  ImageLayout image_layout(&block_graph);
  EXPECT_FALSE(decomposer.Decompose(&image_layout));
}

TEST_F(DecomposerTest, BlockGraphSerializationRoundTrip) {
  FilePath image_path(testing::GetExeRelativePath(kDllName));
  PEFile image_file;

  ASSERT_TRUE(image_file.Init(image_path));

  // Decompose the test image and look at the result.
  Decomposer decomposer(image_file);

  BlockGraph block_graph;
  ImageLayout image_layout(&block_graph);
  ASSERT_TRUE(decomposer.Decompose(&image_layout));

  FilePath temp_dir;
  CreateTemporaryDir(&temp_dir);
  FilePath temp_file_path = temp_dir.Append(L"test_dll.dll.bg");

  // Save the BlockGraph.
  {
    file_util::ScopedFILE temp_file(file_util::OpenFile(temp_file_path, "wb"));
    core::FileOutStream out_stream(temp_file.get());
    core::NativeBinaryOutArchive out_archive(&out_stream);
    EXPECT_TRUE(
        SaveDecomposition(image_file, block_graph, image_layout, &out_archive));
    EXPECT_TRUE(out_archive.Flush());
  }

  // Load the BlockGraph, and compare it to the original.
  {
    file_util::ScopedFILE temp_file(file_util::OpenFile(temp_file_path, "rb"));
    core::FileInStream in_stream(temp_file.get());
    core::NativeBinaryInArchive in_archive(&in_stream);
    PEFile in_image_file;
    BlockGraph in_block_graph;
    ImageLayout in_image_layout(&block_graph);
    EXPECT_TRUE(LoadDecomposition(&in_archive,
                                  &in_image_file,
                                  &in_block_graph,
                                  &in_image_layout));

    EXPECT_TRUE(testing::BlockGraphsEqual(block_graph,
                                          in_block_graph));
    EXPECT_THAT(image_layout.blocks.address_space_impl().ranges(),
        testing::ContainerEq(
            in_image_layout.blocks.address_space_impl().ranges()));

    EXPECT_THAT(image_layout.sections,
                testing::ContainerEq(in_image_layout.sections));
  }
}

TEST_F(DecomposerTest, BasicBlockDecompose) {
  FilePath image_path(testing::GetExeRelativePath(kDllName));
  PEFile image_file;

  ASSERT_TRUE(image_file.Init(image_path));

  // Decompose the test image and look at the result.
  Decomposer decomposer(image_file);

  BlockGraph block_graph;
  ImageLayout image_layout(&block_graph);
  ASSERT_TRUE(decomposer.Decompose(&image_layout));

  Decomposer::BasicBlockBreakdown breakdown;
  ASSERT_TRUE(decomposer.BasicBlockDecompose(image_layout, &breakdown));
  ASSERT_TRUE(breakdown.basic_block_address_space.begin() !=
      breakdown.basic_block_address_space.end());
}

}  // namespace pe
