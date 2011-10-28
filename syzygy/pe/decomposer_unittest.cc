// Copyright 2011 Google Inc.
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
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/pe_utils.h"
#include "syzygy/pe/unittest_util.h"

namespace {

class DecomposerTest: public testing::PELibUnitTest {
  // Insert your customizations here.
};

}  // namespace

namespace pe {

using core::BlockGraph;
using core::RelativeAddress;

TEST_F(DecomposerTest, Decompose) {
  FilePath image_path(GetExeRelativePath(kDllName));
  PEFile image_file;

  ASSERT_TRUE(image_file.Init(image_path));

  // Decompose the test image and look at the result.
  Decomposer decomposer(image_file);

  BlockGraph block_graph;
  ImageLayout image_layout(&block_graph);
  ASSERT_TRUE(decomposer.Decompose(&image_layout));

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

  ASSERT_EQ(6, image_layout.segments.size());

  EXPECT_EQ(".text", image_layout.segments[0].name);
  EXPECT_NE(0U, image_layout.segments[0].addr.value());
  EXPECT_NE(0U, image_layout.segments[0].size);
  EXPECT_NE(0U, image_layout.segments[0].data_size);
  EXPECT_EQ(IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
            image_layout.segments[0].characteristics);

  EXPECT_EQ(".rdata", image_layout.segments[1].name);
  EXPECT_NE(0U, image_layout.segments[1].addr.value());
  EXPECT_NE(0U, image_layout.segments[1].size);
  EXPECT_NE(0U, image_layout.segments[1].data_size);
  EXPECT_EQ(IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
            image_layout.segments[1].characteristics);

  EXPECT_EQ(".data", image_layout.segments[2].name);
  EXPECT_NE(0U, image_layout.segments[2].addr.value());
  EXPECT_NE(0U, image_layout.segments[2].size);
  EXPECT_NE(0U, image_layout.segments[2].data_size);
  EXPECT_EQ(
      IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
      image_layout.segments[2].characteristics);

  EXPECT_EQ(".tls", image_layout.segments[3].name);
  EXPECT_NE(0U, image_layout.segments[3].addr.value());
  EXPECT_NE(0U, image_layout.segments[3].size);
  EXPECT_NE(0U, image_layout.segments[3].data_size);
  EXPECT_EQ(
      IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
      image_layout.segments[3].characteristics);

  EXPECT_EQ(".rsrc", image_layout.segments[4].name);
  EXPECT_NE(0U, image_layout.segments[4].addr.value());
  EXPECT_NE(0U, image_layout.segments[4].size);
  EXPECT_NE(0U, image_layout.segments[4].data_size);
  EXPECT_EQ(IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
      image_layout.segments[4].characteristics);

  EXPECT_EQ(".reloc", image_layout.segments[5].name);
  EXPECT_NE(0U, image_layout.segments[5].addr.value());
  EXPECT_NE(0U, image_layout.segments[5].size);
  EXPECT_NE(0U, image_layout.segments[5].data_size);
  EXPECT_EQ(IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_DISCARDABLE |
      IMAGE_SCN_MEM_READ, image_layout.segments[5].characteristics);

  // We expect the ImageLayout sections to agree with the BlockGraph sections
  // in number, id, name and characteristics.
  EXPECT_EQ(block_graph.sections().size() - 1, image_layout.segments.size());
  for (size_t i = 0; i < image_layout.segments.size(); ++i) {
    const core::BlockGraph::Section* section = block_graph.GetSectionById(i);
    ASSERT_TRUE(section != NULL);
    EXPECT_EQ(section->id(), i);
    EXPECT_EQ(section->name(), image_layout.segments[i].name);
    EXPECT_EQ(section->characteristics(),
              image_layout.segments[i].characteristics);
  }

  // We expect every block to be associated with a section, and only two blocks
  // should be associated with the special 'header' section.
  size_t header_blocks = 0;
  core::BlockGraph::BlockMap::const_iterator it = block_graph.blocks().begin();
  for (; it != block_graph.blocks().end(); ++it) {
    const core::BlockGraph::Block& block = it->second;
    EXPECT_NE(core::BlockGraph::kInvalidSectionId, block.section());
    if (block.section() == core::BlockGraph::kHeaderSectionId) {
      ++header_blocks;
    } else {
      // If this is not a header block, it should refer to a valid section id.
      EXPECT_LE(0u, block.section());
      EXPECT_LT(block.section(), block_graph.sections().size() - 1);
    }
  }
  EXPECT_EQ(2u, header_blocks);
}

TEST_F(DecomposerTest, BlockGraphSerializationRoundTrip) {
  FilePath image_path(GetExeRelativePath(kDllName));
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

    EXPECT_THAT(image_layout.segments,
                testing::ContainerEq(in_image_layout.segments));
  }
}

TEST_F(DecomposerTest, BasicBlockDecompose) {
  FilePath image_path(GetExeRelativePath(kDllName));
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
