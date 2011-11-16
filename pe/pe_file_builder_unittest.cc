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

#include "syzygy/pe/pe_file_builder.h"

#include <algorithm>
#include <cstdlib>
#include <ctime>

#include "base/file_util.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/block_graph/typed_block.h"
#include "syzygy/pe/decomposer.h"
#include "syzygy/pe/pe_file_writer.h"
#include "syzygy/pe/pe_utils.h"
#include "syzygy/pe/unittest_util.h"

namespace pe {

using block_graph::BlockGraph;
using block_graph::ConstTypedBlock;
using core::AddressRange;
using core::RelativeAddress;

namespace {

// A source of int3 instructions for padding code.
const uint8 kInt3Padding[] = {
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
};

class PEFileBuilderTest: public testing::PELibUnitTest {
  typedef testing::PELibUnitTest Super;

 public:
  PEFileBuilderTest() : image_layout_(&block_graph_), dos_header_block_(NULL) {
  }

  void SetUp() {
    Super::SetUp();

    // Create a temporary file we can write a new image to.
    FilePath temp_dir;
    ASSERT_NO_FATAL_FAILURE(CreateTemporaryDir(&temp_dir));
    temp_file_ = temp_dir.Append(kDllName);

    // Decompose the test DLL.
    image_path_ = GetExeRelativePath(kDllName);
    ASSERT_TRUE(image_file_.Init(image_path_));

    Decomposer decomposer(image_file_);
    ASSERT_TRUE(decomposer.Decompose(&image_layout_));

    dos_header_block_ =
        image_layout_.blocks.GetBlockByAddress(RelativeAddress(0));
    ASSERT_TRUE(dos_header_block_ != NULL);
    ASSERT_TRUE(IsValidDosHeaderBlock(dos_header_block_));
  }

  void CopyBlockRange(const BlockGraph::AddressSpace::Range& section_range,
                      RelativeAddress insert_at,
                      PEFileBuilder* builder) {
    typedef BlockGraph::AddressSpace AddressSpace;
    AddressSpace::RangeMapIterPair iter_pair =
        image_layout_.blocks.GetIntersectingBlocks(section_range.start(),
                                                   section_range.size());

    AddressSpace::RangeMapIter& section_it = iter_pair.first;
    const AddressSpace::RangeMapIter& section_end = iter_pair.second;
    for (; section_it != section_end; ++section_it) {
      BlockGraph::Block* block = section_it->second;

      // This is an untransformed decomposition. We fully expect each block to
      // have a simple source range and be fully mapped. That is, all of its
      // data comes directly from a single run of bytes in the source image.
      ASSERT_TRUE(block->source_ranges().IsSimple());
      ASSERT_TRUE(block->source_ranges().IsMapped(0, block->size()));

      // We expect this block to lie entirely within the section we are
      // copying.
      ASSERT_TRUE(section_range.Contains(
          block->source_ranges().range_pair(0).second));

      ASSERT_TRUE(
          builder->image_layout().blocks.InsertBlock(insert_at, block));

      insert_at += block->size();
    }
  }

 protected:
  FilePath image_path_;
  PEFile image_file_;
  BlockGraph block_graph_;
  ImageLayout image_layout_;
  BlockGraph::Block* dos_header_block_;

  FilePath temp_file_;
};

}  // namespace

TEST_F(PEFileBuilderTest, Initialization) {
  PEFileBuilder builder(&block_graph_);

  EXPECT_EQ(NULL, builder.dos_header_block());
  EXPECT_EQ(NULL, builder.nt_headers_block());
  EXPECT_EQ(RelativeAddress(4096), builder.next_section_address());
  EXPECT_EQ(4096, builder.section_alignment());
  EXPECT_EQ(512, builder.file_alignment());
}

TEST_F(PEFileBuilderTest, SetAllocationParameters) {
  PEFileBuilder builder(&block_graph_);

  builder.SetAllocationParameters(1, 8192, 1024);
  EXPECT_EQ(8192, builder.section_alignment());
  EXPECT_EQ(1024, builder.file_alignment());
  EXPECT_EQ(8192, builder.next_section_address().value());

  builder.SetAllocationParameters(12000, 4096, 8192);
  EXPECT_EQ(4096, builder.section_alignment());
  EXPECT_EQ(8192, builder.file_alignment());
  EXPECT_EQ(4096 * 3, builder.next_section_address().value());
}

TEST_F(PEFileBuilderTest, SetImageHeaders) {
  PEFileBuilder builder(&block_graph_);
  ASSERT_TRUE(builder.SetImageHeaders(dos_header_block_));
  EXPECT_EQ(dos_header_block_, builder.dos_header_block());
  EXPECT_TRUE(builder.nt_headers_block() != NULL);
}

TEST_F(PEFileBuilderTest, AddSection) {
  PEFileBuilder builder(&block_graph_);

  const uint32 kCharacteristics = IMAGE_SCN_CNT_CODE;
  EXPECT_EQ(RelativeAddress(0x1000),
      builder.AddSection("foo", 0x1234, 0x1000, kCharacteristics));
  EXPECT_EQ(RelativeAddress(0x3000),
      builder.AddSection("bar", 0x1234, 0x1000, kCharacteristics));

  ImageLayout::SectionInfo expected[] = {
      { "foo", RelativeAddress(0x1000), 0x1234, 0x1000, kCharacteristics },
      { "bar", RelativeAddress(0x3000), 0x1234, 0x1000, kCharacteristics }};

  EXPECT_THAT(builder.image_layout().sections,
              testing::ElementsAreArray(expected));
}

TEST_F(PEFileBuilderTest, RewriteTestDll) {
  // Here's where we build the new image.
  PEFileBuilder builder(&block_graph_);
  ASSERT_TRUE(builder.SetImageHeaders(dos_header_block_));

  ConstTypedBlock<IMAGE_NT_HEADERS> nt_headers;
  ASSERT_TRUE(nt_headers.Init(0, builder.nt_headers_block()));

  ConstTypedBlock<IMAGE_SECTION_HEADER> section_headers;
  ASSERT_TRUE(section_headers.InitWithSize(
      sizeof(IMAGE_NT_HEADERS),
      nt_headers->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER),
      builder.nt_headers_block()));

  // Copy the sections from the original image to the new one, save for
  // the .relocs section.
  size_t num_sections = nt_headers->FileHeader.NumberOfSections;
  for (size_t i = 0; i < num_sections - 1; ++i) {
    const IMAGE_SECTION_HEADER& section = section_headers[i];

    std::string name_str = PEFile::GetSectionName(section);
    RelativeAddress start = builder.AddSection(name_str.c_str(),
                                               section.Misc.VirtualSize,
                                               section.SizeOfRawData,
                                               section.Characteristics);
    ASSERT_EQ(section.VirtualAddress, start.value());

    AddressRange<RelativeAddress, size_t> section_range(
        start, section.Misc.VirtualSize);

    ASSERT_NO_FATAL_FAILURE(CopyBlockRange(section_range, start, &builder));
  }

  ASSERT_TRUE(builder.CreateRelocsSection());
  ASSERT_TRUE(builder.FinalizeHeaders());

  PEFileWriter writer(builder.image_layout());

  ASSERT_TRUE(writer.WriteImage(temp_file_));
  ASSERT_NO_FATAL_FAILURE(CheckTestDll(temp_file_));
}

TEST_F(PEFileBuilderTest, RandomizeTestDll) {
  // Here's where we build the new image.
  PEFileBuilder builder(&block_graph_);
  ASSERT_TRUE(builder.SetImageHeaders(dos_header_block_));

  // Add an empty section to the beginning of the image to make sure
  // everything in the image moves. This mainly tests whether the PE
  // parsing is complete.
  builder.AddSection(".empty", 10 * 1024, 0,
                     IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ);

  // Copy the sections from the decomposed image to the new one, save for
  // the .relocs section. Code sections are turned into read-only data
  // sections, and the code blocks held back for moving to a new section.
  ConstTypedBlock<IMAGE_NT_HEADERS> nt_headers;
  ASSERT_TRUE(nt_headers.Init(0, builder.nt_headers_block()));

  ConstTypedBlock<IMAGE_SECTION_HEADER> section_headers;
  ASSERT_TRUE(section_headers.InitWithSize(
      sizeof(IMAGE_NT_HEADERS),
      nt_headers->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER),
      builder.nt_headers_block()));

  // Copy the sections from the original image to the new one, save for
  // the .relocs section.
  size_t num_sections = nt_headers->FileHeader.NumberOfSections;
  std::vector<BlockGraph::Block*> code_blocks;
  for (size_t i = 0; i < num_sections - 1; ++i) {
    const IMAGE_SECTION_HEADER& section = section_headers[i];
    BlockGraph::AddressSpace::Range section_range(
        RelativeAddress(section.VirtualAddress), section.Misc.VirtualSize);
    std::string name_str = PEFile::GetSectionName(section);

    if (section.Characteristics & IMAGE_SCN_CNT_CODE) {
      // It's a code section, turn it into a read-only data section.
      uint32 characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA |
          IMAGE_SCN_MEM_READ;
      RelativeAddress start = builder.AddSection(".empty",
                                                 section.Misc.VirtualSize,
                                                 0,
                                                 characteristics);

      // Hold back the blocks within the section for reordering.
      typedef BlockGraph::AddressSpace AddressSpace;
      AddressSpace::RangeMapIterPair iter_pair =
          image_layout_.blocks.GetIntersectingBlocks(section_range.start(),
                                                     section_range.size());

      AddressSpace::RangeMapIter& section_it = iter_pair.first;
      const AddressSpace::RangeMapIter& section_end = iter_pair.second;
      for (; section_it != section_end; ++section_it) {
        BlockGraph::Block* block = section_it->second;
        ASSERT_EQ(BlockGraph::CODE_BLOCK, block->type());
        code_blocks.push_back(block);
      }
    } else {
      // If it's the resources section, let's shift it over a bit by inserting
      // a new empty data section before copying it.
      if (name_str == ".rsrc") {
        uint32 characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA |
            IMAGE_SCN_MEM_READ;
        builder.AddSection(
            ".dummy", section.Misc.VirtualSize, 0, characteristics);
      }

      // It's not a code section, copy it.
      RelativeAddress start = builder.AddSection(name_str.c_str(),
                                                 section.Misc.VirtualSize,
                                                 section.SizeOfRawData,
                                                 section.Characteristics);

      ASSERT_NO_FATAL_FAILURE(CopyBlockRange(section_range, start, &builder));
    }
  }

  unsigned int seed = static_cast<unsigned int>(time(NULL));
  srand(seed);
  std::cout << "Random seed: " << seed << std::endl;

  // Now reorder the code blocks and insert them into a new
  // code section at the end of the binary.
  std::random_shuffle(code_blocks.begin(), code_blocks.end());
  RelativeAddress insert_at(builder.next_section_address());
  for (size_t i = 0; i < code_blocks.size(); ++i) {
    // Prefix each block with its name.
    BlockGraph::Block* block = code_blocks[i];

    // Prefix each inserted code block with its name to make
    // debugging of the randomized executable sanitary.
    BlockGraph::Block* name_block =
        builder.image_layout().blocks.AddBlock(BlockGraph::CODE_BLOCK,
                                               insert_at,
                                               strlen(block->name()),
                                               "Name block");
    ASSERT_TRUE(name_block != NULL);
    name_block->CopyData(strlen(block->name()), block->name());
    insert_at += name_block->size();

    ASSERT_TRUE(builder.image_layout().blocks.InsertBlock(insert_at, block));
    insert_at += block->size();

    // Pad generously with int3s.
    BlockGraph::Block* pad_block =
        builder.image_layout().blocks.AddBlock(BlockGraph::CODE_BLOCK,
                                               insert_at,
                                               sizeof(kInt3Padding),
                                               "Int3 padding");
    ASSERT_TRUE(pad_block != NULL);
    pad_block->SetData(kInt3Padding, sizeof(kInt3Padding));
    insert_at += pad_block->size();
  }

  size_t section_size = insert_at - builder.next_section_address();
  uint32 characteristics =
      IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
  builder.AddSection(".text", section_size, section_size, characteristics);

  ASSERT_TRUE(builder.CreateRelocsSection());
  ASSERT_TRUE(builder.FinalizeHeaders());

  PEFileWriter writer(builder.image_layout());

  ASSERT_TRUE(writer.WriteImage(temp_file_));
  ASSERT_NO_FATAL_FAILURE(CheckTestDll(temp_file_));

  // Read the randomized dll and validate that the resources have moved.
  PEFile new_image_file;
  ASSERT_TRUE(new_image_file.Init(temp_file_));
  const IMAGE_DATA_DIRECTORY* old_data_dir =
      image_file_.nt_headers()->OptionalHeader.DataDirectory;
  const IMAGE_DATA_DIRECTORY* new_data_dir =
      new_image_file.nt_headers()->OptionalHeader.DataDirectory;
  ASSERT_EQ(
      old_data_dir[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size,
      new_data_dir[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size);
  ASSERT_NE(
      old_data_dir[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress,
      new_data_dir[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress);
}

}  // namespace pe
