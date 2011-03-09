// Copyright 2010 Google Inc.
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
#include "gtest/gtest.h"
#include "syzygy/pe/decomposer.h"
#include "syzygy/pe/pe_file_writer.h"
#include "syzygy/pe/unittest_util.h"

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

using core::BlockGraph;
using core::RelativeAddress;
using pe::Decomposer;
using pe::PEFile;
using pe::PEFileBuilder;

class PEFileBuilderTest: public testing::Test {
 public:
  PEFileBuilderTest()
      : nt_headers_(NULL),
        num_sections_(0),
        section_headers_(NULL) {
  }

  void SetUp() {
    // Create a temporary file we can write a new image to.
    ASSERT_TRUE(file_util::CreateTemporaryFile(&temp_file_));

    // Decompose the test DLL.
    image_path_ = testing::GetExeRelativePath(testing::kDllName);
    ASSERT_TRUE(image_file_.Init(image_path_));

    Decomposer decomposer(image_file_, image_path_);
    ASSERT_TRUE(decomposer.Decompose(&decomposed_));

    // Retrieve the original image headers.
    ASSERT_GE(decomposed_.header.nt_headers->data_size(),
              sizeof(IMAGE_NT_HEADERS));
    nt_headers_ = reinterpret_cast<const IMAGE_NT_HEADERS*>(
        decomposed_.header.nt_headers->data());

    // Retrieve the original section headers.
    num_sections_ = nt_headers_->FileHeader.NumberOfSections;
    ASSERT_EQ(
        sizeof(IMAGE_SECTION_HEADER) * num_sections_ + sizeof(*nt_headers_),
        decomposed_.header.nt_headers->size());

    section_headers_ = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
        nt_headers_ + 1);

    // We expect the last image segment to be the base relocations.
    ASSERT_EQ(0, strcmp(
        reinterpret_cast<const char*>(section_headers_[num_sections_ - 1].Name),
        ".reloc"));
  }

  void TearDown() {
    // Scrap our temp file.
    file_util::Delete(temp_file_, false);
  }

  void CopyHeaderInfoFromDecomposed(PEFileBuilder* builder) {
    ASSERT_TRUE(builder != NULL);

    // TODO(siggi): Retrieving the entry point from the decomposed image
    //     is pretty awkward - fix the decomposer to provide it more
    //     explicitly.
    BlockGraph::Reference entry_point;
    ASSERT_TRUE(decomposed_.header.nt_headers->GetReference(
        FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader.AddressOfEntryPoint),
        &entry_point));

    builder->set_entry_point(entry_point);
  }

  void CopyBlockRange(const BlockGraph::AddressSpace::Range& section_range,
                      RelativeAddress insert_at,
                      PEFileBuilder* builder) {
    typedef BlockGraph::AddressSpace AddressSpace;
    AddressSpace::RangeMapIterPair iter_pair =
        decomposed_.address_space.GetIntersectingBlocks(section_range.start(),
                                                        section_range.size());

    AddressSpace::RangeMapIter& section_it = iter_pair.first;
    const AddressSpace::RangeMapIter& section_end = iter_pair.second;
    for (; section_it != section_end; ++section_it) {
      BlockGraph::Block* block = section_it->second;
      ASSERT_TRUE(section_range.Contains(
          AddressSpace::Range(block->original_addr(), block->size())));

      ASSERT_TRUE(
          builder->address_space().InsertBlock(insert_at, block));

      insert_at += block->size();
    }
  }

  void CopyDataDirectory(PEFileBuilder* builder) {
    // Copy the data directory from the old image.
    for (size_t i = 0; i < arraysize(decomposed_.header.data_directory); ++i) {
      BlockGraph::Block* block = decomposed_.header.data_directory[i];

      // We don't want to copy the relocs over as the relocs are recreated.
      if (block != NULL && i != IMAGE_DIRECTORY_ENTRY_BASERELOC) {
        ASSERT_TRUE(builder->SetDataDirectoryEntry(i, block));
      }
    }
  }

 protected:
  FilePath image_path_;
  PEFile image_file_;
  Decomposer::DecomposedImage decomposed_;
  const IMAGE_NT_HEADERS* nt_headers_;
  size_t num_sections_;
  const IMAGE_SECTION_HEADER* section_headers_;

  FilePath temp_file_;
};

}  // namespace

namespace pe {

using core::AddressRange;

TEST_F(PEFileBuilderTest, Accessors) {
  PEFileBuilder builder(&decomposed_.image);

  EXPECT_EQ(PEFileBuilder::kDefaultImageBase,
      builder.nt_headers().OptionalHeader.ImageBase);
  EXPECT_EQ(PEFileBuilder::kDefaultHeaderSize,
      builder.nt_headers().OptionalHeader.SizeOfHeaders);
  EXPECT_EQ(PEFileBuilder::kDefaultSectionAlignment,
      builder.nt_headers().OptionalHeader.SectionAlignment);
  EXPECT_EQ(PEFileBuilder::kDefaultFileAlignment,
      builder.nt_headers().OptionalHeader.FileAlignment);
}

TEST_F(PEFileBuilderTest, AddSegment) {
  PEFileBuilder builder(&decomposed_.image);

  const uint32 kChar = IMAGE_SCN_CNT_CODE;
  EXPECT_EQ(RelativeAddress(0x1000),
      builder.AddSegment("foo", 0x1234, 0x1000, kChar));
  EXPECT_EQ(RelativeAddress(0x3000),
      builder.AddSegment("bar", 0x1234, 0x1000, kChar));
}

TEST_F(PEFileBuilderTest, RewriteTestDll) {
  // Here's where we build the new image.
  PEFileBuilder builder(&decomposed_.image);
  ASSERT_NO_FATAL_FAILURE(CopyHeaderInfoFromDecomposed(&builder));

  // Copy the sections from the decomposed image to the new one, save for
  // the .relocs section.
  for (size_t i = 0; i < num_sections_ - 1; ++i) {
    const IMAGE_SECTION_HEADER& section = section_headers_[i];

    const char* name = reinterpret_cast<const char*>(section.Name);
    std::string name_str(name, strnlen(name, arraysize(section.Name)));
    RelativeAddress start = builder.AddSegment(name_str.c_str(),
                                               section.Misc.VirtualSize,
                                               section.SizeOfRawData,
                                               section.Characteristics);
    ASSERT_EQ(section.VirtualAddress, start.value());

    AddressRange<RelativeAddress, size_t> section_range(
        start, section.Misc.VirtualSize);

    ASSERT_NO_FATAL_FAILURE(CopyBlockRange(section_range, start, &builder));
  }

  ASSERT_NO_FATAL_FAILURE(CopyDataDirectory(&builder));

  ASSERT_TRUE(builder.CreateRelocsSection());
  ASSERT_TRUE(builder.FinalizeHeaders());
  ASSERT_TRUE(decomposed_.header.dos_header->
      TransferReferrers(0, builder.dos_header()));

  PEFileWriter writer(builder.address_space(),
                      &builder.nt_headers(),
                      builder.section_headers());

  ASSERT_TRUE(writer.WriteImage(temp_file_));
  ASSERT_NO_FATAL_FAILURE(testing::CheckTestDll(temp_file_));
}

TEST_F(PEFileBuilderTest, RandomizeTestDll) {
  // Here's where we build the new image.
  PEFileBuilder builder(&decomposed_.image);
  ASSERT_NO_FATAL_FAILURE(CopyHeaderInfoFromDecomposed(&builder));

  // Copy the sections from the decomposed image to the new one, save for
  // the .relocs section. Code sections are turned into read-only data
  // sections, and the code blocks held back for moving to a new segment.
  std::vector<BlockGraph::Block*> code_blocks;
  for (size_t i = 0; i < num_sections_ - 1; ++i) {
    const IMAGE_SECTION_HEADER& section = section_headers_[i];
    BlockGraph::AddressSpace::Range section_range(
        RelativeAddress(section.VirtualAddress), section.Misc.VirtualSize);
    const char* name = reinterpret_cast<const char*>(section.Name);
    std::string name_str(name, strnlen(name, arraysize(section.Name)));

    if (section.Characteristics & IMAGE_SCN_CNT_CODE) {
      // It's a code section, turn it into a read-only data section.
      uint32 characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA |
          IMAGE_SCN_MEM_READ;
      RelativeAddress start = builder.AddSegment(".empty",
                                                 section.Misc.VirtualSize,
                                                 0,
                                                 characteristics);

      // Hold back the blocks within the section for reordering.
      typedef BlockGraph::AddressSpace AddressSpace;
      AddressSpace::RangeMapIterPair iter_pair =
          decomposed_.address_space.GetIntersectingBlocks(section_range.start(),
                                                          section_range.size());

      AddressSpace::RangeMapIter& section_it = iter_pair.first;
      const AddressSpace::RangeMapIter& section_end = iter_pair.second;
      for (; section_it != section_end; ++section_it) {
        BlockGraph::Block* block = section_it->second;
        ASSERT_EQ(BlockGraph::CODE_BLOCK, block->type());
        code_blocks.push_back(block);
      }
    } else {
      // It's not a code section, copy it.
      RelativeAddress start = builder.AddSegment(name_str.c_str(),
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
  // code segment at the end of the binary.
  std::random_shuffle(code_blocks.begin(), code_blocks.end());
  RelativeAddress insert_at(builder.next_section_address());
  for (size_t i = 0; i < code_blocks.size(); ++i) {
    // Prefix each block with its name.
    BlockGraph::Block* block = code_blocks[i];

    // Prefix each inserted code block with its name to make
    // debugging of the randomized executable sanitary.
    BlockGraph::Block* name_block =
        builder.address_space().AddBlock(BlockGraph::CODE_BLOCK,
                                         insert_at,
                                         strlen(block->name()),
                                         "Name block");
    ASSERT_TRUE(name_block != NULL);
    name_block->CopyData(strlen(block->name()), block->name());
    insert_at += name_block->size();

    ASSERT_TRUE(builder.address_space().InsertBlock(insert_at, block));
    insert_at += block->size();

    // Pad generously with int3s.
    BlockGraph::Block* pad_block =
        builder.address_space().AddBlock(BlockGraph::CODE_BLOCK,
                                         insert_at,
                                         sizeof(kInt3Padding),
                                         "Int3 padding");
    ASSERT_TRUE(pad_block != NULL);
    pad_block->set_data(kInt3Padding);
    pad_block->set_data_size(sizeof(kInt3Padding));
    insert_at += pad_block->size();
  }

  size_t segment_size = insert_at - builder.next_section_address();
  uint32 characteristics =
      IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
  builder.AddSegment(".text", segment_size, segment_size, characteristics);

  ASSERT_NO_FATAL_FAILURE(CopyDataDirectory(&builder));

  ASSERT_TRUE(builder.CreateRelocsSection());
  ASSERT_TRUE(builder.FinalizeHeaders());
  ASSERT_TRUE(decomposed_.header.dos_header->
      TransferReferrers(0, builder.dos_header()));

  PEFileWriter writer(builder.address_space(),
                      &builder.nt_headers(),
                      builder.section_headers());

  ASSERT_TRUE(writer.WriteImage(temp_file_));
  ASSERT_NO_FATAL_FAILURE(testing::CheckTestDll(temp_file_));
}

}  // namespace pe
