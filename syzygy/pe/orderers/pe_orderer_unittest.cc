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
//
// Unittests for pe::orderers::PEOrderer.

#include "syzygy/pe/orderers/pe_orderer.h"

#include <algorithm>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/block_graph/typed_block.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/decomposer.h"
#include "syzygy/pe/pe_file_writer.h"
#include "syzygy/pe/pe_image_layout_builder.h"
#include "syzygy/pe/pe_utils.h"
#include "syzygy/pe/unittest_util.h"

namespace pe {
namespace orderers {

namespace {

using block_graph::BlockGraph;
using block_graph::BlockVector;
using block_graph::ConstBlockVector;
using block_graph::ConstTypedBlock;
using block_graph::OrderedBlockGraph;
using block_graph::TypedBlock;
using core::RelativeAddress;

const BlockGraph::Block* GetDataDirEntryBlock(
    const ConstTypedBlock<IMAGE_NT_HEADERS>& nt_headers,
    size_t data_dir_index) {
  ConstTypedBlock<char> data_dir;
  if (!nt_headers.Dereference(
          nt_headers->OptionalHeader.DataDirectory[data_dir_index],
          &data_dir)) {
    return NULL;
  }
  // We expect the block to be at zero offset.
  CHECK_EQ(0, data_dir.offset());
  return data_dir.block();
}

// TODO(chrisha): Move all of the PE-layout validation code to somewhere public
//      in pe_lib or pe_unittest_utils_lib. It is useful elsewhere. Similarly,
//      the routines for generating valid PE structures should live in
//      pe_unittest_utils_lib.

void VerifySectionStartsWith(
    const OrderedBlockGraph* obg,
    const BlockGraph::Section* section,
    const ConstBlockVector& blocks) {
  ASSERT_TRUE(obg != NULL);

  const OrderedBlockGraph::OrderedSection& ordered_section =
      obg->ordered_section(section);

  const OrderedBlockGraph::BlockList& block_list(
      ordered_section.ordered_blocks());
  OrderedBlockGraph::BlockList::const_iterator block_it =
      block_list.begin();
  size_t i = 0;
  for (; i < blocks.size() && block_it != block_list.end(); ++block_it, ++i)
    ASSERT_EQ(*block_it, blocks[i]);

  ASSERT_EQ(i, blocks.size());
}

// Verifies that the generated layout is valid.
void VerifyValidLayout(const OrderedBlockGraph* obg,
                       const BlockGraph::Block* dos_header_block) {
  ASSERT_TRUE(obg != NULL);
  ASSERT_TRUE(dos_header_block != NULL);

  ConstTypedBlock<IMAGE_DOS_HEADER> dos_header;
  ASSERT_TRUE(dos_header.Init(0, dos_header_block));

  ConstTypedBlock<IMAGE_NT_HEADERS> nt_headers;
  ASSERT_TRUE(dos_header.Dereference(dos_header->e_lfanew, &nt_headers));

  // Ensure the headers are in the right order.
  ConstBlockVector header_blocks;
  header_blocks.push_back(dos_header.block());
  header_blocks.push_back(nt_headers.block());
  ASSERT_NO_FATAL_FAILURE(VerifySectionStartsWith(obg, NULL, header_blocks));

  const BlockGraph* block_graph = obg->block_graph();
  DCHECK(block_graph != NULL);

  // Check that the resources are in the right section.
  const BlockGraph::Section* rsrc_section =
      block_graph->FindSection(kResourceSectionName);
  const BlockGraph::Block* rsrc_data_dir =
      GetDataDirEntryBlock(nt_headers, IMAGE_DIRECTORY_ENTRY_RESOURCE);

  if (rsrc_data_dir != NULL) {
    ASSERT_TRUE(rsrc_section != NULL);
    ASSERT_EQ(rsrc_section->id(), rsrc_data_dir->section());
  }

  // Check that the relocs are in the right section.
  const BlockGraph::Section* reloc_section =
      block_graph->FindSection(kRelocSectionName);
  const BlockGraph::Block* reloc_data_dir =
      GetDataDirEntryBlock(nt_headers, IMAGE_DIRECTORY_ENTRY_BASERELOC);

  if (reloc_data_dir != NULL) {
    ASSERT_TRUE(reloc_section != NULL);
    ASSERT_EQ(reloc_section->id(), reloc_data_dir->section());
  }

  // Ensure that .rsrc and .reloc are the last two sections.
  OrderedBlockGraph::SectionList::const_iterator section_it =
      obg->ordered_sections().end();
  --section_it;
  if (reloc_section != NULL) {
    ASSERT_EQ((*section_it)->section(), reloc_section);
    --section_it;
  }
  if (rsrc_section != NULL) {
    ASSERT_EQ((*section_it)->section(), rsrc_section);
  }
}

class PEOrdererTest : public testing::PELibUnitTest {
 public:
  PEOrdererTest() : dos_header_block_(NULL) { }

  void InitOrderedBlockGraph() {
    if (ordered_block_graph_.get() == NULL)
      ordered_block_graph_.reset(new OrderedBlockGraph(&block_graph_));
  }

  void RandomizeOrderedBlockGraph() {
    InitOrderedBlockGraph();

    // We randomize *everything*, including the orders of sections and to
    // which sections blocks belong. This is more general than
    // block_graph::orderers::RandomOrderer.

    std::vector<BlockGraph::Section*> sections;
    BlockGraph::SectionMap::iterator section_it =
        block_graph_.sections_mutable().begin();
    for (; section_it != block_graph_.sections_mutable().end(); ++section_it)
      sections.push_back(&section_it->second);

    BlockVector blocks;
    BlockGraph::BlockMap::iterator block_it =
        block_graph_.blocks_mutable().begin();
    for (; block_it != block_graph_.blocks_mutable().end(); ++block_it)
      blocks.push_back(&block_it->second);

    std::random_shuffle(sections.begin(), sections.end());
    std::random_shuffle(blocks.begin(), blocks.end());

    for (size_t i = 0; i < sections.size(); ++i)
      ordered_block_graph_->PlaceAtTail(sections[i]);

    for (size_t i = 0; i < blocks.size(); ++i) {
      // We randomly place some blocks in the 'header' section as well.
      size_t j = rand() % (sections.size() + 1);
      ordered_block_graph_->PlaceAtTail(
          j == sections.size() ? NULL : sections[j],
          blocks[i]);
    }
  }

  // This generates a dummy image with all of the PE features we wish to test,
  // but it will not result in a loadable/runnable module if written. It is
  // significantly more lightweight than test_dll, however.
  void GenerateDummyImage() {
    // Create the standard assortment of sections.
    BlockGraph::Section* text = block_graph_.AddSection(
        kCodeSectionName, kCodeCharacteristics);
    BlockGraph::Section* rdata = block_graph_.AddSection(
        kReadOnlyDataSectionName, kReadOnlyDataCharacteristics);
    BlockGraph::Section* data = block_graph_.AddSection(
        kReadWriteDataSectionName, kReadWriteDataCharacteristics);
    BlockGraph::Section* rsrc = block_graph_.AddSection(
        kResourceSectionName, kReadOnlyDataCharacteristics);
    BlockGraph::Section* reloc = block_graph_.AddSection(
        kRelocSectionName, kRelocCharacteristics);

    // Create one dummy block per section. This just ensures they have something
    // in them.
    AddBlock(BlockGraph::CODE_BLOCK, 16, "text block", text);
    AddBlock(BlockGraph::DATA_BLOCK, 16, "rdata block", rdata);
    AddBlock(BlockGraph::DATA_BLOCK, 16, "data block", data);

    BlockGraph::Block* rsrc_block = AddBlock(BlockGraph::DATA_BLOCK,
        sizeof(IMAGE_RESOURCE_DIRECTORY), "rsrc block", rsrc);

    BlockGraph::Block* reloc_block = AddBlock(BlockGraph::DATA_BLOCK,
        sizeof(IMAGE_BASE_RELOCATION), "reloc block", reloc);

    // Create and initialize the headers.
    dos_header_block_ = block_graph_.AddBlock(
        BlockGraph::DATA_BLOCK, sizeof(IMAGE_DOS_HEADER), "Dos Headers");
    dos_header_block_->ResizeData(dos_header_block_->size());
    BlockGraph::Block* nt_headers_block = block_graph_.AddBlock(
        BlockGraph::DATA_BLOCK,
        sizeof(IMAGE_NT_HEADERS) +
            block_graph_.sections().size() * sizeof(IMAGE_SECTION_HEADER),
        "Nt Headers");
    nt_headers_block->ResizeData(nt_headers_block->size());

    TypedBlock<IMAGE_DOS_HEADER> dos_header;
    ASSERT_TRUE(dos_header.Init(0, dos_header_block_));
    dos_header.SetReference(BlockGraph::RELATIVE_REF,
                            dos_header->e_lfanew,
                            nt_headers_block,
                            0, 0);
    ASSERT_TRUE(UpdateDosHeader(dos_header_block_));

    TypedBlock<IMAGE_NT_HEADERS> nt_headers;
    ASSERT_TRUE(nt_headers.Init(0, nt_headers_block));
    nt_headers->FileHeader.NumberOfSections =
        static_cast<WORD>(block_graph_.sections().size());
    nt_headers->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER);
    nt_headers->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR_MAGIC;
    nt_headers->Signature = IMAGE_NT_SIGNATURE;

    // Set up the relocs data directory.
    TypedBlock<IMAGE_DATA_DIRECTORY> data_dir;
    ASSERT_TRUE(data_dir.Init(nt_headers.OffsetOf(
        nt_headers->OptionalHeader.DataDirectory[
            IMAGE_DIRECTORY_ENTRY_BASERELOC]),
        nt_headers.block()));
    data_dir.SetReference(BlockGraph::RELATIVE_REF,
                          data_dir->VirtualAddress,
                          reloc_block,
                          0, 0);
    data_dir->Size = reloc_block->size();

    // Set up the resources data directory.
    ASSERT_TRUE(data_dir.Init(nt_headers.OffsetOf(
        nt_headers->OptionalHeader.DataDirectory[
            IMAGE_DIRECTORY_ENTRY_RESOURCE]),
        nt_headers.block()));
    data_dir.SetReference(BlockGraph::RELATIVE_REF,
                          data_dir->VirtualAddress,
                          rsrc_block,
                          0, 0);
    data_dir->Size = rsrc_block->size();

    ASSERT_TRUE(IsValidDosHeaderBlock(dos_header_block_));
    ASSERT_TRUE(IsValidNtHeadersBlock(nt_headers_block));
  }

  void DecomposeTestDll() {
    base::FilePath image_path(
        testing::GetExeRelativePath(testing::kTestDllName));

    ASSERT_TRUE(pe_file_.Init(image_path));

    // Decompose the test image and look at the result.
    ImageLayout image_layout(&block_graph_);
    Decomposer decomposer(pe_file_);
    ASSERT_TRUE(decomposer.Decompose(&image_layout));

    // Retrieve and validate the DOS header.
    dos_header_block_ =
        image_layout.blocks.GetBlockByAddress(RelativeAddress(0));
    ASSERT_TRUE(dos_header_block_ != NULL);
    ASSERT_TRUE(IsValidDosHeaderBlock(dos_header_block_));
  }

  BlockGraph::Block* AddBlock(BlockGraph::BlockType type,
                              size_t size,
                              const char* name,
                              const BlockGraph::Section* section) {
    DCHECK(name != NULL);
    BlockGraph::Block* block = block_graph_.AddBlock(type, size, name);
    block->ResizeData(size);
    if (section != NULL)
      block->set_section(section->id());
    return block;
  }

  PEFile pe_file_;
  BlockGraph block_graph_;
  BlockGraph::Block* dos_header_block_;
  std::unique_ptr<OrderedBlockGraph> ordered_block_graph_;
};

}  // namespace

TEST_F(PEOrdererTest, SucceedsWithDummyImage) {
  ASSERT_NO_FATAL_FAILURE(GenerateDummyImage());
  ASSERT_NO_FATAL_FAILURE(RandomizeOrderedBlockGraph());

  PEOrderer pe_orderer;
  EXPECT_TRUE(pe_orderer.OrderBlockGraph(ordered_block_graph_.get(),
                                         dos_header_block_));
  ASSERT_NO_FATAL_FAILURE(VerifyValidLayout(ordered_block_graph_.get(),
                                            dos_header_block_));
}

TEST_F(PEOrdererTest, FailsWithInvalidHeaders) {
  ASSERT_NO_FATAL_FAILURE(GenerateDummyImage());
  dos_header_block_->ResizeData(sizeof(IMAGE_DOS_HEADER) - 1);
  ASSERT_NO_FATAL_FAILURE(InitOrderedBlockGraph());

  PEOrderer pe_orderer;
  EXPECT_FALSE(pe_orderer.OrderBlockGraph(ordered_block_graph_.get(),
                                          dos_header_block_));
}

TEST_F(PEOrdererTest, FailsOnMultipleRsrcSections) {
  ASSERT_NO_FATAL_FAILURE(GenerateDummyImage());
  block_graph_.AddSection(kResourceSectionName, kReadOnlyDataCharacteristics);
  ASSERT_NO_FATAL_FAILURE(InitOrderedBlockGraph());

  PEOrderer pe_orderer;
  EXPECT_FALSE(pe_orderer.OrderBlockGraph(ordered_block_graph_.get(),
                                          dos_header_block_));
}

TEST_F(PEOrdererTest, FailsWithRsrcDataDirButNoRsrcSection) {
  ASSERT_NO_FATAL_FAILURE(GenerateDummyImage());
  block_graph_.RemoveSection(
      block_graph_.FindOrAddSection(kResourceSectionName, 0));
  ASSERT_NO_FATAL_FAILURE(InitOrderedBlockGraph());

  PEOrderer pe_orderer;
  EXPECT_FALSE(pe_orderer.OrderBlockGraph(ordered_block_graph_.get(),
                                          dos_header_block_));
}

TEST_F(PEOrdererTest, FailsOnMultipleRelocSections) {
  ASSERT_NO_FATAL_FAILURE(GenerateDummyImage());
  block_graph_.AddSection(kRelocSectionName, kRelocCharacteristics);
  ASSERT_NO_FATAL_FAILURE(InitOrderedBlockGraph());

  PEOrderer pe_orderer;
  EXPECT_FALSE(pe_orderer.OrderBlockGraph(ordered_block_graph_.get(),
                                          dos_header_block_));
}

TEST_F(PEOrdererTest, FailsWithRelocDataDirButNoRelocSection) {
  ASSERT_NO_FATAL_FAILURE(GenerateDummyImage());
  block_graph_.RemoveSection(
      block_graph_.FindOrAddSection(kRelocSectionName, 0));
  ASSERT_NO_FATAL_FAILURE(InitOrderedBlockGraph());

  PEOrderer pe_orderer;
  EXPECT_FALSE(pe_orderer.OrderBlockGraph(ordered_block_graph_.get(),
                                          dos_header_block_));
}

TEST_F(PEOrdererTest, SucceedsWithTestDll) {
  ASSERT_NO_FATAL_FAILURE(DecomposeTestDll());
  InitOrderedBlockGraph();

  // NOTE: The eventual goal is to continue to enhance PEOrderer until it
  //     is able to take a completely scrambled block-graph and generate a
  //     working image from it. We're not quite there yet, hence this test is
  //     a little simplistic.

  PEOrderer pe_orderer;
  EXPECT_TRUE(pe_orderer.OrderBlockGraph(ordered_block_graph_.get(),
                                         dos_header_block_));
  ASSERT_NO_FATAL_FAILURE(VerifyValidLayout(ordered_block_graph_.get(),
                                            dos_header_block_));

  ImageLayout layout(&block_graph_);
  PEImageLayoutBuilder builder(&layout);
  ASSERT_TRUE(builder.LayoutImageHeaders(dos_header_block_));
  ASSERT_TRUE(builder.LayoutOrderedBlockGraph(*ordered_block_graph_.get()));
  ASSERT_TRUE(builder.Finalize());

  // Create a temporary file we can write a new image to.
  base::FilePath temp_dir;
  ASSERT_NO_FATAL_FAILURE(CreateTemporaryDir(&temp_dir));
  base::FilePath temp_file = temp_dir.Append(testing::kTestDllName);

  PEFileWriter writer(layout);
  ASSERT_TRUE(writer.WriteImage(temp_file));
  ASSERT_NO_FATAL_FAILURE(CheckTestDll(temp_file));
}

}  // namespace orderers
}  // namespace pe
