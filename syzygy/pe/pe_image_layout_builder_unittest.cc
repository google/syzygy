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

#include "syzygy/pe/pe_image_layout_builder.h"

#include <algorithm>
#include <cstdlib>
#include <ctime>

#include "base/file_util.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/block_graph/typed_block.h"
#include "syzygy/block_graph/unittest_util.h"
#include "syzygy/block_graph/orderers/original_orderer.h"
#include "syzygy/block_graph/orderers/random_orderer.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/decomposer.h"
#include "syzygy/pe/pe_file_writer.h"
#include "syzygy/pe/pe_utils.h"
#include "syzygy/pe/unittest_util.h"
#include "syzygy/pe/transforms/pe_prepare_headers_transform.h"

namespace pe {

using block_graph::BlockGraph;
using block_graph::ConstTypedBlock;
using block_graph::OrderedBlockGraph;
using core::AddressRange;
using core::RelativeAddress;

namespace {

class PEImageLayoutBuilderTest : public testing::PELibUnitTest {
  typedef testing::PELibUnitTest Super;

 public:
  PEImageLayoutBuilderTest()
      : image_layout_(&block_graph_), dos_header_block_(NULL) {
  }

  void SetUp() {
    Super::SetUp();

    // Create a temporary file we can write a new image to.
    base::FilePath temp_dir;
    ASSERT_NO_FATAL_FAILURE(CreateTemporaryDir(&temp_dir));
    temp_file_ = temp_dir.Append(testing::kTestDllName);

    // Decompose the test DLL.
    image_path_ = testing::GetExeRelativePath(testing::kTestDllName);
    ASSERT_TRUE(image_file_.Init(image_path_));

    Decomposer decomposer(image_file_);
    ASSERT_TRUE(decomposer.Decompose(&image_layout_));

    dos_header_block_ =
        image_layout_.blocks.GetBlockByAddress(RelativeAddress(0));
    ASSERT_TRUE(dos_header_block_ != NULL);
    ASSERT_TRUE(IsValidDosHeaderBlock(dos_header_block_));

    // Prepare the headers. This puts our DOS stub in place.
    transforms::PEPrepareHeadersTransform prep_headers;
    ASSERT_TRUE(block_graph::ApplyBlockGraphTransform(
        &prep_headers, &policy_, &block_graph_, dos_header_block_));
  }

 protected:
  testing::DummyTransformPolicy policy_;
  base::FilePath image_path_;
  PEFile image_file_;
  BlockGraph block_graph_;
  ImageLayout image_layout_;
  BlockGraph::Block* dos_header_block_;

  base::FilePath temp_file_;
};

}  // namespace

TEST_F(PEImageLayoutBuilderTest, Initialization) {
  ImageLayout layout(&block_graph_);
  PEImageLayoutBuilder builder(&layout);

  EXPECT_EQ(&layout, builder.image_layout());
  EXPECT_EQ(&block_graph_, builder.block_graph());
  EXPECT_EQ(NULL, builder.dos_header_block());
  EXPECT_EQ(NULL, builder.nt_headers_block());
  EXPECT_EQ(0, builder.padding());
  EXPECT_EQ(1, builder.code_alignment());
}

TEST_F(PEImageLayoutBuilderTest, Accessors) {
  ImageLayout layout(&block_graph_);
  PEImageLayoutBuilder builder(&layout);

  builder.set_padding(16);
  builder.set_code_alignment(8);
  EXPECT_EQ(16, builder.padding());
  EXPECT_EQ(8, builder.code_alignment());
}

TEST_F(PEImageLayoutBuilderTest, LayoutImageHeaders) {
  ImageLayout layout(&block_graph_);
  PEImageLayoutBuilder builder(&layout);

  EXPECT_TRUE(builder.LayoutImageHeaders(dos_header_block_));
  EXPECT_EQ(dos_header_block_, builder.dos_header_block());
  EXPECT_TRUE(builder.nt_headers_block() != NULL);
}

TEST_F(PEImageLayoutBuilderTest, RewriteTestDll) {
  OrderedBlockGraph obg(&block_graph_);
  block_graph::orderers::OriginalOrderer orig_orderer;
  ASSERT_TRUE(orig_orderer.OrderBlockGraph(&obg, dos_header_block_));

  ImageLayout layout(&block_graph_);
  PEImageLayoutBuilder builder(&layout);
  ASSERT_TRUE(builder.LayoutImageHeaders(dos_header_block_));
  EXPECT_TRUE(builder.LayoutOrderedBlockGraph(obg));
  EXPECT_TRUE(builder.Finalize());

  PEFileWriter writer(layout);
  ASSERT_TRUE(writer.WriteImage(temp_file_));
  ASSERT_NO_FATAL_FAILURE(CheckTestDll(temp_file_));

  // We expect all of the sections to have been placed at the same addresses,
  // have the same size, etc (except for relocs).
  EXPECT_EQ(image_layout_.sections.size(), layout.sections.size());
  for (size_t i = 0; i < image_layout_.sections.size() - 1; ++i)
    EXPECT_EQ(image_layout_.sections[i], layout.sections[i]);

  // We expect our image to be no bigger. In fact, we are generally smaller as
  // we trim some cruft from the .relocs section.
  int64 orig_size, rewritten_size;
  ASSERT_TRUE(base::GetFileSize(image_path_, &orig_size));
  ASSERT_TRUE(base::GetFileSize(temp_file_, &rewritten_size));
  EXPECT_LE(rewritten_size, orig_size);
}

TEST_F(PEImageLayoutBuilderTest, PadTestDll) {
  OrderedBlockGraph obg(&block_graph_);
  block_graph::orderers::OriginalOrderer orig_orderer;
  ASSERT_TRUE(orig_orderer.OrderBlockGraph(&obg, dos_header_block_));

  // We modify the CV info so that the debugger doesn't try to load the
  // wrong symbols for this image.
  ASSERT_NO_FATAL_FAILURE(testing::TwiddlePdbGuidAndPath(dos_header_block_));

  ImageLayout layout(&block_graph_);
  PEImageLayoutBuilder builder(&layout);
  builder.set_padding(100);
  ASSERT_TRUE(builder.LayoutImageHeaders(dos_header_block_));
  EXPECT_TRUE(builder.LayoutOrderedBlockGraph(obg));
  EXPECT_TRUE(builder.Finalize());

  PEFileWriter writer(layout);
  ASSERT_TRUE(writer.WriteImage(temp_file_));
  ASSERT_NO_FATAL_FAILURE(CheckTestDll(temp_file_));

  // We expect the sections to have gotten longer by the right number of bytes.
  EXPECT_EQ(image_layout_.sections.size(), layout.sections.size());
  EXPECT_EQ(image_layout_.sections.size(), obg.ordered_sections().size());
  OrderedBlockGraph::SectionList::const_iterator obg_section_it =
      obg.ordered_sections().begin();
  size_t expected_file_size_increase = 0;
  for (size_t i = 0; i < image_layout_.sections.size(); ++i) {
    const ImageLayout::SectionInfo& old_section = image_layout_.sections[i];
    const ImageLayout::SectionInfo& new_section = layout.sections[i];

    // All sections (except for .reloc, the last one) should only have grown
    // in size. As each of the non-reloc sections may now spread across more
    // pages than before, the .reloc section itself may have grown (it contains
    // a structure per page of the image). But, due to the fact that the MS
    // linker generally creates an overly large .reloc section, it may also have
    // stayed the same size or gotten smaller.
    if (i + 1 < image_layout_.sections.size()) {
      // We expect the section to have increased in size by at least 100
      // in between each and every block.
      size_t added_bytes =
          100 * ((*obg_section_it)->ordered_blocks().size() - 1);
      EXPECT_GE(new_section.size, old_section.size + added_bytes);
      EXPECT_GE(new_section.data_size, old_section.data_size);
    }

    // Keep track of the total number of new bytes that should be making it
    // to disk.
    expected_file_size_increase += new_section.data_size -
        old_section.data_size;

    ++obg_section_it;
  }

  int64 orig_size, rewritten_size;
  ASSERT_TRUE(base::GetFileSize(image_path_, &orig_size));
  ASSERT_TRUE(base::GetFileSize(temp_file_, &rewritten_size));
  EXPECT_GE(rewritten_size, orig_size + expected_file_size_increase);
}

TEST_F(PEImageLayoutBuilderTest, CodeAlignmentTestDll) {
  OrderedBlockGraph obg(&block_graph_);
  block_graph::orderers::OriginalOrderer orig_orderer;
  ASSERT_TRUE(orig_orderer.OrderBlockGraph(&obg, dos_header_block_));

  // We modify the CV info so that the debugger doesn't try to load the
  // wrong symbols for this image.
  ASSERT_NO_FATAL_FAILURE(testing::TwiddlePdbGuidAndPath(dos_header_block_));

  const uint32 kCodeAlignment = 8;
  ImageLayout layout(&block_graph_);
  PEImageLayoutBuilder builder(&layout);
  builder.set_code_alignment(kCodeAlignment);
  ASSERT_TRUE(builder.LayoutImageHeaders(dos_header_block_));
  EXPECT_TRUE(builder.LayoutOrderedBlockGraph(obg));
  EXPECT_TRUE(builder.Finalize());

  PEFileWriter writer(layout);
  ASSERT_TRUE(writer.WriteImage(temp_file_));
  ASSERT_NO_FATAL_FAILURE(CheckTestDll(temp_file_));

  // Validate that code blocks are aligned correctly.
  BlockGraph::AddressSpace::RangeMapConstIter iter = layout.blocks.begin();
  for (; iter != layout.blocks.end(); ++iter) {
    BlockGraph::Block* block = iter->second;
    BlockGraph::AddressSpace::Range range =iter->first;
    if (block->type() == BlockGraph::CODE_BLOCK) {
      EXPECT_TRUE(range.start().IsAligned(kCodeAlignment));
    }
  }
}

TEST_F(PEImageLayoutBuilderTest, RandomizeTestDll) {
  OrderedBlockGraph obg(&block_graph_);
  block_graph::orderers::RandomOrderer random_orderer(true);
  ASSERT_TRUE(random_orderer.OrderBlockGraph(&obg, dos_header_block_));

  // We modify the CV info so that the debugger doesn't try to load the
  // wrong symbols for this image.
  ASSERT_NO_FATAL_FAILURE(testing::TwiddlePdbGuidAndPath(dos_header_block_));

  ImageLayout layout(&block_graph_);
  PEImageLayoutBuilder builder(&layout);
  ASSERT_TRUE(builder.LayoutImageHeaders(dos_header_block_));
  EXPECT_TRUE(builder.LayoutOrderedBlockGraph(obg));
  EXPECT_TRUE(builder.Finalize());

  PEFileWriter writer(layout);
  ASSERT_TRUE(writer.WriteImage(temp_file_));
  ASSERT_NO_FATAL_FAILURE(CheckTestDll(temp_file_));
}

TEST_F(PEImageLayoutBuilderTest, ShiftTestDll) {
  // Create an empty section. We will place this at the beginning of the
  // image to ensure that everything gets shifted by a fixed amount. A loadable
  // module is a good indication that we properly parsed everything.
  BlockGraph::Section* section = block_graph_.AddSection(
      ".empty", kReadOnlyDataCharacteristics);
  BlockGraph::Block* block = block_graph_.AddBlock(BlockGraph::DATA_BLOCK,
      10 * 1024, ".empty");
  block->AllocateData(block->size());
  ::memset(block->GetMutableData(), 0xcc, block->data_size());
  block->set_section(section->id());

  // Prepare the headers (again). We need to do this to make sure that the image
  // headers accurately reflect the number of sections as we've added a new
  // one.
  transforms::PEPrepareHeadersTransform prep_headers;
  ASSERT_TRUE(block_graph::ApplyBlockGraphTransform(
      &prep_headers, &policy_, &block_graph_, dos_header_block_));

  OrderedBlockGraph obg(&block_graph_);
  block_graph::orderers::OriginalOrderer orig_orderer;
  ASSERT_TRUE(orig_orderer.OrderBlockGraph(&obg, dos_header_block_));

  // Move the new section to the beginning of the image. This causes everything
  // to be shifted by a fixed amount.
  obg.PlaceAtHead(section);

  // We modify the CV info so that the debugger doesn't try to load the
  // wrong symbols for this image.
  ASSERT_NO_FATAL_FAILURE(testing::TwiddlePdbGuidAndPath(dos_header_block_));

  ImageLayout layout(&block_graph_);
  PEImageLayoutBuilder builder(&layout);
  ASSERT_TRUE(builder.LayoutImageHeaders(dos_header_block_));
  EXPECT_TRUE(builder.LayoutOrderedBlockGraph(obg));
  EXPECT_TRUE(builder.Finalize());

  PEFileWriter writer(layout);
  ASSERT_TRUE(writer.WriteImage(temp_file_));
  ASSERT_NO_FATAL_FAILURE(CheckTestDll(temp_file_));

  // Read the rewritten DLL and validate that the resources have moved.
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
