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

#include "syzygy/pe/pe_coff_image_layout_builder.h"

#include "gtest/gtest.h"
#include "syzygy/common/align.h"

namespace pe {

using block_graph::BlockGraph;
using core::RelativeAddress;

namespace {

class TestImageLayoutBuilder : public PECoffImageLayoutBuilder {
 public:
  // Make the builder publicly constructible.
  TestImageLayoutBuilder(ImageLayout* image_layout,
                         size_t section_alignment,
                         size_t file_alignment)
      : PECoffImageLayoutBuilder(image_layout) {
    PECoffImageLayoutBuilder::Init(section_alignment, file_alignment);

    // Advance cursor to simulate headers having been written.
    cursor_ += 1;
  }
};

class PECoffImageLayoutBuilderTest : public testing::Test {
 public:
  PECoffImageLayoutBuilderTest() {
  }

 protected:
  BlockGraph block_graph_;

 private:
  DISALLOW_COPY_AND_ASSIGN(PECoffImageLayoutBuilderTest);
};

}  // namespace

TEST_F(PECoffImageLayoutBuilderTest, Initialization) {
  ImageLayout layout(&block_graph_);
  TestImageLayoutBuilder builder(&layout, 1, 1);

  EXPECT_EQ(&layout, builder.image_layout());
  EXPECT_EQ(&block_graph_, builder.block_graph());
}

TEST_F(PECoffImageLayoutBuilderTest, AddSection) {
  ImageLayout layout(&block_graph_);
  TestImageLayoutBuilder builder(&layout, 1, 1);

  // Create a few dummy blocks for populating our sections.
  BlockGraph::Block* b1 = block_graph_.AddBlock(BlockGraph::CODE_BLOCK,
                                                0x1234, "b1");
  BlockGraph::Block* b2 = block_graph_.AddBlock(BlockGraph::CODE_BLOCK,
                                                0x1234, "b2");
  b1->AllocateData(0x1000);
  b2->AllocateData(0x1000);
  memset(b1->GetMutableData(), 0xCC, 0x1000);
  memset(b2->GetMutableData(), 0xCC, 0x1000);

  const uint32 kCharacteristics = IMAGE_SCN_CNT_CODE;
  EXPECT_TRUE(builder.OpenSection("foo", kCharacteristics));
  EXPECT_TRUE(builder.LayoutBlock(b1));
  EXPECT_TRUE(builder.CloseSection());

  EXPECT_TRUE(builder.OpenSection("bar", kCharacteristics));
  EXPECT_TRUE(builder.LayoutBlock(b2));
  EXPECT_TRUE(builder.CloseSection());

  // Check sections.
  const std::vector<ImageLayout::SectionInfo>& sections =
      builder.image_layout()->sections;

  EXPECT_EQ("foo", sections[0].name);
  EXPECT_EQ(RelativeAddress(0x1), sections[0].addr);
  EXPECT_EQ(0x1234, sections[0].size);
  EXPECT_EQ(0x1000, sections[0].data_size);
  EXPECT_EQ(kCharacteristics, sections[0].characteristics);

  EXPECT_EQ("bar", sections[1].name);
  EXPECT_EQ(sections[0].addr + sections[0].size, sections[1].addr);
  EXPECT_EQ(0x1234, sections[1].size);
  EXPECT_EQ(0x1000, sections[1].data_size);
  EXPECT_EQ(kCharacteristics, sections[1].characteristics);
}

TEST_F(PECoffImageLayoutBuilderTest, Alignment) {
  ImageLayout layout(&block_graph_);

  const size_t kSectionAlignment = 300;
  const size_t kFileAlignment = 150;
  TestImageLayoutBuilder builder(&layout, kSectionAlignment, kFileAlignment);

  // Create a few dummy blocks for populating our sections.
  BlockGraph::Block* b1 = block_graph_.AddBlock(BlockGraph::CODE_BLOCK,
                                                0x1234, "b1");
  BlockGraph::Block* b2 = block_graph_.AddBlock(BlockGraph::CODE_BLOCK,
                                                0x1234, "b2");
  b1->AllocateData(0x1000);
  b2->AllocateData(0x1000);
  memset(b1->GetMutableData(), 0xCC, 0x1000);
  memset(b2->GetMutableData(), 0xCC, 0x1000);

  const uint32 kCharacteristics = IMAGE_SCN_CNT_CODE;
  EXPECT_TRUE(builder.OpenSection("foo", kCharacteristics));
  EXPECT_TRUE(builder.LayoutBlock(b1));
  EXPECT_TRUE(builder.CloseSection());

  EXPECT_TRUE(builder.OpenSection("bar", kCharacteristics));
  EXPECT_TRUE(builder.LayoutBlock(b2));
  EXPECT_TRUE(builder.CloseSection());

  // Check sections; section addresses should have been rounded up, as well
  // as raw data sizes. Virtual sizes should be untouched.
  const std::vector<ImageLayout::SectionInfo>& sections =
      builder.image_layout()->sections;

  EXPECT_EQ("foo", sections[0].name);
  EXPECT_EQ(RelativeAddress(0x1).AlignUp(kSectionAlignment), sections[0].addr);
  EXPECT_EQ(0x1234, sections[0].size);
  EXPECT_EQ(common::AlignUp(0x1000, kFileAlignment), sections[0].data_size);
  EXPECT_EQ(kCharacteristics, sections[0].characteristics);

  EXPECT_EQ("bar", sections[1].name);
  EXPECT_EQ((sections[0].addr + sections[0].size).AlignUp(kSectionAlignment),
            sections[1].addr);
  EXPECT_EQ(0x1234, sections[1].size);
  EXPECT_EQ(common::AlignUp(0x1000, kFileAlignment), sections[1].data_size);
  EXPECT_EQ(kCharacteristics, sections[1].characteristics);
}

TEST_F(PECoffImageLayoutBuilderTest, Padding) {
  ImageLayout layout(&block_graph_);
  TestImageLayoutBuilder builder(&layout, 1, 1);

  const size_t kPadding = 100;
  builder.set_padding(kPadding);

  // Create a few dummy blocks for populating our sections.
  BlockGraph::Block* b1 = block_graph_.AddBlock(BlockGraph::CODE_BLOCK,
                                                0x1234, "b1");
  BlockGraph::Block* b2 = block_graph_.AddBlock(BlockGraph::CODE_BLOCK,
                                                0x1234, "b2");
  BlockGraph::Block* b3 = block_graph_.AddBlock(BlockGraph::CODE_BLOCK,
                                                0x123, "b3");
  b1->AllocateData(0x1000);
  b2->AllocateData(0x1000);
  b3->AllocateData(0x100);
  memset(b1->GetMutableData(), 0xCC, 0x1000);
  memset(b2->GetMutableData(), 0xCC, 0x1000);
  memset(b3->GetMutableData(), 0xCC, 0x100);

  const uint32 kCharacteristics = IMAGE_SCN_CNT_CODE;
  EXPECT_TRUE(builder.OpenSection("foo", kCharacteristics));
  EXPECT_TRUE(builder.LayoutBlock(b1));
  EXPECT_TRUE(builder.LayoutBlock(b3));
  EXPECT_TRUE(builder.CloseSection());

  EXPECT_TRUE(builder.OpenSection("bar", kCharacteristics));
  EXPECT_TRUE(builder.LayoutBlock(b2));
  EXPECT_TRUE(builder.CloseSection());

  // Check sections. Only last block can be trimmed; any non-last block is
  // written up to its virtual size, before any padding is added.
  const std::vector<ImageLayout::SectionInfo>& sections =
      builder.image_layout()->sections;

  EXPECT_EQ("foo", sections[0].name);
  EXPECT_EQ(RelativeAddress(0x1), sections[0].addr);
  EXPECT_EQ(0x1234 + kPadding + 0x123, sections[0].size);
  EXPECT_EQ(0x1234 + kPadding + 0x100, sections[0].data_size);
  EXPECT_EQ(kCharacteristics, sections[0].characteristics);

  EXPECT_EQ("bar", sections[1].name);
  EXPECT_EQ(sections[0].addr + sections[0].size, sections[1].addr);
  EXPECT_EQ(0x1234, sections[1].size);
  EXPECT_EQ(0x1000, sections[1].data_size);
  EXPECT_EQ(kCharacteristics, sections[1].characteristics);
}

}  // namespace pe
