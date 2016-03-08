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

  const uint32_t kCharacteristics = IMAGE_SCN_CNT_CODE;
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

  const uint32_t kCharacteristics = IMAGE_SCN_CNT_CODE;
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

  const uint32_t kCharacteristics = IMAGE_SCN_CNT_CODE;
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

TEST_F(PECoffImageLayoutBuilderTest, BlockPadding) {
  ImageLayout layout(&block_graph_);
  TestImageLayoutBuilder builder(&layout, 1, 1);

  const size_t kBlockPadding = 7;

  // Create a few dummy blocks for populating our sections.
  BlockGraph::Block* b1 = block_graph_.AddBlock(BlockGraph::CODE_BLOCK,
                                                0x123, "b1");
  BlockGraph::Block* b2 = block_graph_.AddBlock(BlockGraph::CODE_BLOCK,
                                                0x123, "b2");
  BlockGraph::Block* b3 = block_graph_.AddBlock(BlockGraph::CODE_BLOCK,
                                                0x123, "b3");
  b1->AllocateData(0x100);
  b2->AllocateData(0x100);
  b3->AllocateData(0x100);
  memset(b1->GetMutableData(), 0xCC, 0x100);
  memset(b2->GetMutableData(), 0xCC, 0x100);
  memset(b3->GetMutableData(), 0xCC, 0x100);

  // Set block paddings.
  b2->set_padding_before(kBlockPadding);
  b3->set_padding_before(kBlockPadding);

  const uint32_t kCharacteristics = IMAGE_SCN_CNT_CODE;
  EXPECT_TRUE(builder.OpenSection("foo", kCharacteristics));
  EXPECT_TRUE(builder.LayoutBlock(b1));
  EXPECT_TRUE(builder.LayoutBlock(b2));
  EXPECT_TRUE(builder.CloseSection());

  EXPECT_TRUE(builder.OpenSection("bar", kCharacteristics));
  EXPECT_TRUE(builder.LayoutBlock(b3));
  EXPECT_TRUE(builder.CloseSection());

  // Check sections. Only last block can be trimmed; any non-last block is
  // written up to its virtual size, before any padding is added.
  const std::vector<ImageLayout::SectionInfo>& sections =
      builder.image_layout()->sections;

  EXPECT_EQ("foo", sections[0].name);
  EXPECT_EQ(RelativeAddress(0x1), sections[0].addr);
  EXPECT_EQ(0x123 + kBlockPadding + 0x123, sections[0].size);
  EXPECT_EQ(0x123 + kBlockPadding + 0x100, sections[0].data_size);
  EXPECT_EQ(kCharacteristics, sections[0].characteristics);

  // Padding is applied to the first block in a section as well.
  EXPECT_EQ("bar", sections[1].name);
  EXPECT_EQ(sections[0].addr + sections[0].size, sections[1].addr);
  EXPECT_EQ(kBlockPadding + 0x123, sections[1].size);
  EXPECT_EQ(kBlockPadding + 0x100, sections[1].data_size);
  EXPECT_EQ(kCharacteristics, sections[1].characteristics);
}

TEST_F(PECoffImageLayoutBuilderTest, PaddingAndBlockPadding) {
  ImageLayout layout(&block_graph_);
  TestImageLayoutBuilder builder(&layout, 1, 1);

  const size_t kPadding = 5;
  builder.set_padding(kPadding);

  // Test a smaller and a bigger value than kPadding.
  const size_t kBlockPaddingSmall = 3;
  const size_t kBlockPaddingBig = 7;

  // Create a few dummy blocks for populating our sections.
  BlockGraph::Block* b1 = block_graph_.AddBlock(BlockGraph::CODE_BLOCK,
                                                0x123, "b1");
  BlockGraph::Block* b2 = block_graph_.AddBlock(BlockGraph::CODE_BLOCK,
                                                0x123, "b2");
  BlockGraph::Block* b3 = block_graph_.AddBlock(BlockGraph::CODE_BLOCK,
                                                0x123, "b3");
  BlockGraph::Block* b4 = block_graph_.AddBlock(BlockGraph::CODE_BLOCK,
                                                0x123, "b4");

  b1->AllocateData(0x100);
  b2->AllocateData(0x100);
  b3->AllocateData(0x100);
  b4->AllocateData(0x100);
  memset(b1->GetMutableData(), 0xCC, 0x100);
  memset(b2->GetMutableData(), 0xCC, 0x100);
  memset(b3->GetMutableData(), 0xCC, 0x100);
  memset(b4->GetMutableData(), 0xCC, 0x100);

  // Set block paddings.
  b2->set_padding_before(kBlockPaddingSmall);
  b4->set_padding_before(kBlockPaddingBig);

  const uint32_t kCharacteristics = IMAGE_SCN_CNT_CODE;
  EXPECT_TRUE(builder.OpenSection("foo", kCharacteristics));
  EXPECT_TRUE(builder.LayoutBlock(b1));
  EXPECT_TRUE(builder.LayoutBlock(b2));
  EXPECT_TRUE(builder.CloseSection());

  EXPECT_TRUE(builder.OpenSection("bar", kCharacteristics));
  EXPECT_TRUE(builder.LayoutBlock(b3));
  EXPECT_TRUE(builder.LayoutBlock(b4));
  EXPECT_TRUE(builder.CloseSection());

  const std::vector<ImageLayout::SectionInfo>& sections =
      builder.image_layout()->sections;

  // Inter-block padding is bigger, that should be in effect.
  EXPECT_EQ("foo", sections[0].name);
  EXPECT_EQ(RelativeAddress(0x1), sections[0].addr);
  EXPECT_EQ(0x123 + kPadding + 0x123, sections[0].size);
  EXPECT_EQ(0x123 + kPadding + 0x100, sections[0].data_size);
  EXPECT_EQ(kCharacteristics, sections[0].characteristics);

  // Block's own padding is bigger, that should be in effect.
  EXPECT_EQ("bar", sections[1].name);
  EXPECT_EQ(sections[0].addr + sections[0].size, sections[1].addr);
  EXPECT_EQ(0x123 + kBlockPaddingBig + 0x123, sections[1].size);
  EXPECT_EQ(0x123 + kBlockPaddingBig + 0x100, sections[1].data_size);
  EXPECT_EQ(kCharacteristics, sections[1].characteristics);
}

TEST_F(PECoffImageLayoutBuilderTest, Align) {
  ImageLayout layout(&block_graph_);
  TestImageLayoutBuilder builder(&layout, 1, 1);

  const size_t kAlignment = 16U;
  const size_t kBlockSize = 17U;
  const BlockGraph::Offset kOffsetMin = -1;
  const BlockGraph::Offset kOffsetMax = 100;

  // Create aligned blocks with different alignment offsets.
  std::vector<BlockGraph::Block*> blocks;
  for (BlockGraph::Offset i = kOffsetMin; i < kOffsetMax; ++i) {
    BlockGraph::Block* block = block_graph_.AddBlock(BlockGraph::CODE_BLOCK,
                                                     kBlockSize,
                                                     "b" + std::to_string(i));
    block->AllocateData(kBlockSize);
    memset(block->GetMutableData(), 0xCC, kBlockSize);

    block->set_alignment(kAlignment);
    block->set_alignment_offset(i);

    blocks.push_back(block);
  }

  const uint32_t kCharacteristics = IMAGE_SCN_CNT_CODE;
  EXPECT_TRUE(builder.OpenSection("foo", kCharacteristics));
  for (BlockGraph::Block* block : blocks) {
    EXPECT_TRUE(builder.LayoutBlock(block));
  }
  EXPECT_TRUE(builder.CloseSection());

  const std::vector<ImageLayout::SectionInfo>& sections =
      builder.image_layout()->sections;
  EXPECT_EQ("foo", sections[0].name);
  EXPECT_EQ(RelativeAddress(0x1), sections[0].addr);

  // Check if each block is placed at an address that respects its alignment
  // and that the blocks do not overlap, nor are they placed too far away from
  // each other.
  // This test uses the fact that Block::addr_ is populated upon layout.
  BlockGraph::RelativeAddress last_address;
  bool first = true;
  for (const BlockGraph::Block* block : blocks) {
    BlockGraph::RelativeAddress curr_address = block->addr();
    BlockGraph::Offset curr_offset = block->alignment_offset();

    // Test proper alignment.
    EXPECT_TRUE((curr_address + curr_offset).IsAligned(kAlignment));

    if (first) {
      first = false;

      // This is true because kOffsetMin is negative.
      EXPECT_EQ(static_cast<uint32_t>(-kOffsetMin), curr_address.value());
    } else {
      // The space between the blocks is the difference of the addresses minus
      // the data size.
      int space_between_blocks = curr_address - last_address -
                                 static_cast<int>(kBlockSize);

      // Check that blocks do not overlap.
      EXPECT_GE(space_between_blocks, 0);

      // If the space is bigger then kAlignment bytes then the block could have
      // been placed kAlignment bytes ahead.
      EXPECT_LT(space_between_blocks, static_cast<int>(kAlignment));
    }
    last_address = curr_address;
  }
}

}  // namespace pe
