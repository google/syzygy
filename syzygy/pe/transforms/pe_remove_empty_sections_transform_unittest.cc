// Copyright 2014 Google Inc. All Rights Reserved.
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

#include "syzygy/pe/transforms/pe_remove_empty_sections_transform.h"

#include "gtest/gtest.h"
#include "syzygy/pe/decomposer.h"
#include "syzygy/pe/pe_utils.h"
#include "syzygy/pe/unittest_util.h"

namespace pe {
namespace transforms {

namespace {

using block_graph::BlockGraph;
typedef block_graph::BlockGraph::Section Section;

// _asm ret
const uint8 kCodeRet[] = { 0xC3 };

// Dummy data.
const uint8 kData[] = { 0x01, 0x02, 0x03, 0x04 };

class PERemoveEmptySectionsTransformTest : public testing::Test {
 public:
  PERemoveEmptySectionsTransformTest()
      : image_layout_(&block_graph_),
        block_header_(NULL) {
  }

  virtual void SetUp() OVERRIDE {
    // Set the block graph type to PE_IMAGE.
    block_graph_.set_image_format(BlockGraph::PE_IMAGE);

    // Create the text section.
    BlockGraph::Section* section_text = block_graph_.AddSection(".text", 0);
    ASSERT_TRUE(section_text != NULL);
    pe::ImageLayout::SectionInfo section_info_text = {};
    section_info_text.name = section_text->name();
    section_info_text.addr = core::RelativeAddress(0x1000);
    section_info_text.size = 0x1000;
    section_info_text.data_size = 0x1000;
    image_layout_.sections.push_back(section_info_text);

    // Create the unused section.
    BlockGraph::Section* section_unused = block_graph_.AddSection(".unused", 0);
    ASSERT_TRUE(section_unused != NULL);
    pe::ImageLayout::SectionInfo section_info_unused = {};
    section_info_unused.name = section_unused->name();
    section_info_unused.addr = core::RelativeAddress(0x2000);
    section_info_unused.size = 0x1000;
    section_info_unused.data_size = 0x1000;
    image_layout_.sections.push_back(section_info_unused);

    // Create the DOS header.
    block_header_ = block_graph_.AddBlock(BlockGraph::DATA_BLOCK,
                                          sizeof(kData),
                                          "header");
    ASSERT_TRUE(block_header_ != NULL);

    // Create main function block.
    block_main_ =
        block_graph_.AddBlock(BlockGraph::CODE_BLOCK, sizeof(kCodeRet), "main");
    DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), block_main_);
    block_main_->SetData(kCodeRet, sizeof(kCodeRet));
    block_main_->SetLabel(0, "main", BlockGraph::CODE_LABEL);


    // Put blocks into text section.
    block_header_->set_section(section_text->id());
    block_main_->set_section(section_text->id());
  }

  PEFile pe_file_;
  testing::DummyTransformPolicy policy_;
  BlockGraph block_graph_;
  ImageLayout image_layout_;
  BlockGraph::Block* block_header_;
  BlockGraph::Block* block_main_;
};

}  // namespace


TEST_F(PERemoveEmptySectionsTransformTest, RemoveSection) {
  // Validate that both section exists.
  Section* section_text = block_graph_.FindSection(".text");
  Section* section_ununsed = block_graph_.FindSection(".unused");
  ASSERT_TRUE(section_text != NULL);
  ASSERT_TRUE(section_ununsed != NULL);

  // Apply the transform.
  PERemoveEmptySectionsTransform transform;
  EXPECT_TRUE(block_graph::ApplyBlockGraphTransform(
      &transform, &policy_, &block_graph_, block_header_));

  // Validate that .text still exists.
  EXPECT_EQ(section_text, block_graph_.FindSection(".text"));

  // Validate that the unused section no longer exists.
  section_ununsed = block_graph_.FindSection(".unused");
  EXPECT_TRUE(section_ununsed == NULL);
}

}  // namespace transforms
}  // namespace pe
