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

#include "syzygy/pe/coff_decomposer.h"

#include "gtest/gtest.h"
#include "syzygy/block_graph/typed_block.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/unittest_util.h"

namespace pe {

namespace {

using block_graph::BlockGraph;
using block_graph::ConstTypedBlock;
using core::RelativeAddress;

const size_t kPointerSize = BlockGraph::Reference::kMaximumSize;

// test_dll.coff_obj-specific constants. Adjust to match current code in
// test_dll.cc.
const size_t kNumTextSections = 26;
const size_t kNumDataSections = 2;
const size_t kNumRDataSections = 14;  // Includes .rdata$r sections.
const size_t kNumDebugSections = 28;  // Includes .debug$S and .debug$T.
const size_t kNumBssSections = 1;

const size_t kNumFunctions = 14;
const size_t kNumJumpLabelsInDllMain = 3;
const size_t kNumCaseLabelsInDllMain = 2;

class CoffDecomposerTest : public testing::Test {
 public:
  virtual void SetUp() OVERRIDE {
    testing::Test::SetUp();

    test_dll_obj_path_ =
        testing::GetExeTestDataRelativePath(testing::kTestDllCoffObjName);
    ASSERT_TRUE(image_file_.Init(test_dll_obj_path_));
  }

  base::FilePath test_dll_obj_path_;
  CoffFile image_file_;
};

}  // namespace

TEST_F(CoffDecomposerTest, Decompose) {
  // Decompose the test image.
  CoffDecomposer decomposer(image_file_);

  BlockGraph block_graph;
  ImageLayout image_layout(&block_graph);
  ASSERT_TRUE(decomposer.Decompose(&image_layout));

  EXPECT_EQ(BlockGraph::COFF_IMAGE, block_graph.image_format());

  // Retrieve the COFF file header.
  BlockGraph::Block* file_header_block =
      image_layout.blocks.GetBlockByAddress(RelativeAddress(0));
  ASSERT_TRUE(file_header_block != NULL);

  // There should be some blocks in the graph and in the layout, and the
  // same number in the block graph and image layout.
  EXPECT_LT(0u, block_graph.blocks().size());
  EXPECT_LT(0u, image_layout.blocks.size());
  EXPECT_EQ(block_graph.blocks().size(),
            image_layout.blocks.size() + kNumBssSections);

  // We expect the ImageLayout sections to agree with the BlockGraph
  // sections in number, id, name and characteristics.
  EXPECT_EQ(block_graph.sections().size(), image_layout.sections.size());
  for (size_t i = 0; i < image_layout.sections.size(); ++i) {
    const BlockGraph::Section* section = block_graph.GetSectionById(i);
    ASSERT_TRUE(section != NULL);
    EXPECT_EQ(section->id(), i);
    EXPECT_EQ(section->name(), image_layout.sections[i].name);
    EXPECT_EQ(section->characteristics(),
              image_layout.sections[i].characteristics);
  }

  // Count symbols.
  size_t num_internal_symbols = 0;
  size_t num_assoc_comdat_sections = 0;
  size_t num_symbols = image_file_.file_header()->NumberOfSymbols;
  for (size_t i = 0; i < num_symbols; ++i) {
    const IMAGE_SYMBOL* symbol = image_file_.symbol(i);
    i += symbol->NumberOfAuxSymbols;
    if (symbol->SectionNumber > 0)
      ++num_internal_symbols;
  }

  // Check that the number of sections, blocks and references match
  // expectations.
  size_t num_code_blocks = 0;
  size_t num_section_blocks = 0;
  size_t num_section_blocks_with_references = 0;
  size_t num_debug_section_blocks = 0;
  size_t num_non_section_blocks = 0;
  size_t num_references_in_symbol_table = 0;
  BlockGraph::BlockMap::const_iterator it =
      block_graph.blocks().begin();
  for (; it != block_graph.blocks().end(); ++it) {
    const BlockGraph::Block& block = it->second;

    if (block.type() == BlockGraph::CODE_BLOCK)
      ++num_code_blocks;

    if (block.section() == BlockGraph::kInvalidSectionId) {
      ++num_non_section_blocks;

      if ((block.attributes() & BlockGraph::COFF_SYMBOL_TABLE) != 0)
        num_references_in_symbol_table = block.references().size();
    } else {
      // If this is not a header block, it should refer to a valid
      // section index.
      EXPECT_LT(block.section(), block_graph.sections().size());
      ++num_section_blocks;

      BlockGraph::Section* section =
          block_graph.GetSectionById(block.section());
      DCHECK(section != NULL);
      if (section->name() == ".debug$S")
        ++num_debug_section_blocks;

      size_t num_relocs =
          image_file_.section_header(block.section())->NumberOfRelocations;
      // Debug sections also have hard-coded references in addition to
      // relocation references, so the numbers will not match exactly, but
      // it will be at least that many.
      if (image_file_.GetSectionName(block.section()) == ".debug$S") {
        EXPECT_LE(num_relocs, block.references().size());
      } else {
        EXPECT_EQ(num_relocs, block.references().size());
      }
      if (block.references().size() > 0)
        ++num_section_blocks_with_references;
    }
  }
  EXPECT_EQ(num_section_blocks + num_non_section_blocks,
            block_graph.blocks().size());

  // Each symbol has one section and one section offset reference; plus,
  // each associative COMDAT section definition must have one additional
  // reference. In test_dll.obj, only .debug$S sections should be COMDAT
  // associative, except the global .debug$S section.
  EXPECT_EQ(2 * num_internal_symbols + num_debug_section_blocks - 1,
            num_references_in_symbol_table);

  // There should be at least as many code blocks as there are functions in
  // test_dll.cc.
  EXPECT_LE(kNumFunctions, num_code_blocks);

  // There should be exactly one block per section (including BSS sections)
  // in an object file with function-level linking.
  EXPECT_EQ(image_file_.file_header()->NumberOfSections, num_section_blocks);

  // Non-section blocks should be: the header block, the symbol and string
  // tables, and the per-section relocations tables.
  EXPECT_EQ(num_section_blocks_with_references + 3, num_non_section_blocks);
}

TEST_F(CoffDecomposerTest, FunctionsAndLabels) {
  // Decompose the test image and look at the result.
  CoffDecomposer decomposer(image_file_);
  BlockGraph block_graph;
  ImageLayout image_layout(&block_graph);
  ASSERT_TRUE(decomposer.Decompose(&image_layout));

  // Locate various specific function blocks in the block graph, while
  // validating the number of blocks matching each section name (.text,
  // .data, etc.).
  size_t num_text_blocks = 0;
  size_t num_data_blocks = 0;
  size_t num_rdata_blocks = 0;
  size_t num_debug_blocks = 0;
  size_t num_bss_blocks = 0;
  const BlockGraph::Block* dll_main_block = NULL;
  const BlockGraph::Block* func_with_inl_asm_block = NULL;

  BlockGraph::BlockMap::const_iterator block_it =
      block_graph.blocks().begin();
  for (; block_it != block_graph.blocks().end(); ++block_it) {
    const BlockGraph::Block* block = &block_it->second;
    const std::string& name = block->name();

    if (name.find(".text") != std::string::npos)
      ++num_text_blocks;
    else if (name.find(".data") != std::string::npos)
      ++num_data_blocks;
    else if (name.find(".rdata") != std::string::npos)
      ++num_rdata_blocks;
    else if (name.find(".debug") != std::string::npos)
      ++num_debug_blocks;
    else if (name.find(".bss") != std::string::npos)
      ++num_bss_blocks;

    if (block->type() == BlockGraph::CODE_BLOCK) {
      if (name.find("DllMain") != std::string::npos) {
        EXPECT_TRUE(dll_main_block == NULL);
        dll_main_block = &block_it->second;
      } else if (name.find("FunctionWithInlineAssembly") != std::string::npos) {
        EXPECT_TRUE(func_with_inl_asm_block == NULL);
        func_with_inl_asm_block = &block_it->second;
      }
    }
  }

  EXPECT_EQ(kNumTextSections, num_text_blocks);
  EXPECT_EQ(kNumDataSections, num_data_blocks);
  EXPECT_EQ(kNumRDataSections, num_rdata_blocks);
  EXPECT_EQ(kNumDebugSections, num_debug_blocks);
  EXPECT_EQ(kNumBssSections, num_bss_blocks);

  EXPECT_TRUE(dll_main_block != NULL);
  EXPECT_TRUE(func_with_inl_asm_block != NULL);

  // TODO(lenh): Check for HAS_INLINE_ASSEMBLY attribute when we are able to
  // parse CV debug information to tag functions with inline assembly
  // properly.

  // Validate that the DllMain block has the expected population of labels.
  // These numbers should match those for the PE decomposer.
  std::map<BlockGraph::LabelAttributes, size_t> label_attr_counts;
  BlockGraph::Block::LabelMap::const_iterator label_it =
      dll_main_block->labels().begin();
  for (; label_it != dll_main_block->labels().end(); ++label_it) {
    BlockGraph::LabelAttributes attr_mask = 1;
    for (; attr_mask != BlockGraph::LABEL_ATTRIBUTES_MAX; attr_mask <<= 1) {
      if (label_it->second.has_attributes(attr_mask))
        ++label_attr_counts[attr_mask];
    }
  }

  EXPECT_EQ(kNumJumpLabelsInDllMain,
            label_attr_counts[BlockGraph::JUMP_TABLE_LABEL]);
  EXPECT_EQ(kNumCaseLabelsInDllMain,
            label_attr_counts[BlockGraph::CASE_TABLE_LABEL]);
}

}  // namespace pe
