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

#include "syzygy/pe/decomposer.h"

#include <set>

#include "base/file_util.h"
#include "base/path_service.h"
#include "base/string_util.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/block_graph/block_graph_serializer.h"
#include "syzygy/block_graph/typed_block.h"
#include "syzygy/block_graph/unittest_util.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pdb/pdb_byte_stream.h"
#include "syzygy/pdb/pdb_file.h"
#include "syzygy/pdb/pdb_reader.h"
#include "syzygy/pdb/pdb_stream.h"
#include "syzygy/pdb/pdb_util.h"
#include "syzygy/pdb/pdb_writer.h"
#include "syzygy/pe/pe_relinker.h"
#include "syzygy/pe/pe_utils.h"
#include "syzygy/pe/unittest_util.h"

namespace pe {

using block_graph::BlockGraph;
using block_graph::ConstTypedBlock;
using core::RelativeAddress;
using testing::ContainerEq;

namespace {

const size_t kPointerSize = BlockGraph::Reference::kMaximumSize;

static const BlockGraph::BlockAttributes kGapOrPadding =
    BlockGraph::GAP_BLOCK | BlockGraph::PADDING_BLOCK;

// Exposes the protected methods for testing.
class TestDecomposer: public Decomposer {
 public:
  explicit TestDecomposer(const PEFile& image_file)
      : Decomposer(image_file) {
  }

  // Expose as public for testing.
  using Decomposer::LoadBlockGraphFromPdbStream;
  using Decomposer::GetBlockGraphStreamFromPdb;
};

class DecomposerTest : public testing::PELibUnitTest {
  typedef testing::PELibUnitTest Super;

 public:
  void SetUp() {
    Super::SetUp();

    ASSERT_NO_FATAL_FAILURE(CreateTemporaryDir(&temp_dir_));
  }

  base::FilePath temp_dir_;
};

}  // namespace

TEST_F(DecomposerTest, Decompose) {
  base::FilePath image_path(testing::GetExeRelativePath(testing::kTestDllName));
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

  typedef std::map<BlockGraph::SectionId, size_t> SectionCountMap;
  typedef std::map<BlockGraph::BlockType, size_t> BlockTypeCountMap;

  // We expect every block to be associated with a section, and only two blocks
  // should not be assigned to a section--the two header blocks. Similarly, set
  // expectations on the number of blocks per section, and the number of blocks
  // by type.
  SectionCountMap section_counts;
  BlockTypeCountMap block_type_counts;
  BlockGraph::BlockMap::const_iterator it =
      block_graph.blocks().begin();
  for (; it != block_graph.blocks().end(); ++it) {
    const BlockGraph::Block& block = it->second;

    // We can't count gap or padding blocks, as more or less of these can appear
    // based on the directory in which the user performed the build.
    if (block.attributes() & kGapOrPadding)
      continue;

    ++section_counts[block.section()];
    ++block_type_counts[block.type()];
  }

  SectionCountMap expected_section_counts;
#ifndef NDEBUG
  // Debug build.
  expected_section_counts[-1] = 2;
  expected_section_counts[0] = 302;
  expected_section_counts[1] = 329;
  expected_section_counts[2] = 88;
  expected_section_counts[3] = 1;
  expected_section_counts[4] = 1;
  expected_section_counts[5] = 1;
#else
  // Release build.
  expected_section_counts[-1] = 2;
  expected_section_counts[0] = 280;
  expected_section_counts[1] = 303;
  expected_section_counts[2] = 81;
  expected_section_counts[3] = 1;
  expected_section_counts[4] = 1;
  expected_section_counts[5] = 1;
#endif
  EXPECT_THAT(section_counts, ContainerEq(expected_section_counts));

  BlockTypeCountMap expected_block_type_counts;
#ifndef NDEBUG
  // Debug build.
  expected_block_type_counts[BlockGraph::CODE_BLOCK] = 302;
  expected_block_type_counts[BlockGraph::DATA_BLOCK] = 422;
#else
  // Release build.
  expected_block_type_counts[BlockGraph::CODE_BLOCK] = 280;
  expected_block_type_counts[BlockGraph::DATA_BLOCK] = 389;
#endif
  EXPECT_THAT(block_type_counts, ContainerEq(expected_block_type_counts));

  // Make sure that all bracketed COFF groups have been parsed. There are 8
  // of them that we currently know of:
  // .CRT$XCA -> .CRT$XCZ: C initializers
  // .CRT$XIA -> .CRT$XLZ: C++ initializers
  // .CRT$XLA -> .CRT$XLZ: TLS callbacks
  // .CRT$XPA -> .CRT$XPZ: CRT pre-termination functions.
  // .CRT$XTA -> .CRT$XTZ: CRT termination functions.
  // .rtc$IAA -> .rtc$IZZ: Run-time checking initializers.
  // .rtc$TAA -> .rtc$TZZ: Run-time checking termination functions.
  // .tls -> .tls$ZZZ: TLS data.
  size_t coff_group_blocks = 0;
  it = block_graph.blocks().begin();
  for (; it != block_graph.blocks().end(); ++it) {
    const BlockGraph::Block& block = it->second;
    if (block.attributes() & BlockGraph::COFF_GROUP)
      ++coff_group_blocks;
  }
  EXPECT_EQ(8u, coff_group_blocks);
}

TEST_F(DecomposerTest, DecomposeFailsWithNonexistentPdb) {
  base::FilePath image_path(testing::GetExeRelativePath(testing::kTestDllName));
  PEFile image_file;

  ASSERT_TRUE(image_file.Init(image_path));

  Decomposer decomposer(image_file);
  decomposer.set_pdb_path(testing::GetExeRelativePath(L"nonexistent.pdb"));

  BlockGraph block_graph;
  ImageLayout image_layout(&block_graph);
  EXPECT_FALSE(decomposer.Decompose(&image_layout));
}

TEST_F(DecomposerTest, LabelsAndAttributes) {
  base::FilePath image_path(testing::GetExeRelativePath(testing::kTestDllName));
  PEFile image_file;

  ASSERT_TRUE(image_file.Init(image_path));

  // Decompose the test image and look at the result.
  Decomposer decomposer(image_file);
  BlockGraph block_graph;
  ImageLayout image_layout(&block_graph);
  ASSERT_TRUE(decomposer.Decompose(&image_layout));

  // Locate various specific function blocks in the block-graph.
  const BlockGraph::Block* dll_main_block = NULL;
  const BlockGraph::Block* func_with_inl_asm_block = NULL;
  const BlockGraph::Block* strchr_block = NULL;
  const BlockGraph::Block* imp_load_block = NULL;
  const BlockGraph::Block* no_private_symbols_block = NULL;

  typedef std::map<BlockGraph::BlockAttributeEnum, size_t> AttribCountMap;
  AttribCountMap attrib_counts;

  {
    typedef std::map<std::string, const BlockGraph::Block**> TestBlockMap;

    TestBlockMap test_blocks;
    test_blocks.insert(std::make_pair("DllMain", &dll_main_block));
    test_blocks.insert(std::make_pair("FunctionWithInlineAssembly",
                                      &func_with_inl_asm_block));
    test_blocks.insert(std::make_pair("found_bx", &strchr_block));
    test_blocks.insert(std::make_pair("__imp_load_CoCreateGuid",
                                      &imp_load_block));
    test_blocks.insert(std::make_pair("TestFunctionWithNoPrivateSymbols",
                                      &no_private_symbols_block));

    BlockGraph::BlockMap::const_iterator it = block_graph.blocks().begin();
    for (; it != block_graph.blocks().end(); ++it) {
      const BlockGraph::Block& block = it->second;

      // Count the attributes across the entire block-graph.
      for (size_t i = 0; i < BlockGraph::BLOCK_ATTRIBUTES_MAX_BIT; ++i) {
        BlockGraph::BlockAttributeEnum attr =
            static_cast<BlockGraph::BlockAttributeEnum>(1 << i);

        // We don't count gap or padding blocks as they vary from machine to
        // machine depending on lengths of certain strings.
        if (attr & kGapOrPadding)
          continue;

        if (block.attributes() & attr)
          ++attrib_counts[attr];
      }

      TestBlockMap::const_iterator test_it = test_blocks.find(block.name());
      if (test_it == test_blocks.end())
        continue;

      ASSERT_TRUE(*test_it->second == NULL);
      *test_it->second = &block;
    }
  }

  // Check the attribute counts.
  AttribCountMap expected_attrib_counts;
#ifndef NDEBUG
  // Debug build.
  expected_attrib_counts[BlockGraph::NON_RETURN_FUNCTION] = 8;
  expected_attrib_counts[BlockGraph::PE_PARSED] = 95;
  expected_attrib_counts[BlockGraph::SECTION_CONTRIB] = 720;
  expected_attrib_counts[BlockGraph::HAS_INLINE_ASSEMBLY] = 15;
  expected_attrib_counts[BlockGraph::BUILT_BY_UNSUPPORTED_COMPILER] = 142;
  expected_attrib_counts[BlockGraph::INCOMPLETE_DISASSEMBLY] = 68;
  expected_attrib_counts[BlockGraph::ERRORED_DISASSEMBLY] = 4;
  expected_attrib_counts[BlockGraph::HAS_EXCEPTION_HANDLING] = 24;
  expected_attrib_counts[BlockGraph::DISASSEMBLED_PAST_END] = 7;
  expected_attrib_counts[BlockGraph::THUNK] = 6;
  expected_attrib_counts[BlockGraph::COFF_GROUP] = 8;
#else
  // Release build.
  expected_attrib_counts[BlockGraph::NON_RETURN_FUNCTION] = 8;
  expected_attrib_counts[BlockGraph::PE_PARSED] = 93;
  expected_attrib_counts[BlockGraph::SECTION_CONTRIB] = 665;
  expected_attrib_counts[BlockGraph::HAS_INLINE_ASSEMBLY] = 14;
  expected_attrib_counts[BlockGraph::BUILT_BY_UNSUPPORTED_COMPILER] = 140;
  expected_attrib_counts[BlockGraph::INCOMPLETE_DISASSEMBLY] = 63;
  expected_attrib_counts[BlockGraph::ERRORED_DISASSEMBLY] = 4;
  expected_attrib_counts[BlockGraph::HAS_EXCEPTION_HANDLING] = 22;
  expected_attrib_counts[BlockGraph::DISASSEMBLED_PAST_END] = 7;
  expected_attrib_counts[BlockGraph::THUNK] = 6;
  expected_attrib_counts[BlockGraph::COFF_GROUP] = 8;
#endif
  EXPECT_THAT(attrib_counts, ContainerEq(expected_attrib_counts));

  // The block with no private symbols should be marked as ERRORED_DISASSEMBLY,
  // and only have a single public symbol label.
  ASSERT_FALSE(no_private_symbols_block == NULL);
  EXPECT_TRUE(no_private_symbols_block->attributes() &
      BlockGraph::ERRORED_DISASSEMBLY);
  EXPECT_EQ(1u, no_private_symbols_block->labels().size());
  BlockGraph::Block::LabelMap::const_iterator label_it =
      no_private_symbols_block->labels().begin();
  EXPECT_EQ(0, label_it->first);
  EXPECT_EQ(BlockGraph::PUBLIC_SYMBOL_LABEL, label_it->second.attributes());

  // The __imp_load__ block should be a thunk.
  ASSERT_FALSE(imp_load_block == NULL);
  EXPECT_NE(0UL, imp_load_block->attributes() & BlockGraph::THUNK);

  // Validate that the FunctionWithInlineAssembly block has the appropriate
  // attributes.
  ASSERT_FALSE(func_with_inl_asm_block == NULL);
  ASSERT_TRUE(func_with_inl_asm_block->attributes() &
      BlockGraph::HAS_INLINE_ASSEMBLY);

  // Validate that the strchr block has the appropriate attributes.
  ASSERT_FALSE(strchr_block == NULL);
  ASSERT_TRUE(strchr_block->attributes() &
      BlockGraph::BUILT_BY_UNSUPPORTED_COMPILER);

#ifdef OFFICIAL_BUILD
  static const size_t kDllMainLabelCount = 41;
  static const size_t kCallSiteLabelCount = 26;
#else
  static const size_t kDllMainLabelCount = 31;
  static const size_t kCallSiteLabelCount = 10;
#endif

  // Validate compiland name.
  EXPECT_TRUE(EndsWith(dll_main_block->compiland_name(),
                       "\\test_dll.obj",
                       true));
  EXPECT_TRUE(EndsWith(func_with_inl_asm_block->compiland_name(),
                       "\\test_dll.obj",
                       true));
  EXPECT_TRUE(EndsWith(strchr_block->compiland_name(),
                       "\\strchr.obj",
                       true));

  // Validate that the DllMain block has the expected population of labels.
  ASSERT_FALSE(dll_main_block == NULL);
  EXPECT_EQ(kDllMainLabelCount, dll_main_block->labels().size());

  // DllMain has a jump table so it should have pointer alignment.
  ASSERT_EQ(kPointerSize, dll_main_block->alignment());

  std::map<BlockGraph::LabelAttributes, size_t> label_attr_counts;
  {
    BlockGraph::Block::LabelMap::const_iterator it =
        dll_main_block->labels().begin();
    for (; it != dll_main_block->labels().end(); ++it) {
      BlockGraph::LabelAttributes attr_mask = 1;
      for (; attr_mask != BlockGraph::LABEL_ATTRIBUTES_MAX; attr_mask <<= 1) {
        if (it->second.has_attributes(attr_mask))
          label_attr_counts[attr_mask]++;
      }
    }
  }

  EXPECT_EQ(19, label_attr_counts[BlockGraph::CODE_LABEL]);
  EXPECT_EQ(kCallSiteLabelCount,
            label_attr_counts[BlockGraph::CALL_SITE_LABEL]);
  EXPECT_EQ(5, label_attr_counts[BlockGraph::DATA_LABEL]);
  EXPECT_EQ(3, label_attr_counts[BlockGraph::JUMP_TABLE_LABEL]);
  EXPECT_EQ(2, label_attr_counts[BlockGraph::CASE_TABLE_LABEL]);
  EXPECT_EQ(1, label_attr_counts[BlockGraph::DEBUG_START_LABEL]);
}

namespace {

void GetNtHeadersBlock(const BlockGraph::Block* dos_header_block,
                       BlockGraph::Block** out_nt_headers_block) {
  DCHECK(out_nt_headers_block != NULL);

  ConstTypedBlock<IMAGE_DOS_HEADER> dos_header;
  ASSERT_TRUE(dos_header.Init(0, dos_header_block));
  ConstTypedBlock<IMAGE_NT_HEADERS> nt_headers;
  ASSERT_TRUE(dos_header.Dereference(dos_header->e_lfanew, &nt_headers));
  ASSERT_TRUE(nt_headers.block() != NULL);
  *out_nt_headers_block = const_cast<BlockGraph::Block*>(nt_headers.block());
}

// This test fixture class contains all the tests that need files generated by
// the relinker (the new image and its corresponding PDB).
class DecomposerAfterRelinkTest : public DecomposerTest {
 public:
  typedef DecomposerTest Super;

  DecomposerAfterRelinkTest() : relinker_(&policy_) { }

  virtual void SetUp() OVERRIDE {
    Super::SetUp();
  }

  void Relink(bool compress_pdb) {
    // Initialize a relinker and generate a pdb that contains a block-graph
    // stream.
    relinked_dll_ = temp_dir_.Append(testing::kTestDllName);
    relinked_pdb_ = temp_dir_.Append(testing::kTestDllPdbName);

    relinker_.set_input_path(testing::GetExeRelativePath(
        testing::kTestDllName));
    relinker_.set_input_pdb_path(testing::GetExeRelativePath(
        testing::kTestDllPdbName));
    relinker_.set_allow_overwrite(true);
    relinker_.set_augment_pdb(true);
    relinker_.set_compress_pdb(compress_pdb);
    relinker_.set_output_path(relinked_dll_);
    relinker_.set_output_pdb_path(relinked_pdb_);
    ASSERT_TRUE(relinker_.Init());
    ASSERT_TRUE(relinker_.Relink());
  }

  void ReconcileNtHeaders(ImageLayout* image_layout) {
    DCHECK(image_layout != NULL);

    BlockGraph::Block* nt1 = NULL;
    ASSERT_NO_FATAL_FAILURE(GetNtHeadersBlock(relinker_.headers_block(), &nt1));
    ASSERT_TRUE(nt1 != NULL);

    BlockGraph::Block* dos_header_block =
      image_layout->blocks.GetBlockByAddress(core::RelativeAddress(0));
    ASSERT_TRUE(dos_header_block != NULL);
    BlockGraph::Block* nt2 = NULL;
    ASSERT_NO_FATAL_FAILURE(GetNtHeadersBlock(dos_header_block, &nt2));
    ASSERT_TRUE(nt2 != NULL);

    // The NT headers don't compare equal because things like the timestamp and
    // checksum are filled out post transform.
    ASSERT_EQ(nt1->data_size(), nt2->data_size());
    nt1->SetData(nt2->data(), nt2->data_size());
  }

  void LoadRedecompositionData(bool compressed) {
    ASSERT_NO_FATAL_FAILURE(Relink(compressed));

    PEFile image_file;
    ASSERT_TRUE(image_file.Init(relinked_dll_));

    // Decompose the test image and look at the result.
    Decomposer decomposer(image_file);
    BlockGraph block_graph;
    ImageLayout image_layout(&block_graph);

    ASSERT_TRUE(decomposer.Decompose(&image_layout));

    // Certain data is written to the NT headers post-transform (checksum), so
    // it's not reflected in the relinker's block-graph. We reconcile the
    // headers prior to doing the comparison.
    ASSERT_NO_FATAL_FAILURE(ReconcileNtHeaders(&image_layout));

    // Ensure that the post-relink block-graph and the deserialized one from the
    // PDB are the same.
    block_graph::BlockGraphSerializer bgs;
    ASSERT_TRUE(::testing::BlockGraphsEqual(relinker_.block_graph(),
                                            block_graph,
                                            bgs));
  }

  PETransformPolicy policy_;
  PERelinker relinker_;
  base::FilePath relinked_dll_;
  base::FilePath relinked_pdb_;
};

}  // namespace

TEST_F(DecomposerAfterRelinkTest, LoadRedecompositionDataUncompressed) {
  ASSERT_NO_FATAL_FAILURE(LoadRedecompositionData(false));
}

TEST_F(DecomposerAfterRelinkTest, LoadRedecompositionDataCompressed) {
  ASSERT_NO_FATAL_FAILURE(LoadRedecompositionData(true));
}

TEST_F(DecomposerAfterRelinkTest, FailToLoadBlockGraphWithInvalidVersion) {
  ASSERT_NO_FATAL_FAILURE(Relink(true));

  // Get the block-graph stream from the PDB and change the version of it.

  // Get the stream.
  PEFile image_file;
  ASSERT_TRUE(image_file.Init(relinked_dll_));
  TestDecomposer decomposer(image_file);
  pdb::PdbFile pdb_file;
  pdb::PdbReader pdb_reader;
  pdb_reader.Read(relinked_pdb_, &pdb_file);
  scoped_refptr<pdb::PdbStream> block_graph_stream =
      decomposer.GetBlockGraphStreamFromPdb(&pdb_file);

  // Create a copy of the stream. We need to do this to have a stream that we
  // can modify.
  scoped_refptr<pdb::PdbByteStream> new_stream = new pdb::PdbByteStream();
  ASSERT_TRUE(new_stream->Init(block_graph_stream.get()));
  block_graph_stream = new_stream.get();
  scoped_refptr<pdb::WritablePdbStream> block_graph_writer =
      block_graph_stream->GetWritablePdbStream();
  ASSERT_TRUE(block_graph_writer.get() != NULL);

  // Change the version of the stream.
  block_graph_writer->set_pos(0);
  block_graph_writer->Write(pdb::kSyzygyBlockGraphStreamVersion + 1);

  BlockGraph block_graph;
  ImageLayout image_layout(&block_graph);
  // We've invalided the version previously so this test should fail.
  ASSERT_FALSE(decomposer.LoadBlockGraphFromPdbStream(image_file,
                                                      block_graph_stream.get(),
                                                      &image_layout));
}

}  // namespace pe
