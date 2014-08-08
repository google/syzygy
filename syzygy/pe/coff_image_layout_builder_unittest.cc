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

#include "syzygy/pe/coff_image_layout_builder.h"

#include <cstring>

#include "base/command_line.h"
#include "base/process/launch.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/block_graph/typed_block.h"
#include "syzygy/block_graph/orderers/original_orderer.h"
#include "syzygy/common/align.h"
#include "syzygy/core/random_number_generator.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/coff_decomposer.h"
#include "syzygy/pe/coff_file.h"
#include "syzygy/pe/coff_file_writer.h"
#include "syzygy/pe/decomposer.h"
#include "syzygy/pe/pe_utils.h"
#include "syzygy/pe/unittest_util.h"
#include "syzygy/testing/toolchain.h"

namespace pe {
namespace {

using block_graph::BlockGraph;
using block_graph::ConstTypedBlock;
using block_graph::OrderedBlockGraph;
using core::RelativeAddress;

class ShuffleOrderer : public block_graph::BlockGraphOrdererInterface {
 public:
  explicit ShuffleOrderer(uint32 seed) : rng_(seed) {
  }

  virtual const char* name() const OVERRIDE {
    return "ShuffleOrderer";
  }

  // Shuffle sections while paying attention to put .debug$S sections at the
  // end, so that they come after the associated sections.
  virtual bool OrderBlockGraph(
      OrderedBlockGraph* ordered_graph,
      BlockGraph::Block* /* headers_block */) OVERRIDE {
    DCHECK(ordered_graph != NULL);
    BlockGraph* graph = ordered_graph->block_graph();
    DCHECK(graph != NULL);

    std::vector<BlockGraph::SectionId> sections;
    for (size_t i = 0; i < graph->sections().size(); ++i)
      sections.push_back(i);

    std::random_shuffle(sections.begin(), sections.end(), rng_);
    for (size_t i = 0; i < sections.size(); ++i) {
      BlockGraph::Section* section = graph->GetSectionById(sections[i]);
      if (section->name() == ".debug$S")
        ordered_graph->PlaceAtTail(section);
      else
        ordered_graph->PlaceAtHead(section);
    }

    return true;
  }

 private:
  core::RandomNumberGenerator rng_;
};

// We can't rely on CommandLine to built the command-line string for us
// because it doesn't maintain the order of arguments.
void MakeCommandLineString(const CommandLine::StringVector& args,
                           CommandLine::StringType* cmd_line) {
  DCHECK(cmd_line != NULL);

  cmd_line->clear();
  for (size_t i = 0; i < args.size(); ++i) {
    if (i > 0)
      cmd_line->push_back(L' ');
    cmd_line->push_back(L'"');
    cmd_line->append(args[i]);
    cmd_line->push_back(L'"');
  }
}

class CoffImageLayoutBuilderTest : public testing::PELibUnitTest {
 public:
  CoffImageLayoutBuilderTest() : image_layout_(&block_graph_) {
  }

  virtual void SetUp() OVERRIDE {
    testing::PELibUnitTest::SetUp();

    test_dll_obj_path_ =
        testing::GetExeTestDataRelativePath(testing::kTestDllCoffObjName);
    ASSERT_NO_FATAL_FAILURE(CreateTemporaryDir(&temp_dir_path_));
    new_test_dll_obj_path_ = temp_dir_path_.Append(L"test_dll.obj");
    new_test_dll_path_ = temp_dir_path_.Append(testing::kTestDllName);
  }

 protected:
  // Decompose test_dll.coff_obj.
  void DecomposeOriginal() {
    ASSERT_TRUE(image_file_.Init(test_dll_obj_path_));
    CoffDecomposer decomposer(image_file_);
    ASSERT_TRUE(decomposer.Decompose(&image_layout_));
  }

  // Reorder and lay out test_dll.coff_obj into a new object file, located
  // at new_test_dll_obj_path_.
  void LayoutAndWriteNew(block_graph::BlockGraphOrdererInterface* orderer) {
    DCHECK(orderer != NULL);

    // Fetch headers block.
    ConstTypedBlock<IMAGE_FILE_HEADER> file_header;
    BlockGraph::Block* headers_block =
        image_layout_.blocks.GetBlockByAddress(RelativeAddress(0));
    ASSERT_TRUE(headers_block != NULL);
    ASSERT_TRUE(file_header.Init(0, headers_block));

    // Reorder using the specified ordering.
    OrderedBlockGraph ordered_graph(&block_graph_);
    ASSERT_TRUE(orderer->OrderBlockGraph(&ordered_graph, headers_block));

    // Wipe references from headers, so we can remove relocation blocks
    // during laying out.
    ASSERT_TRUE(headers_block->RemoveAllReferences());

    // Lay out new image.
    ImageLayout new_image_layout(&block_graph_);
    CoffImageLayoutBuilder layout_builder(&new_image_layout);
    ASSERT_TRUE(layout_builder.LayoutImage(ordered_graph));

    // Write temporary image file.
    CoffFileWriter writer(&new_image_layout);
    ASSERT_TRUE(writer.WriteImage(new_test_dll_obj_path_));
  }

  // Decompose, reorder, and lay out test_dll.coff_obj.
  void RewriteTestDllObj(block_graph::BlockGraphOrdererInterface* orderer) {
    DCHECK(orderer != NULL);

    ASSERT_NO_FATAL_FAILURE(DecomposeOriginal());
    ASSERT_NO_FATAL_FAILURE(LayoutAndWriteNew(orderer));
  }

  // Call the linker to produce a new test DLL located at
  // new_test_dll_obj_path_.
  void LinkNewTestDll() {
    // Link the rewritten object file into a new DLL.
    base::LaunchOptions opts;
    opts.wait = true;

    // Build linker command line.
    CommandLine::StringVector args;
    args.push_back(testing::kToolchainWrapperPath);
    args.push_back(L"LINK.EXE");
    args.push_back(L"/NOLOGO");
    args.push_back(L"/INCREMENTAL:NO");
    args.push_back(L"/DEBUG");
    args.push_back(L"/PROFILE");
    args.push_back(L"/SAFESEH");
    args.push_back(L"/LARGEADDRESSAWARE");
    args.push_back(L"/NXCOMPAT");
    args.push_back(L"/NODEFAULTLIB:libcmtd.lib");
    args.push_back(L"/DLL");
    args.push_back(L"/MACHINE:X86");
    args.push_back(L"/SUBSYSTEM:CONSOLE");

    args.push_back(L"/OUT:" + new_test_dll_path_.value());
    args.push_back(L"/IMPLIB:" +
                   temp_dir_path_.Append(L"test_dll.dll.lib").value());
    args.push_back(L"/PDB:" +
                   temp_dir_path_.Append(L"test_dll.dll.pdb").value());

    args.push_back(L"/LIBPATH:" +
                   testing::GetExeTestDataRelativePath(L".").value());
    args.push_back(L"ole32.lib");
    args.push_back(L"export_dll.dll.lib");
    args.push_back(L"test_dll_no_private_symbols.lib");

    base::FilePath def_path(
        testing::GetSrcRelativePath(L"syzygy\\pe\\test_dll.def"));
    base::FilePath label_test_func_obj_path(
        testing::GetExeTestDataRelativePath(L"test_dll_label_test_func.obj"));
    args.push_back(L"/DEF:" + def_path.value());
    args.push_back(label_test_func_obj_path.value());
    args.push_back(new_test_dll_obj_path_.value());

    // Link and check result.
    CommandLine::StringType cmd_line;
    MakeCommandLineString(args, &cmd_line);
    ASSERT_TRUE(base::LaunchProcess(cmd_line, opts, NULL));
    ASSERT_NO_FATAL_FAILURE(CheckTestDll(new_test_dll_path_));
  }

  base::FilePath test_dll_obj_path_;
  base::FilePath new_test_dll_obj_path_;
  base::FilePath new_test_dll_path_;
  base::FilePath temp_dir_path_;

  // Original image details.
  CoffFile image_file_;
  BlockGraph block_graph_;
  ImageLayout image_layout_;
};

bool IsDebugBlock(const BlockGraph::Block& block, const BlockGraph& graph) {
  if (block.section() == BlockGraph::kInvalidSectionId)
    return false;
  const BlockGraph::Section* section = graph.GetSectionById(block.section());
  if (section->name() != ".debug$S")
    return false;
  return true;
}

}  // namespace

TEST_F(CoffImageLayoutBuilderTest, Redecompose) {
  block_graph::orderers::OriginalOrderer orig_orderer;
  ASSERT_NO_FATAL_FAILURE(RewriteTestDllObj(&orig_orderer));

  // Redecompose.
  CoffFile image_file;
  ASSERT_TRUE(image_file.Init(new_test_dll_obj_path_));

  CoffDecomposer decomposer(image_file);
  block_graph::BlockGraph block_graph;
  pe::ImageLayout image_layout(&block_graph);
  ASSERT_TRUE(decomposer.Decompose(&image_layout));

  // Compare the results of the two decompositions.
  ConstTypedBlock<IMAGE_FILE_HEADER> file_header;
  BlockGraph::Block* headers_block =
      image_layout.blocks.GetBlockByAddress(RelativeAddress(0));
  ASSERT_TRUE(headers_block != NULL);
  ASSERT_TRUE(file_header.Init(0, headers_block));

  EXPECT_EQ(image_layout_.sections.size(), image_layout.sections.size());
  EXPECT_EQ(image_layout_.blocks.size(), image_layout.blocks.size());

  // Expect same sections in the same order, due to original ordering.
  for (size_t i = 0; i < image_layout_.sections.size(); ++i) {
    EXPECT_EQ(image_layout_.sections[i].name, image_layout.sections[i].name);
    EXPECT_EQ(image_layout_.sections[i].characteristics,
              image_layout.sections[i].characteristics);
  }
}

TEST_F(CoffImageLayoutBuilderTest, Shuffle) {
  ShuffleOrderer shuffle_orderer(1234);
  ASSERT_NO_FATAL_FAILURE(RewriteTestDllObj(&shuffle_orderer));

  // Save rounded-up sizes of sections to which symbols point; these should
  // not change even if sections are shuffled.
  std::vector<size_t> symbol_ref_block_sizes;
  BlockGraph::BlockMap::const_iterator it =
      block_graph_.blocks().begin();
  for (; it != block_graph_.blocks().end(); ++it) {
    if ((it->second.attributes() & BlockGraph::COFF_SYMBOL_TABLE) == 0)
      continue;

    BlockGraph::Block::ReferenceMap::const_iterator ref_it =
        it->second.references().begin();
    for (; ref_it != it->second.references().end(); ++ref_it) {
      symbol_ref_block_sizes.push_back(
          common::AlignUp(ref_it->second.referenced()->data_size(), 4));
    }
  }

  // Redecompose.
  CoffFile image_file;
  ASSERT_TRUE(image_file.Init(new_test_dll_obj_path_));

  CoffDecomposer decomposer(image_file);
  block_graph::BlockGraph block_graph;
  pe::ImageLayout image_layout(&block_graph);
  ASSERT_TRUE(decomposer.Decompose(&image_layout));

  // Compare the results of the two decompositions.
  ConstTypedBlock<IMAGE_FILE_HEADER> file_header;
  BlockGraph::Block* headers_block =
      image_layout.blocks.GetBlockByAddress(RelativeAddress(0));
  ASSERT_TRUE(headers_block != NULL);
  ASSERT_TRUE(file_header.Init(0, headers_block));

  EXPECT_EQ(image_layout_.sections.size(), image_layout.sections.size());
  EXPECT_EQ(image_layout_.blocks.size(), image_layout.blocks.size());

  // Expect symbols to point to the same blocks they did in the previous
  // graph, though they will have been shuffled around.
  it = block_graph.blocks().begin();
  for (; it != block_graph.blocks().end(); ++it) {
    if ((it->second.attributes() & BlockGraph::COFF_SYMBOL_TABLE) == 0)
      continue;

    ASSERT_EQ(symbol_ref_block_sizes.size(), it->second.references().size());

    size_t i = 0;
    BlockGraph::Block::ReferenceMap::const_iterator ref_it =
        it->second.references().begin();
    for (; ref_it != it->second.references().end(); ++ref_it) {
      EXPECT_EQ(symbol_ref_block_sizes[i++],
                ref_it->second.referenced()->data_size());
    }
    EXPECT_EQ(symbol_ref_block_sizes.size(), i);
  }
}

TEST_F(CoffImageLayoutBuilderTest, ShiftedCode) {
  ASSERT_NO_FATAL_FAILURE(DecomposeOriginal());

  // Store hard-coded references in debug sections.
  std::vector<BlockGraph::Reference> orig_refs;
  BlockGraph::BlockMap::const_iterator it =
      block_graph_.blocks().begin();
  for (; it != block_graph_.blocks().end(); ++it) {
    if (!IsDebugBlock(it->second, block_graph_))
      continue;
    BlockGraph::Block::ReferenceMap::const_iterator ref_it =
        it->second.references().begin();
    for (; ref_it != it->second.references().end(); ++ref_it) {
      if (ref_it->second.referenced()->type() != BlockGraph::CODE_BLOCK ||
          (ref_it->second.type() & BlockGraph::RELOC_REF_BIT) != 0) {
        continue;
      }
      orig_refs.push_back(ref_it->second);
    }
  }

  // Shift every code block.
  BlockGraph::BlockMap& blocks = block_graph_.blocks_mutable();
  BlockGraph::BlockMap::iterator mutable_it = blocks.begin();
  for (; mutable_it != blocks.end(); ++mutable_it) {
    if (mutable_it->second.type() != BlockGraph::CODE_BLOCK)
      continue;

    mutable_it->second.InsertData(0, 11, false);
    uint8* data = mutable_it->second.GetMutableData();
    for (size_t i = 0; i < 11; ++i) {
      // NOP.
      data[i] = 0x90;
    }
  }

  // Check that references have been shifted.
  size_t i = 0;
  it = block_graph_.blocks().begin();
  for (; it != block_graph_.blocks().end(); ++it) {
    if (!IsDebugBlock(it->second, block_graph_))
      continue;
    BlockGraph::Block::ReferenceMap::const_iterator ref_it =
        it->second.references().begin();
    for (; ref_it != it->second.references().end(); ++ref_it) {
      if (ref_it->second.referenced()->type() != BlockGraph::CODE_BLOCK ||
          (ref_it->second.type() & BlockGraph::RELOC_REF_BIT) != 0) {
        continue;
      }
      ASSERT_EQ(orig_refs[i++].offset() + 11, ref_it->second.offset());
    }
  }

  // Write the new object.
  block_graph::orderers::OriginalOrderer orig_orderer;
  ASSERT_NO_FATAL_FAILURE(LayoutAndWriteNew(&orig_orderer));

  // Redecompose.
  CoffFile image_file;
  ASSERT_TRUE(image_file.Init(new_test_dll_obj_path_));

  CoffDecomposer decomposer(image_file);
  block_graph::BlockGraph block_graph;
  pe::ImageLayout image_layout(&block_graph);
  ASSERT_TRUE(decomposer.Decompose(&image_layout));

  // Compare references.
  i = 0;
  it = block_graph.blocks().begin();
  for (; it != block_graph.blocks().end(); ++it) {
    if (!IsDebugBlock(it->second, block_graph))
      continue;
    BlockGraph::Block::ReferenceMap::const_iterator ref_it =
        it->second.references().begin();
    for (; ref_it != it->second.references().end(); ++ref_it) {
      if (ref_it->second.referenced()->type() != BlockGraph::CODE_BLOCK ||
          (ref_it->second.type() & BlockGraph::RELOC_REF_BIT) != 0) {
        continue;
      }
      EXPECT_EQ(orig_refs[i++].offset() + 11, ref_it->second.offset());
    }
  }
}

TEST_F(CoffImageLayoutBuilderTest, RedecomposePE) {
  block_graph::orderers::OriginalOrderer orig_orderer;
  ASSERT_NO_FATAL_FAILURE(RewriteTestDllObj(&orig_orderer));
  ASSERT_NO_FATAL_FAILURE(LinkNewTestDll());

  PEFile pe_file;
  ASSERT_TRUE(pe_file.Init(new_test_dll_path_));

  Decomposer pe_decomposer(pe_file);
  block_graph::BlockGraph pe_block_graph;
  pe::ImageLayout pe_image_layout(&pe_block_graph);
  ASSERT_TRUE(pe_decomposer.Decompose(&pe_image_layout));
}

TEST_F(CoffImageLayoutBuilderTest, RedecomposeRandom) {
  ShuffleOrderer shuffle_orderer(1234);
  ASSERT_NO_FATAL_FAILURE(RewriteTestDllObj(&shuffle_orderer));

  // Redecompose.
  CoffFile image_file;
  ASSERT_TRUE(image_file.Init(new_test_dll_obj_path_));

  CoffDecomposer decomposer(image_file);
  block_graph::BlockGraph block_graph;
  pe::ImageLayout image_layout(&block_graph);
  ASSERT_TRUE(decomposer.Decompose(&image_layout));

  // Compare the results of the two decompositions.
  ConstTypedBlock<IMAGE_FILE_HEADER> file_header;
  BlockGraph::Block* headers_block =
      image_layout.blocks.GetBlockByAddress(RelativeAddress(0));
  ASSERT_TRUE(headers_block != NULL);
  ASSERT_TRUE(file_header.Init(0, headers_block));

  EXPECT_EQ(image_layout_.sections.size(), image_layout.sections.size());
  EXPECT_EQ(image_layout_.blocks.size(), image_layout.blocks.size());
}

TEST_F(CoffImageLayoutBuilderTest, RedecomposePERandom) {
  ShuffleOrderer shuffle_orderer(1234);
  ASSERT_NO_FATAL_FAILURE(RewriteTestDllObj(&shuffle_orderer));
  ASSERT_NO_FATAL_FAILURE(LinkNewTestDll());

  PEFile pe_file;
  ASSERT_TRUE(pe_file.Init(new_test_dll_path_));

  Decomposer pe_decomposer(pe_file);
  block_graph::BlockGraph pe_block_graph;
  pe::ImageLayout pe_image_layout(&pe_block_graph);
  ASSERT_TRUE(pe_decomposer.Decompose(&pe_image_layout));
}

}  // namespace pe
