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
#include "base/process_util.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/block_graph/typed_block.h"
#include "syzygy/block_graph/orderers/original_orderer.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/coff_decomposer.h"
#include "syzygy/pe/coff_file.h"
#include "syzygy/pe/coff_file_writer.h"
#include "syzygy/pe/new_decomposer.h"
#include "syzygy/pe/pe_utils.h"
#include "syzygy/pe/unittest_util.h"

namespace pe {

namespace {

using block_graph::BlockGraph;
using block_graph::ConstTypedBlock;
using block_graph::OrderedBlockGraph;
using core::RelativeAddress;

class CoffImageLayoutBuilderTest : public testing::PELibUnitTest {
 public:
  CoffImageLayoutBuilderTest() : image_layout_(&block_graph_) {
  }

  virtual void SetUp() OVERRIDE {
    test_dll_obj_path_ =
        testing::GetExeTestDataRelativePath(testing::kTestDllCoffObjName);
    ASSERT_NO_FATAL_FAILURE(CreateTemporaryDir(&temp_dir_path_));
    new_test_dll_obj_path_ = temp_dir_path_.Append(L"test_dll.obj");
    new_test_dll_path_ = temp_dir_path_.Append(testing::kTestDllName);
  }

 protected:
  // Decompose, reorder, and lay out test_dll.coff_obj into a new object
  // file, located at new_test_dll_obj_path_.
  void RewriteTestDllObj() {
    // Decompose the original image.
    CoffFile image_file;
    ASSERT_TRUE(image_file.Init(test_dll_obj_path_));

    CoffDecomposer decomposer(image_file);
    ASSERT_TRUE(decomposer.Decompose(&image_layout_));

    // Fetch headers block.
    ConstTypedBlock<IMAGE_FILE_HEADER> file_header;
    BlockGraph::Block* headers_block =
        image_layout_.blocks.GetBlockByAddress(RelativeAddress(0));
    ASSERT_TRUE(headers_block != NULL);
    ASSERT_TRUE(file_header.Init(0, headers_block));

    // Reorder using the same original ordering.
    OrderedBlockGraph ordered_graph(&block_graph_);
    block_graph::orderers::OriginalOrderer orig_orderer;
    ASSERT_TRUE(orig_orderer.OrderBlockGraph(&ordered_graph, headers_block));

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

  // Call the linker to produce a new test DLL located at
  // new_test_dll_obj_path_.
  void LinkNewTestDll() {
    // Link the rewritten object file into a new DLL.
    base::LaunchOptions opts;
    opts.wait = true;

    // Try dry-running the linker with no inputs to see if the binary can be
    // found in the current path; if not, issue a clear error.
    CommandLine::StringVector args;
    args.push_back(L"LINK");
    args.push_back(L"/NOLOGO");
    ASSERT_TRUE(base::LaunchProcess(CommandLine(args), opts, NULL))
        << "Cannot run LINK.EXE; executable not in PATH?";

    // Build linker command line.
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
                   temp_dir_path_.Append(L"test_dll.lib").value());
    args.push_back(L"/PDB:" +
                   temp_dir_path_.Append(L"test_dll.dll.pdb").value());

    args.push_back(L"/LIBPATH:" +
                   testing::GetExeTestDataRelativePath(L".").value());
    args.push_back(L"ole32.lib");
    args.push_back(L"export_dll.lib");
    args.push_back(L"test_dll_no_private_symbols.lib");

    base::FilePath def_path(
        testing::GetSrcRelativePath(L"syzygy\\pe\\test_dll.def"));
    base::FilePath label_test_func_obj_path(
        testing::GetExeTestDataRelativePath(L"test_dll_label_test_func.obj"));
    args.push_back(L"/DEF:" + def_path.value());
    args.push_back(label_test_func_obj_path.value());
    args.push_back(new_test_dll_obj_path_.value());

    // Link and check result.
    ASSERT_TRUE(base::LaunchProcess(CommandLine(args), opts, NULL));
    ASSERT_NO_FATAL_FAILURE(CheckTestDll(new_test_dll_path_));
  }

  base::FilePath test_dll_obj_path_;
  base::FilePath new_test_dll_obj_path_;
  base::FilePath new_test_dll_path_;
  base::FilePath temp_dir_path_;

  // Original image layout and block graph.
  BlockGraph block_graph_;
  ImageLayout image_layout_;
};

}  // namespace

TEST_F(CoffImageLayoutBuilderTest, Link) {
  ASSERT_NO_FATAL_FAILURE(RewriteTestDllObj());
  ASSERT_NO_FATAL_FAILURE(LinkNewTestDll());
}

TEST_F(CoffImageLayoutBuilderTest, Redecompose) {
  ASSERT_NO_FATAL_FAILURE(RewriteTestDllObj());

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

TEST_F(CoffImageLayoutBuilderTest, RedecomposePE) {
  ASSERT_NO_FATAL_FAILURE(RewriteTestDllObj());
  ASSERT_NO_FATAL_FAILURE(LinkNewTestDll());

  PEFile pe_file;
  ASSERT_TRUE(pe_file.Init(new_test_dll_path_));

  NewDecomposer pe_decomposer(pe_file);
  block_graph::BlockGraph pe_block_graph;
  pe::ImageLayout pe_image_layout(&pe_block_graph);
  ASSERT_TRUE(pe_decomposer.Decompose(&pe_image_layout));
}

}  // namespace pe
