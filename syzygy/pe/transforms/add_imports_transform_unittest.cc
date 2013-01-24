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

#include "syzygy/pe/transforms/add_imports_transform.h"

#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/decomposer.h"
#include "syzygy/pe/pe_utils.h"
#include "syzygy/pe/unittest_util.h"

namespace pe {
namespace transforms {

using block_graph::BlockGraph;
using core::RelativeAddress;
typedef AddImportsTransform::ImportedModule ImportedModule;

namespace {

class AddImportsTransformTest : public testing::PELibUnitTest {
 public:
  AddImportsTransformTest() : image_layout_(&block_graph_) {
  }

  virtual void SetUp() {
    FilePath image_path(testing::GetExeRelativePath(kDllName));

    ASSERT_TRUE(pe_file_.Init(image_path));

    // Decompose the test image and look at the result.
    Decomposer decomposer(pe_file_);
    ASSERT_TRUE(decomposer.Decompose(&image_layout_));

    // Retrieve and validate the DOS header.
    dos_header_block_ =
        image_layout_.blocks.GetBlockByAddress(RelativeAddress(0));
    ASSERT_TRUE(dos_header_block_ != NULL);
    ASSERT_TRUE(IsValidDosHeaderBlock(dos_header_block_));
  }

  PEFile pe_file_;
  BlockGraph block_graph_;
  ImageLayout image_layout_;
  BlockGraph::Block* dos_header_block_;
};

// Given an ImportedModule tests that all of its symbols have been properly
// processed.
void TestSymbols(const ImportedModule& module) {
  for (size_t i = 0; i < module.size(); ++i) {
    BlockGraph::Reference ref;
    EXPECT_TRUE(module.GetSymbolReference(i, &ref));
    EXPECT_TRUE(ref.referenced() != NULL);
    EXPECT_GE(ref.offset(), 0);
    EXPECT_LT(ref.offset(),
              static_cast<BlockGraph::Offset>(ref.referenced()->size()));
  }
}

}  // namespace

TEST_F(AddImportsTransformTest, AddImportsExisting) {
  ImportedModule module("export_dll.dll");
  size_t function1 = module.AddSymbol("function1");
  size_t function3 = module.AddSymbol("function3");
  EXPECT_EQ("function1", module.GetSymbolName(function1));
  EXPECT_EQ("function3", module.GetSymbolName(function3));

  AddImportsTransform transform;
  transform.AddModule(&module);
  EXPECT_TRUE(block_graph::ApplyBlockGraphTransform(
      &transform, &block_graph_, dos_header_block_));
  EXPECT_EQ(0u, transform.modules_added());
  EXPECT_EQ(0u, transform.symbols_added());

  EXPECT_NO_FATAL_FAILURE(TestSymbols(module));
}

TEST_F(AddImportsTransformTest, AddImportsNewSymbol) {
  ImportedModule module("export_dll.dll");
  size_t function1 = module.AddSymbol("function1");
  size_t function3 = module.AddSymbol("function3");
  size_t function4 = module.AddSymbol("function4");
  EXPECT_EQ("function1", module.GetSymbolName(function1));
  EXPECT_EQ("function3", module.GetSymbolName(function3));
  EXPECT_EQ("function4", module.GetSymbolName(function4));

  AddImportsTransform transform;
  transform.AddModule(&module);
  EXPECT_TRUE(block_graph::ApplyBlockGraphTransform(
      &transform, &block_graph_, dos_header_block_));
  EXPECT_EQ(0u, transform.modules_added());
  EXPECT_EQ(1u, transform.symbols_added());

  EXPECT_NO_FATAL_FAILURE(TestSymbols(module));

  // TODO(chrisha): Write the image and try to load it!
}

TEST_F(AddImportsTransformTest, AddImportsNewModule) {
  ImportedModule module("call_trace_client_rpc.dll");
  size_t indirect_penter = module.AddSymbol("_indirect_penter");
  size_t indirect_penter_dllmain = module.AddSymbol("_indirect_penter_dllmain");
  EXPECT_EQ("_indirect_penter",
            module.GetSymbolName(indirect_penter));
  EXPECT_EQ("_indirect_penter_dllmain",
            module.GetSymbolName(indirect_penter_dllmain));

  AddImportsTransform transform;
  transform.AddModule(&module);
  EXPECT_TRUE(block_graph::ApplyBlockGraphTransform(
      &transform, &block_graph_, dos_header_block_));
  EXPECT_EQ(1u, transform.modules_added());
  EXPECT_EQ(2u, transform.symbols_added());

  EXPECT_NO_FATAL_FAILURE(TestSymbols(module));

  // TODO(chrisha): Write the image and try to load it!
}

}  // namespace transforms
}  // namespace pe
