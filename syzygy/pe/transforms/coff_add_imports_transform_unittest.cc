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

#include "syzygy/pe/transforms/coff_add_imports_transform.h"

#include "gtest/gtest.h"
#include "syzygy/block_graph/typed_block.h"
#include "syzygy/block_graph/unittest_util.h"
#include "syzygy/block_graph/orderers/original_orderer.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/coff_decomposer.h"
#include "syzygy/pe/coff_file.h"
#include "syzygy/pe/coff_file_writer.h"
#include "syzygy/pe/coff_image_layout_builder.h"
#include "syzygy/pe/pe_utils.h"
#include "syzygy/pe/unittest_util.h"

namespace pe {
namespace transforms {

using block_graph::BlockGraph;
using block_graph::ConstTypedBlock;
using block_graph::OrderedBlockGraph;
using core::RelativeAddress;

namespace {

class CoffAddImportsTransformTest : public testing::PELibUnitTest {
 public:
  CoffAddImportsTransformTest() : image_layout_(&block_graph_) {
  }

  virtual void SetUp() OVERRIDE {
    testing::PELibUnitTest::SetUp();

    test_dll_obj_path_ =
        testing::GetExeTestDataRelativePath(testing::kTestDllCoffObjName);
    ASSERT_NO_FATAL_FAILURE(CreateTemporaryDir(&temp_dir_path_));
    new_test_dll_obj_path_ = temp_dir_path_.Append(L"test_dll.obj");

    ASSERT_NO_FATAL_FAILURE(DecomposeOriginal());
  }

 protected:
  // Decompose test_dll.coff_obj.
  void DecomposeOriginal() {
    ASSERT_TRUE(image_file_.Init(test_dll_obj_path_));
    CoffDecomposer decomposer(image_file_);
    ASSERT_TRUE(decomposer.Decompose(&image_layout_));

    headers_block_ = image_layout_.blocks.GetBlockByAddress(RelativeAddress(0));
    ASSERT_TRUE(headers_block_ != NULL);
  }

  // Reorder and lay out test_dll.coff_obj into a new object file, located
  // at new_test_dll_obj_path_.
  void LayoutAndWriteNew(block_graph::BlockGraphOrdererInterface* orderer) {
    DCHECK(orderer != NULL);

    // Cast headers block.
    ConstTypedBlock<IMAGE_FILE_HEADER> file_header;
    ASSERT_TRUE(file_header.Init(0, headers_block_));

    // Reorder using the specified ordering.
    OrderedBlockGraph ordered_graph(&block_graph_);
    ASSERT_TRUE(orderer->OrderBlockGraph(&ordered_graph, headers_block_));

    // Wipe references from headers, so we can remove relocation blocks
    // during laying out.
    ASSERT_TRUE(headers_block_->RemoveAllReferences());

    // Lay out new image.
    ImageLayout new_image_layout(&block_graph_);
    CoffImageLayoutBuilder layout_builder(&new_image_layout);
    ASSERT_TRUE(layout_builder.LayoutImage(ordered_graph));

    // Write temporary image file.
    CoffFileWriter writer(&new_image_layout);
    ASSERT_TRUE(writer.WriteImage(new_test_dll_obj_path_));
  }

  // Check that symbols in @p module have been assigned a reference, and
  // that writing and parsing the file again yields a symbol table that
  // contains them.
  void TestSymbols(const ImportedModule& module) {
    // Check resulting references.
    for (size_t i = 0; i < module.size(); ++i) {
      BlockGraph::Reference ref;
      EXPECT_TRUE(module.GetSymbolReference(i, &ref));
      EXPECT_TRUE(ref.referenced() != NULL);
      EXPECT_GE(ref.offset(), 0);
      EXPECT_LT(ref.offset(),
                static_cast<BlockGraph::Offset>(ref.referenced()->size()));
    }

    // Rewrite file and parse new symbol table.
    block_graph::orderers::OriginalOrderer orig_orderer;
    ASSERT_NO_FATAL_FAILURE(LayoutAndWriteNew(&orig_orderer));
    CoffFile image_file;
    ASSERT_TRUE(image_file.Init(new_test_dll_obj_path_));

    size_t num_found = 0;
    size_t num_symbols = image_file.file_header()->NumberOfSymbols;
    const IMAGE_SYMBOL* symbol = NULL;
    for (size_t i = 0; i < num_symbols; i += 1 + symbol->NumberOfAuxSymbols) {
      symbol = image_file.symbol(i);
      const char* name = image_file.GetSymbolName(i);
      for (size_t j = 0; j < module.size(); ++j) {
        if (module.GetSymbolName(j) == name)
          ++num_found;
      }
    }
    EXPECT_EQ(module.size(), num_found);
  }

  base::FilePath test_dll_obj_path_;
  base::FilePath new_test_dll_obj_path_;
  base::FilePath temp_dir_path_;

  // Original image details.
  testing::DummyTransformPolicy policy_;
  CoffFile image_file_;
  BlockGraph block_graph_;
  ImageLayout image_layout_;
  BlockGraph::Block* headers_block_;
};

const char kFunction1Name[] = "__imp_?function1@@YAHXZ";
const char kFunction3Name[] = "?function3@@YAHXZ";
const char kFunction4Name[] = "?function4@@YAHXZ";

}  // namespace

TEST_F(CoffAddImportsTransformTest, AddImportsExisting) {
  ImportedModule module("export_dll.dll");
  size_t function1 = module.AddSymbol(kFunction1Name,
                                      ImportedModule::kAlwaysImport);
  size_t function3 = module.AddSymbol(kFunction3Name,
                                      ImportedModule::kAlwaysImport);

  CoffAddImportsTransform transform;
  transform.AddModule(&module);
  EXPECT_TRUE(block_graph::ApplyBlockGraphTransform(
      &transform, &policy_, &block_graph_, headers_block_));
  EXPECT_EQ(0u, transform.modules_added());
  EXPECT_EQ(0u, transform.symbols_added());

  EXPECT_TRUE(module.ModuleIsImported());
  EXPECT_TRUE(module.SymbolIsImported(function1));
  EXPECT_TRUE(module.SymbolIsImported(function3));

  EXPECT_FALSE(module.ModuleWasAdded());
  EXPECT_FALSE(module.SymbolWasAdded(function1));
  EXPECT_FALSE(module.SymbolWasAdded(function3));

  EXPECT_NO_FATAL_FAILURE(TestSymbols(module));
}

TEST_F(CoffAddImportsTransformTest, AddImportsNewSymbol) {
  ImportedModule module("export_dll.dll");
  size_t function1 = module.AddSymbol(kFunction1Name,
                                      ImportedModule::kAlwaysImport);
  size_t function3 = module.AddSymbol(kFunction3Name,
                                      ImportedModule::kAlwaysImport);
  size_t function4 = module.AddSymbol(kFunction4Name,
                                      ImportedModule::kAlwaysImport);

  CoffAddImportsTransform transform;
  transform.AddModule(&module);
  EXPECT_TRUE(block_graph::ApplyBlockGraphTransform(
      &transform, &policy_, &block_graph_, headers_block_));
  EXPECT_EQ(0u, transform.modules_added());
  EXPECT_EQ(1u, transform.symbols_added());

  EXPECT_TRUE(module.ModuleIsImported());
  EXPECT_TRUE(module.SymbolIsImported(function1));
  EXPECT_TRUE(module.SymbolIsImported(function3));
  EXPECT_TRUE(module.SymbolIsImported(function4));

  EXPECT_FALSE(module.ModuleWasAdded());
  EXPECT_FALSE(module.SymbolWasAdded(function1));
  EXPECT_FALSE(module.SymbolWasAdded(function3));
  EXPECT_TRUE(module.SymbolWasAdded(function4));

  EXPECT_NO_FATAL_FAILURE(TestSymbols(module));
}

TEST_F(CoffAddImportsTransformTest, FindImportsExisting) {
  ImportedModule module("export_dll.dll");
  size_t function1 = module.AddSymbol(kFunction1Name,
                                      ImportedModule::kFindOnly);
  size_t function3 = module.AddSymbol(kFunction3Name,
                                      ImportedModule::kFindOnly);

  CoffAddImportsTransform transform;
  transform.AddModule(&module);
  EXPECT_TRUE(block_graph::ApplyBlockGraphTransform(
      &transform, &policy_, &block_graph_, headers_block_));
  EXPECT_EQ(0u, transform.modules_added());
  EXPECT_EQ(0u, transform.symbols_added());

  EXPECT_TRUE(module.ModuleIsImported());
  EXPECT_TRUE(module.SymbolIsImported(function1));
  EXPECT_TRUE(module.SymbolIsImported(function3));

  EXPECT_FALSE(module.ModuleWasAdded());
  EXPECT_FALSE(module.SymbolWasAdded(function1));
  EXPECT_FALSE(module.SymbolWasAdded(function3));
}

TEST_F(CoffAddImportsTransformTest, FindImportsNewSymbol) {
  ImportedModule module("export_dll.dll");
  size_t function1 = module.AddSymbol(kFunction1Name,
                                      ImportedModule::kFindOnly);
  size_t function3 = module.AddSymbol(kFunction3Name,
                                      ImportedModule::kFindOnly);
  size_t function4 = module.AddSymbol(kFunction4Name,
                                      ImportedModule::kFindOnly);

  CoffAddImportsTransform transform;
  transform.AddModule(&module);
  EXPECT_TRUE(block_graph::ApplyBlockGraphTransform(
      &transform, &policy_, &block_graph_, headers_block_));
  EXPECT_EQ(0u, transform.modules_added());
  EXPECT_EQ(0u, transform.symbols_added());

  EXPECT_TRUE(module.ModuleIsImported());
  EXPECT_TRUE(module.SymbolIsImported(function1));
  EXPECT_TRUE(module.SymbolIsImported(function3));
  EXPECT_FALSE(module.SymbolIsImported(function4));

  EXPECT_FALSE(module.ModuleWasAdded());
  EXPECT_FALSE(module.SymbolWasAdded(function1));
  EXPECT_FALSE(module.SymbolWasAdded(function3));
  EXPECT_FALSE(module.SymbolWasAdded(function4));
}

}  // namespace transforms
}  // namespace pe
