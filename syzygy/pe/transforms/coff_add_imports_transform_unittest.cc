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
#include "syzygy/block_graph/unittest_util.h"
#include "syzygy/pe/pe_utils.h"
#include "syzygy/pe/unittest_util.h"

namespace pe {
namespace transforms {

using block_graph::BlockGraph;

namespace {

class CoffAddImportsTransformTest : public testing::CoffUnitTest {
 public:
  virtual void SetUp() OVERRIDE {
    testing::CoffUnitTest::SetUp();
  }

  // Check that symbols in @p module have been assigned a reference, and that
  // they pass through a round-trip writing and decomposition.
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

    ASSERT_NO_FATAL_FAILURE(TestRoundTrip());
  }
};

const char kFunction1Name[] = "__imp_?function1@@YAHXZ";
const char kFunction3Name[] = "?function3@@YAHXZ";
const char kFunction4Name[] = "?function4@@YAHXZ";
const char kMemcpy[] = "_memset";  // Multiply defined.

}  // namespace

TEST_F(CoffAddImportsTransformTest, AddImportsExisting) {
  ASSERT_NO_FATAL_FAILURE(DecomposeOriginal());
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
  ASSERT_NO_FATAL_FAILURE(DecomposeOriginal());
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

TEST_F(CoffAddImportsTransformTest, FindImportsExistingMultiple) {
  ASSERT_NO_FATAL_FAILURE(DecomposeOriginal());
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
  ASSERT_NO_FATAL_FAILURE(DecomposeOriginal());
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

TEST_F(CoffAddImportsTransformTest, EmptyStringTable) {
  // Override with a different module.
  test_dll_obj_path_ = testing::GetSrcRelativePath(
      testing::kEmptyStringTableCoffName);
  ASSERT_NO_FATAL_FAILURE(DecomposeOriginal());
  ImportedModule module("export_dll.dll");
  size_t function1 = module.AddSymbol(kFunction1Name,
                                      ImportedModule::kAlwaysImport);

  CoffAddImportsTransform transform;
  transform.AddModule(&module);
  EXPECT_TRUE(block_graph::ApplyBlockGraphTransform(
      &transform, &policy_, &block_graph_, headers_block_));
  EXPECT_EQ(0u, transform.modules_added());
  EXPECT_EQ(1u, transform.symbols_added());

  EXPECT_TRUE(module.ModuleIsImported());
  EXPECT_TRUE(module.SymbolIsImported(function1));

  EXPECT_FALSE(module.ModuleWasAdded());
  EXPECT_TRUE(module.SymbolWasAdded(function1));
}


}  // namespace transforms
}  // namespace pe
