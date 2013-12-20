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

#include "syzygy/pe/transforms/pe_coff_add_imports_transform.h"

#include "gtest/gtest.h"

namespace pe {
namespace transforms {
namespace {

using block_graph::BlockGraph;

class TestPECoffAddImportsTransform : public PECoffAddImportsTransform {
 public:
  using PECoffAddImportsTransform::UpdateModule;
  using PECoffAddImportsTransform::UpdateModuleSymbolInfo;
  using PECoffAddImportsTransform::UpdateModuleSymbolReference;
};

}  // namespace

TEST(ImportedModuleTest, UniqueSymbol) {
  ImportedModule module("foo");

  size_t i1 = module.AddSymbol("bar", ImportedModule::kFindOnly);
  EXPECT_EQ(ImportedModule::kFindOnly, module.GetSymbolMode(i1));

  // The mode should be 'bumped', but the symbol index should be the same.
  size_t i2 = module.AddSymbol("bar", ImportedModule::kAlwaysImport);
  EXPECT_EQ(ImportedModule::kAlwaysImport, module.GetSymbolMode(i1));
  EXPECT_EQ(i1, i2);
}

TEST(ImportedModuleTest, BeforeTransform) {
  ImportedModule module("foo");
  EXPECT_EQ("foo", module.name());
  EXPECT_EQ(0, module.size());

  EXPECT_EQ(ImportedModule::kFindOnly, module.mode());
  size_t froboz1 = module.AddSymbol("froboz1", ImportedModule::kFindOnly);
  EXPECT_EQ(ImportedModule::kFindOnly, module.mode());
  size_t bar1 = module.AddSymbol("bar1", ImportedModule::kAlwaysImport);
  EXPECT_EQ(ImportedModule::kAlwaysImport, module.mode());
  size_t froboz2 = module.AddSymbol("froboz2", ImportedModule::kFindOnly);
  EXPECT_EQ(3, module.size());

  EXPECT_EQ("froboz1", module.GetSymbolName(froboz1));
  EXPECT_EQ("bar1", module.GetSymbolName(bar1));
  EXPECT_EQ("froboz2", module.GetSymbolName(froboz2));

  EXPECT_EQ(ImportedModule::kFindOnly, module.GetSymbolMode(froboz1));
  EXPECT_EQ(ImportedModule::kAlwaysImport, module.GetSymbolMode(bar1));
  EXPECT_EQ(ImportedModule::kFindOnly, module.GetSymbolMode(froboz2));
}

TEST(ImportedModuleTest, WithDate) {
  ImportedModule module("abcd", 0xABCD);
  EXPECT_EQ("abcd", module.name());
  EXPECT_EQ(0xABCD, module.date());
  EXPECT_EQ(0, module.size());
}

TEST(ImportedModuleTest, AfterTransform) {
  ImportedModule module("foo");
  EXPECT_EQ("foo", module.name());
  EXPECT_EQ(0, module.size());

  size_t froboz1 = module.AddSymbol("froboz1", ImportedModule::kFindOnly);
  size_t bar1 = module.AddSymbol("bar1", ImportedModule::kAlwaysImport);
  size_t froboz2 = module.AddSymbol("froboz2", ImportedModule::kFindOnly);
  EXPECT_EQ(3, module.size());

  TestPECoffAddImportsTransform transform;
  EXPECT_EQ(0, transform.modules_added());
  transform.AddModule(&module);
  // modules_added() is for modules that were added to the import table, not
  // by AddModule(), hence it should still return zero.
  EXPECT_EQ(0, transform.modules_added());

  TestPECoffAddImportsTransform::UpdateModule(true, true, &module);
  EXPECT_TRUE(module.ModuleIsImported());
  EXPECT_TRUE(module.ModuleWasAdded());

  TestPECoffAddImportsTransform::UpdateModuleSymbolInfo(bar1, true,
                                                        true, &module);
  EXPECT_TRUE(module.SymbolIsImported(bar1));
  EXPECT_TRUE(module.SymbolWasAdded(bar1));

  BlockGraph block_graph;
  BlockGraph::Block* some_block =
      block_graph.AddBlock(BlockGraph::CODE_BLOCK, 0x100, "some_block");
  BlockGraph::Reference ref(BlockGraph::ABSOLUTE_REF, 4, some_block, 0, 0);
  TestPECoffAddImportsTransform::UpdateModuleSymbolReference(bar1, ref,
                                                             true, &module);
  BlockGraph::Reference actual_ref;
  bool is_ptr = false;
  ASSERT_TRUE(module.GetSymbolReference(bar1, &actual_ref, &is_ptr));
  EXPECT_EQ(ref, actual_ref);
  EXPECT_TRUE(is_ptr);
}

}  // namespace transforms
}  // namespace pe
