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

#include "syzygy/pehacker/operations/redirect_imports_operation.h"

#include <algorithm>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/pe/pe_transform_policy.h"
#include "syzygy/pehacker/unittest_util.h"

namespace pehacker {
namespace operations {

namespace {

using block_graph::BlockGraph;
using testing::Return;

const char kSimpleConfig[] =
    "{\n"
    "  \"type\": \"redirect_imports\",\n"
    "  \"redirects\": [\n"
    "    { \"src\": { \"module_name\": \"foo.dll\",\n"
    "                 \"function_name\": \"foo\" },\n"
    "      \"dst\": { \"module_name\": \"bar.dll\",\n"
    "                 \"function_name\": \"bar\" },\n"
    "    },\n"
    "  ],\n"
    "}";

class LenientTestRedirectImportsOperation : public RedirectImportsOperation {
 public:
  LenientTestRedirectImportsOperation() { }
  virtual ~LenientTestRedirectImportsOperation() { }

  MOCK_METHOD4(ApplyTransform, bool(block_graph::BlockGraphTransformInterface*,
                                    const TransformPolicyInterface*,
                                    BlockGraph*,
                                    BlockGraph::Block*));
  MOCK_METHOD0(RedirectImports, bool(void));

  typedef RedirectImportsOperation::ImportedModule ImportedModule;
  typedef RedirectImportsOperation::ImportedModuleMap ImportedModuleMap;
  typedef RedirectImportsOperation::ImportedSymbol ImportedSymbol;
  typedef RedirectImportsOperation::RedirectedSymbol RedirectedSymbol;
  typedef RedirectImportsOperation::RedirectedSymbols RedirectedSymbols;

  using RedirectImportsOperation::add_imports_tx_;
  using RedirectImportsOperation::imported_modules_;
  using RedirectImportsOperation::imported_module_map_;
  using RedirectImportsOperation::redirects_;
};
typedef testing::StrictMock<LenientTestRedirectImportsOperation>
    TestRedirectImportsOperation;

typedef TestRedirectImportsOperation::ImportedModule ImportedModule;
typedef TestRedirectImportsOperation::ImportedModuleMap  ImportedModuleMap;

typedef testing::OperationTest RedirectImportsOperationTest;

void GetNonPEReferrers(const BlockGraph::Reference& reference,
                       BlockGraph::Block::ReferrerSet* referrers) {
  ASSERT_TRUE(referrers != NULL);
  referrers->clear();

  // Iterate over referrers of the referenced block.
  BlockGraph::Block::ReferrerSet::const_iterator ref_it =
      reference.referenced()->referrers().begin();
  for (; ref_it != reference.referenced()->referrers().end(); ++ref_it) {
    BlockGraph::Block* src_block = ref_it->first;
    BlockGraph::Offset src_offset = ref_it->second;

    // Skip PE blocks.
    if (src_block->attributes() & BlockGraph::PE_PARSED)
      continue;

    // Get the source reference.
    BlockGraph::Reference src_ref;
    ASSERT_TRUE(src_block->GetReference(src_offset, &src_ref));

    // If this is to the reference in question, then record it.
    if (src_ref.referenced() == reference.referenced() &&
        src_ref.offset() == reference.offset()) {
      referrers->insert(std::make_pair(src_block, src_offset));
    }
  }
}

}  // namespace

TEST_F(RedirectImportsOperationTest, Name) {
  TestRedirectImportsOperation op;
  EXPECT_STREQ(TestRedirectImportsOperation::kName, op.name());
}

TEST_F(RedirectImportsOperationTest, InitFailsNoRedirects) {
  const char kConfig[] = "{ \"type\": \"redirect_imports\" }";
  TestRedirectImportsOperation op;
  ASSERT_NO_FATAL_FAILURE(InitConfig(kConfig));
  pe::PETransformPolicy policy;
  EXPECT_FALSE(op.Init(&policy, config_.get()));
}

TEST_F(RedirectImportsOperationTest, InitFailsRedirectNoSrc) {
  const char kConfig[] =
      "{ \"type\": \"redirect_imports\",\n"
      "  \"redirects\": [ { \"dst\": { \"module_name\": \"foo.dll\",\n"
      "                                \"function_name\": \"foo\" } } ] }";
  TestRedirectImportsOperation op;
  ASSERT_NO_FATAL_FAILURE(InitConfig(kConfig));
  pe::PETransformPolicy policy;
  EXPECT_FALSE(op.Init(&policy, config_.get()));
}

TEST_F(RedirectImportsOperationTest, InitFailsRedirectNoDst) {
  const char kConfig[] =
      "{ \"type\": \"redirect_imports\",\n"
      "  \"redirects\": [ { \"src\": { \"module_name\": \"foo.dll\",\n"
      "                                \"function_name\": \"foo\" } } ] }";
  TestRedirectImportsOperation op;
  ASSERT_NO_FATAL_FAILURE(InitConfig(kConfig));
  pe::PETransformPolicy policy;
  EXPECT_FALSE(op.Init(&policy, config_.get()));
}

TEST_F(RedirectImportsOperationTest, InitFailsOrdinalAndFunctionName) {
  const char kConfig[] =
      "{ \"type\": \"redirect_imports\",\n"
      "  \"redirects\": [ { \"src\": { \"module_name\": \"bar.dll\",\n"
      "                                \"function_name\": \"bar\",\n"
      "                                \"ordinal\": 2 },\n"
      "                     \"dst\": { \"module_name\": \"foo.dll\",\n"
      "                                \"function_name\": \"foo\" } } ] }";
  TestRedirectImportsOperation op;
  ASSERT_NO_FATAL_FAILURE(InitConfig(kConfig));
  pe::PETransformPolicy policy;
  EXPECT_FALSE(op.Init(&policy, config_.get()));
}

TEST_F(RedirectImportsOperationTest, InitFailsOrdinal) {
  const char kConfig[] =
      "{ \"type\": \"redirect_imports\",\n"
      "  \"redirects\": [ { \"src\": { \"module_name\": \"bar.dll\",\n"
      "                                \"ordinal\": 2 },\n"
      "                     \"dst\": { \"module_name\": \"foo.dll\",\n"
      "                                \"function_name\": \"foo\" } } ] }";
  TestRedirectImportsOperation op;
  ASSERT_NO_FATAL_FAILURE(InitConfig(kConfig));
  pe::PETransformPolicy policy;
  EXPECT_FALSE(op.Init(&policy, config_.get()));
}

TEST_F(RedirectImportsOperationTest, InitSucceedsUselessRedirect) {
  const char kConfig[] =
      "{ \"type\": \"redirect_imports\",\n"
      "  \"redirects\": [ { \"src\": { \"module_name\": \"bar.dll\",\n"
      "                                \"function_name\": \"bar\" },\n"
      "                     \"dst\": { \"module_name\": \"bar.dll\",\n"
      "                                \"function_name\": \"bar\" } } ] }";
  TestRedirectImportsOperation op;
  ASSERT_NO_FATAL_FAILURE(InitConfig(kConfig));
  pe::PETransformPolicy policy;
  EXPECT_TRUE(op.Init(&policy, config_.get()));
  EXPECT_EQ(0u, op.redirects_.size());
}

TEST_F(RedirectImportsOperationTest, Init) {
  TestRedirectImportsOperation op;
  ASSERT_NO_FATAL_FAILURE(InitConfig(kSimpleConfig));
  pe::PETransformPolicy policy;
  EXPECT_TRUE(op.Init(&policy, config_.get()));

  EXPECT_EQ(2u, op.imported_modules_.size());
  EXPECT_EQ(2u, op.imported_module_map_.size());

  // Ensure the transform is appropriately configured.
  // The modules are in alphabetical order in the map, but in order of
  // appearance in the vector.
  ImportedModuleMap::iterator mod_it = op.imported_module_map_.begin();
  EXPECT_EQ("bar.dll", mod_it->first);
  EXPECT_EQ(op.imported_modules_[1], mod_it->second);
  EXPECT_EQ("bar.dll", mod_it->second->name());
  EXPECT_EQ(1u, mod_it->second->size());
  EXPECT_EQ("bar", mod_it->second->GetSymbolName(0));
  EXPECT_EQ(pe::transforms::ImportedModule::kFindOnly,
            mod_it->second->GetSymbolMode(0));

  ++mod_it;
  EXPECT_EQ("foo.dll", mod_it->first);
  EXPECT_EQ(op.imported_modules_[0], mod_it->second);
  EXPECT_EQ("foo.dll", mod_it->second->name());
  EXPECT_EQ(1u, mod_it->second->size());
  EXPECT_EQ("foo", mod_it->second->GetSymbolName(0));
  EXPECT_EQ(pe::transforms::ImportedModule::kFindOnly,
            mod_it->second->GetSymbolMode(0));

  EXPECT_EQ(1u, op.redirects_.size());
  const TestRedirectImportsOperation::RedirectedSymbol& redirect =
      op.redirects_.front();
  const TestRedirectImportsOperation::ImportedSymbol& src = redirect.first;
  const TestRedirectImportsOperation::ImportedSymbol& dst = redirect.second;
  EXPECT_EQ("foo.dll", src.first->name());
  EXPECT_EQ("foo", src.first->GetSymbolName(src.second));
  EXPECT_EQ("bar.dll", dst.first->name());
  EXPECT_EQ("bar", dst.first->GetSymbolName(dst.second));
}

TEST_F(RedirectImportsOperationTest, RunApplyFails) {
  TestRedirectImportsOperation op;
  ASSERT_NO_FATAL_FAILURE(InitConfig(kSimpleConfig));
  pe::PETransformPolicy policy;
  ASSERT_TRUE(op.Init(&policy, config_.get()));

  BlockGraph bg;
  BlockGraph::Block* header = bg.AddBlock(BlockGraph::DATA_BLOCK, 1, "header");

  EXPECT_CALL(op, ApplyTransform(&op.add_imports_tx_,
                                 &policy,
                                 &bg,
                                 header)).WillOnce(Return(false));

  EXPECT_FALSE(op.Apply(&policy, &bg, header));
}

TEST_F(RedirectImportsOperationTest, RunRedirectFails) {
  TestRedirectImportsOperation op;
  ASSERT_NO_FATAL_FAILURE(InitConfig(kSimpleConfig));
  pe::PETransformPolicy policy;
  ASSERT_TRUE(op.Init(&policy, config_.get()));

  BlockGraph bg;
  BlockGraph::Block* header = bg.AddBlock(BlockGraph::DATA_BLOCK, 1, "header");

  EXPECT_CALL(op, ApplyTransform(&op.add_imports_tx_,
                                 &policy,
                                 &bg,
                                 header)).WillOnce(Return(true));

  EXPECT_CALL(op, RedirectImports()).WillOnce(Return(false));

  EXPECT_FALSE(op.Apply(&policy, &bg, header));
}

TEST_F(RedirectImportsOperationTest, RunSucceeds) {
  TestRedirectImportsOperation op;
  ASSERT_NO_FATAL_FAILURE(InitConfig(kSimpleConfig));
  pe::PETransformPolicy policy;
  ASSERT_TRUE(op.Init(&policy, config_.get()));

  BlockGraph bg;
  BlockGraph::Block* header = bg.AddBlock(BlockGraph::DATA_BLOCK, 1, "header");

  EXPECT_CALL(op, ApplyTransform(&op.add_imports_tx_,
                                 &policy,
                                 &bg,
                                 header)).WillOnce(Return(true));

  EXPECT_CALL(op, RedirectImports()).WillOnce(Return(true));

  EXPECT_TRUE(op.Apply(&policy, &bg, header));
}

TEST_F(RedirectImportsOperationTest, SucceedsOnTestDll) {
  const char kConfig[] =
      "{ \"type\": \"redirect_imports\",\n"
      "  \"redirects\": [ { \"src\": { \"module_name\": \"export_dll.dll\",\n"
      "                                \"function_name\": \"function1\" },\n"
      "                     \"dst\": { \"module_name\": \"export_dll.dll\",\n"
      "                                \"function_name\": \"function3\" } }\n"
      "                 ] }";

  // Decompose test dll.
  BlockGraph block_graph;
  pe::ImageLayout image_layout(&block_graph);
  pe::PEFile pe_file;
  ASSERT_NO_FATAL_FAILURE(DecomposeTestDll(false, &pe_file, &image_layout));
  BlockGraph::Block* header = image_layout.blocks.GetBlockByAddress(
      core::RelativeAddress(0));

  // Find function1 and function3.
  pe::transforms::PEAddImportsTransform find_imports;
  ImportedModule export_dll("export_dll.dll");
  size_t function1_idx = export_dll.AddSymbol("function1",
                                              ImportedModule::kFindOnly);
  size_t function3_idx = export_dll.AddSymbol("function3",
                                              ImportedModule::kFindOnly);
  find_imports.AddModule(&export_dll);
  pe::PETransformPolicy policy;
  ASSERT_TRUE(find_imports.TransformBlockGraph(
      &policy, &block_graph, header));

  // Get all references to function1 that aren't from PE blocks.
  BlockGraph::Reference ref_to_function1;
  export_dll.GetSymbolReference(function1_idx, &ref_to_function1);
  BlockGraph::Block::ReferrerSet refs_to_function1;
  ASSERT_NO_FATAL_FAILURE(GetNonPEReferrers(ref_to_function1,
                                            &refs_to_function1));

  BlockGraph::Reference ref_to_function3;
  export_dll.GetSymbolReference(function3_idx, &ref_to_function3);
  BlockGraph::Block::ReferrerSet refs_to_function3;
  ASSERT_NO_FATAL_FAILURE(GetNonPEReferrers(ref_to_function3,
                                            &refs_to_function3));

  // Apply the operation to it.
  RedirectImportsOperation op;
  ASSERT_NO_FATAL_FAILURE(InitConfig(kConfig));
  ASSERT_TRUE(op.Init(&policy, config_.get()));
  EXPECT_TRUE(op.Apply(&policy, &block_graph, header));

  // Get the references after the transform.
  BlockGraph::Block::ReferrerSet new_refs_to_function1;
  ASSERT_NO_FATAL_FAILURE(GetNonPEReferrers(ref_to_function1,
                                            &new_refs_to_function1));

  BlockGraph::Block::ReferrerSet new_refs_to_function3;
  ASSERT_NO_FATAL_FAILURE(GetNonPEReferrers(ref_to_function3,
                                            &new_refs_to_function3));

  //BlockGraph::Block::ReferrerSet expected_refs_to_function3(
  BlockGraph::Block::ReferrerSet expected_refs_to_function3;
  std::set_union(refs_to_function1.begin(),
                 refs_to_function1.end(),
                 refs_to_function3.begin(),
                 refs_to_function3.end(),
                 std::inserter(expected_refs_to_function3,
                               expected_refs_to_function3.begin()));

  EXPECT_THAT(new_refs_to_function3,
              testing::ContainerEq(expected_refs_to_function3));
}

}  // namespace operations
}  // namespace pehacker
