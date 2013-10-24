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

#include "syzygy/pehacker/operations/add_imports_operation.h"

#include "base/json/json_reader.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/pe_transform_policy.h"

namespace pehacker {
namespace operations {

namespace {

using block_graph::BlockGraph;
using testing::Return;

const char kSimpleConfig[] =
    "{\n"
    "  \"type\": \"add_imports\",\n"
    "  \"modules\": [\n"
    "    {\n"
    "      \"module_name\": \"foo.dll\","
    "      \"imports\": [\n"
    "        { \"function_name\": \"bar\" },\n"
    "      ]\n"
    "    },\n"
    "  ],\n"
    "}";

class TestAddImportsOperation : public AddImportsOperation {
 public:
  TestAddImportsOperation() { }
  virtual ~TestAddImportsOperation() { }

  MOCK_METHOD4(ApplyTransform, bool(block_graph::BlockGraphTransformInterface*,
                                    const TransformPolicyInterface*,
                                    BlockGraph*,
                                    BlockGraph::Block*));

  typedef AddImportsOperation::ImportedModuleMap ImportedModuleMap;

  using AddImportsOperation::add_imports_tx_;
  using AddImportsOperation::imported_modules_;
  using AddImportsOperation::imported_module_map_;
};

class AddImportsOperationTest : public testing::Test {
 public:
  AddImportsOperationTest() : previous_log_level_(0) {
  }

  void SetUp() {
    // Silence logging.
    previous_log_level_ = logging::GetMinLogLevel();
    logging::SetMinLogLevel(logging::LOG_FATAL);
  }

  void TearDown() {
    // Restore logging to its previous level.
    logging::SetMinLogLevel(previous_log_level_);
    previous_log_level_ = 0;
  }

  void InitConfig() {
    scoped_ptr<base::Value> value(base::JSONReader::Read(
        kSimpleConfig, base::JSON_ALLOW_TRAILING_COMMAS));
    ASSERT_TRUE(value.get() != NULL);
    base::DictionaryValue* dict = NULL;
    ASSERT_TRUE(value->GetAsDictionary(&dict));
    config_.reset(dict);
    value.release();
  }

  int previous_log_level_;
  scoped_ptr<base::DictionaryValue> config_;
};

}  // namespace

TEST_F(AddImportsOperationTest, Name) {
  TestAddImportsOperation op;
  EXPECT_STREQ(TestAddImportsOperation::kName, op.name());
}

TEST_F(AddImportsOperationTest, Init) {
  TestAddImportsOperation op;
  ASSERT_NO_FATAL_FAILURE(InitConfig());
  pe::PETransformPolicy policy;
  EXPECT_TRUE(op.Init(&policy, config_.get()));

  EXPECT_EQ(1u, op.imported_modules_.size());
  EXPECT_EQ(1u, op.imported_module_map_.size());

  // Ensure the transform is appropriately configured.
  TestAddImportsOperation::ImportedModuleMap::iterator mod_it =
      op.imported_module_map_.begin();
  EXPECT_EQ("foo.dll", mod_it->first);
  EXPECT_EQ(op.imported_modules_[0], mod_it->second);
  EXPECT_EQ("foo.dll", mod_it->second->name());
  EXPECT_EQ(1u, mod_it->second->size());
  EXPECT_EQ("bar", mod_it->second->GetSymbolName(0));
  EXPECT_EQ(pe::transforms::ImportedModule::kAlwaysImport,
            mod_it->second->GetSymbolMode(0));
}

TEST_F(AddImportsOperationTest, RunFails) {
  TestAddImportsOperation op;
  ASSERT_NO_FATAL_FAILURE(InitConfig());
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

TEST_F(AddImportsOperationTest, RunSucceeds) {
  TestAddImportsOperation op;
  ASSERT_NO_FATAL_FAILURE(InitConfig());
  pe::PETransformPolicy policy;
  ASSERT_TRUE(op.Init(&policy, config_.get()));

  BlockGraph bg;
  BlockGraph::Block* header = bg.AddBlock(BlockGraph::DATA_BLOCK, 1, "header");

  EXPECT_CALL(op, ApplyTransform(&op.add_imports_tx_,
                                 &policy,
                                 &bg,
                                 header)).WillOnce(Return(true));

  EXPECT_TRUE(op.Apply(&policy, &bg, header));
}

}  // namespace operations
}  // namespace pehacker
