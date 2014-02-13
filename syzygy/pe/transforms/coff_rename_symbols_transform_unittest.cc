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

#include "syzygy/pe/transforms/coff_rename_symbols_transform.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/block_graph/block_hash.h"
#include "syzygy/block_graph/unittest_util.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/coff_decomposer.h"
#include "syzygy/pe/coff_utils.h"
#include "syzygy/pe/pe_utils.h"
#include "syzygy/pe/unittest_util.h"

namespace pe {
namespace transforms {

namespace {

using block_graph::BlockGraph;
using core::RelativeAddress;

class TestCoffRenameSymbolsTransform : public CoffRenameSymbolsTransform {
 public:
  typedef CoffRenameSymbolsTransform::SymbolMap SymbolMap;

  using CoffRenameSymbolsTransform::mappings_;
};

class CoffRenameSymbolsTransformTest : public testing::CoffUnitTest {
 public:
  virtual void SetUp() OVERRIDE {
    testing::CoffUnitTest::SetUp();
    ASSERT_NO_FATAL_FAILURE(DecomposeOriginal());
  }
};

const char kFunction1Name[] = "__imp_?function1@@YAHXZ";
const char kFunction2Name[] = "?function2@@YAHXZ";
const char kFunction3Name[] = "?function3@@YAHXZ";
const char kFunction4Name[] = "?function4@@YAHXZ";  // Does not exist.
const char kFoo[] = "foo";  // Does not exist, less than 8 characters.
const char kMemset[] = "_memset";  // Exists, and is multiply defined.

}  // namespace

std::ostream& operator<<(std::ostream& os,
                         const block_graph::BlockHash& hash) {
  os << "BlockHash(" << hash.md5_digest.a << ")";
  return os;
}

TEST_F(CoffRenameSymbolsTransformTest, ApplyMissingSymbolFails) {
  TestCoffRenameSymbolsTransform tx;
  EXPECT_TRUE(tx.mappings_.empty());

  TestCoffRenameSymbolsTransform::SymbolMap expected_mappings;
  expected_mappings.push_back(std::make_pair(kFunction4Name, kFunction1Name));

  tx.AddSymbolMapping(kFunction4Name, kFunction1Name);
  EXPECT_THAT(tx.mappings_, testing::ContainerEq(expected_mappings));

  BlockGraph::Block* symbols_block;
  BlockGraph::Block* strings_block;
  ASSERT_TRUE(FindCoffSpecialBlocks(
      &block_graph_, NULL, &symbols_block, &strings_block));
  block_graph::BlockHash symbols_hash_before(symbols_block);
  block_graph::BlockHash strings_hash_before(strings_block);

  EXPECT_TRUE(tx.symbols_must_exist());
  EXPECT_FALSE(tx.TransformBlockGraph(&policy_, &block_graph_, headers_block_));

  // The block contents should not have changed.
  block_graph::BlockHash symbols_hash_after(symbols_block);
  block_graph::BlockHash strings_hash_after(strings_block);
  EXPECT_EQ(symbols_hash_before, symbols_hash_after);
  EXPECT_EQ(strings_hash_before, strings_hash_after);

  ASSERT_NO_FATAL_FAILURE(TestRoundTrip());
}

TEST_F(CoffRenameSymbolsTransformTest, ApplyMissingSymbolSucceeds) {
  TestCoffRenameSymbolsTransform tx;
  EXPECT_TRUE(tx.mappings_.empty());

  TestCoffRenameSymbolsTransform::SymbolMap expected_mappings;
  expected_mappings.push_back(std::make_pair(kFunction4Name, kFunction1Name));

  tx.AddSymbolMapping(kFunction4Name, kFunction1Name);
  EXPECT_THAT(tx.mappings_, testing::ContainerEq(expected_mappings));

  BlockGraph::Block* symbols_block;
  BlockGraph::Block* strings_block;
  ASSERT_TRUE(FindCoffSpecialBlocks(
      &block_graph_, NULL, &symbols_block, &strings_block));
  block_graph::BlockHash symbols_hash_before(symbols_block);
  block_graph::BlockHash strings_hash_before(strings_block);

  tx.set_symbols_must_exist(false);
  EXPECT_FALSE(tx.symbols_must_exist());
  EXPECT_TRUE(tx.TransformBlockGraph(&policy_, &block_graph_, headers_block_));

  // The block contents should not have changed.
  block_graph::BlockHash symbols_hash_after(symbols_block);
  block_graph::BlockHash strings_hash_after(strings_block);
  EXPECT_EQ(symbols_hash_before, symbols_hash_after);
  EXPECT_EQ(strings_hash_before, strings_hash_after);

  ASSERT_NO_FATAL_FAILURE(TestRoundTrip());
}

TEST_F(CoffRenameSymbolsTransformTest, ApplyExistingSymbols) {
  TestCoffRenameSymbolsTransform tx;
  EXPECT_TRUE(tx.mappings_.empty());

  TestCoffRenameSymbolsTransform::SymbolMap expected_mappings;
  expected_mappings.push_back(std::make_pair(kFunction1Name, kFunction2Name));

  tx.AddSymbolMapping(kFunction1Name, kFunction2Name);
  EXPECT_THAT(tx.mappings_, testing::ContainerEq(expected_mappings));

  BlockGraph::Block* symbols_block;
  BlockGraph::Block* strings_block;
  ASSERT_TRUE(FindCoffSpecialBlocks(
      &block_graph_, NULL, &symbols_block, &strings_block));
  size_t symbols_before = symbols_block->size();
  size_t strings_before = strings_block->size();

  EXPECT_TRUE(tx.symbols_must_exist());
  EXPECT_TRUE(tx.TransformBlockGraph(&policy_, &block_graph_, headers_block_));

  EXPECT_EQ(symbols_before, symbols_block->size());
  EXPECT_EQ(strings_before, strings_block->size());

  ASSERT_NO_FATAL_FAILURE(TestRoundTrip());
}

TEST_F(CoffRenameSymbolsTransformTest, ApplyMultiplyDefinedSource) {
  TestCoffRenameSymbolsTransform tx;
  EXPECT_TRUE(tx.mappings_.empty());

  TestCoffRenameSymbolsTransform::SymbolMap expected_mappings;
  expected_mappings.push_back(std::make_pair(kMemset, kFunction2Name));

  tx.AddSymbolMapping(kMemset, kFunction2Name);
  EXPECT_THAT(tx.mappings_, testing::ContainerEq(expected_mappings));

  BlockGraph::Block* symbols_block;
  BlockGraph::Block* strings_block;
  ASSERT_TRUE(FindCoffSpecialBlocks(
      &block_graph_, NULL, &symbols_block, &strings_block));
  size_t symbols_before = symbols_block->size();
  size_t strings_before = strings_block->size();

  EXPECT_TRUE(tx.symbols_must_exist());
  EXPECT_TRUE(tx.TransformBlockGraph(&policy_, &block_graph_, headers_block_));

  EXPECT_EQ(symbols_before, symbols_block->size());
  EXPECT_EQ(strings_before, strings_block->size());

  ASSERT_NO_FATAL_FAILURE(TestRoundTrip());
}

TEST_F(CoffRenameSymbolsTransformTest, ApplyMultiplyDefinedDestination) {
  TestCoffRenameSymbolsTransform tx;
  EXPECT_TRUE(tx.mappings_.empty());

  TestCoffRenameSymbolsTransform::SymbolMap expected_mappings;
  expected_mappings.push_back(std::make_pair(kFunction2Name, kMemset));

  tx.AddSymbolMapping(kFunction2Name, kMemset);
  EXPECT_THAT(tx.mappings_, testing::ContainerEq(expected_mappings));

  BlockGraph::Block* symbols_block;
  BlockGraph::Block* strings_block;
  ASSERT_TRUE(FindCoffSpecialBlocks(
      &block_graph_, NULL, &symbols_block, &strings_block));
  size_t symbols_before = symbols_block->size();
  size_t strings_before = strings_block->size();

  EXPECT_TRUE(tx.symbols_must_exist());
  EXPECT_TRUE(tx.TransformBlockGraph(&policy_, &block_graph_, headers_block_));

  EXPECT_EQ(symbols_before, symbols_block->size());
  EXPECT_EQ(strings_before, strings_block->size());

  ASSERT_NO_FATAL_FAILURE(TestRoundTrip());
}

TEST_F(CoffRenameSymbolsTransformTest, ApplyNewSymbolLong) {
  TestCoffRenameSymbolsTransform tx;
  EXPECT_TRUE(tx.mappings_.empty());

  TestCoffRenameSymbolsTransform::SymbolMap expected_mappings;
  expected_mappings.push_back(std::make_pair(kFunction3Name, kFunction4Name));

  tx.AddSymbolMapping(kFunction3Name, kFunction4Name);
  EXPECT_THAT(tx.mappings_, testing::ContainerEq(expected_mappings));

  BlockGraph::Block* symbols_block;
  BlockGraph::Block* strings_block;
  ASSERT_TRUE(FindCoffSpecialBlocks(
      &block_graph_, NULL, &symbols_block, &strings_block));
  size_t symbols_before = symbols_block->size();
  size_t strings_before = strings_block->size();

  EXPECT_TRUE(tx.symbols_must_exist());
  EXPECT_TRUE(tx.TransformBlockGraph(&policy_, &block_graph_, headers_block_));

  // Expect only one symbol to have been created, and a corresponding string.
  EXPECT_EQ(symbols_before + sizeof(IMAGE_SYMBOL), symbols_block->size());
  EXPECT_EQ(strings_before + ::strlen(kFunction4Name) + 1,
            strings_block->size());

  ASSERT_NO_FATAL_FAILURE(TestRoundTrip());
}

TEST_F(CoffRenameSymbolsTransformTest, ApplyNewSymbolShort) {
  TestCoffRenameSymbolsTransform tx;
  EXPECT_TRUE(tx.mappings_.empty());

  TestCoffRenameSymbolsTransform::SymbolMap expected_mappings;
  expected_mappings.push_back(std::make_pair(kFunction1Name, kFoo));

  tx.AddSymbolMapping(kFunction1Name, kFoo);
  EXPECT_THAT(tx.mappings_, testing::ContainerEq(expected_mappings));

  BlockGraph::Block* symbols_block;
  BlockGraph::Block* strings_block;
  ASSERT_TRUE(FindCoffSpecialBlocks(
      &block_graph_, NULL, &symbols_block, &strings_block));
  size_t symbols_before = symbols_block->size();
  size_t strings_before = strings_block->size();

  EXPECT_TRUE(tx.symbols_must_exist());
  EXPECT_TRUE(tx.TransformBlockGraph(&policy_, &block_graph_, headers_block_));

  // Expect only one symbol to have been created, but no new string.
  EXPECT_EQ(symbols_before + sizeof(IMAGE_SYMBOL), symbols_block->size());
  EXPECT_EQ(strings_before, strings_block->size());

  ASSERT_NO_FATAL_FAILURE(TestRoundTrip());
}

}  // namespace transforms
}  // namespace pe
