// Copyright 2014 Google Inc. All Rights Reserved.
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

#include "syzygy/pe/coff_utils.h"

#include "base/bind.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/pe/unittest_util.h"

namespace pe {

namespace {

using block_graph::BlockGraph;
using testing::_;
using testing::Return;

static const char kFunction2[] = "?function2@@YAHXZ";
static const char kDebugS[] = ".debug$S";

class LenientCoffUtilsTest : public testing::CoffUnitTest {
 public:
  MOCK_METHOD3(VisitCoffSymbol, bool(BlockGraph::Block*,
                                     BlockGraph::Block*,
                                     BlockGraph::Offset));
};
typedef testing::StrictMock<LenientCoffUtilsTest> CoffUtilsTest;

typedef std::set<std::string> StringSet;
bool VisitCoffSymbolAndGrabName(StringSet* names,
                                BlockGraph::Block* symbols_block,
                                BlockGraph::Block* strings_block,
                                BlockGraph::Offset symbol_offset) {
  DCHECK_NE(reinterpret_cast<StringSet*>(NULL), names);
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), symbols_block);
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), strings_block);

  base::StringPiece name;
  EXPECT_TRUE(GetCoffSymbolName(symbols_block, strings_block, symbol_offset,
                                &name));
  EXPECT_FALSE(name.empty());
  names->insert(name.as_string());
  return true;
}

}  // namespace

TEST_F(CoffUtilsTest, FindCoffSpecialBlocks) {
  BlockGraph::Block* actual_headers_block = NULL;
  BlockGraph::Block* actual_symbols_block = NULL;
  BlockGraph::Block* actual_strings_block = NULL;

  BlockGraph::Block* headers_block =
      block_graph_.AddBlock(
          BlockGraph::DATA_BLOCK,
          sizeof(IMAGE_FILE_HEADER) + 12 * sizeof(IMAGE_SECTION_HEADER),
          "COFF Headers");
  ASSERT_TRUE(headers_block != NULL);
  headers_block->set_attribute(BlockGraph::COFF_HEADERS);

  // FindCoffSpecialBlocks() should fail even if we don't request the other
  // special blocks.
  EXPECT_FALSE(FindCoffSpecialBlocks(&block_graph_,
                                     &actual_headers_block,
                                     &actual_symbols_block,
                                     &actual_strings_block));
  EXPECT_FALSE(FindCoffSpecialBlocks(&block_graph_,
                                     &actual_headers_block, NULL, NULL));

  BlockGraph::Block* symbols_block =
      block_graph_.AddBlock(BlockGraph::DATA_BLOCK,
                            30 * sizeof(IMAGE_SYMBOL),
                            "COFF Symbol Table");
  ASSERT_TRUE(symbols_block != NULL);
  symbols_block->set_attribute(BlockGraph::COFF_SYMBOL_TABLE);

  EXPECT_FALSE(FindCoffSpecialBlocks(&block_graph_,
                                     &actual_headers_block,
                                     &actual_symbols_block,
                                     &actual_strings_block));
  EXPECT_FALSE(FindCoffSpecialBlocks(&block_graph_,
                                     &actual_headers_block,
                                     &actual_symbols_block,
                                     NULL));

  BlockGraph::Block* strings_block =
      block_graph_.AddBlock(BlockGraph::DATA_BLOCK, 242, "COFF String Table");
  ASSERT_TRUE(strings_block != NULL);
  strings_block->set_attribute(BlockGraph::COFF_STRING_TABLE);

  EXPECT_TRUE(FindCoffSpecialBlocks(&block_graph_,
                                    &actual_headers_block,
                                    &actual_symbols_block,
                                    &actual_strings_block));
  EXPECT_EQ(headers_block, actual_headers_block);
  EXPECT_EQ(symbols_block, actual_symbols_block);
  EXPECT_EQ(strings_block, actual_strings_block);
}

TEST_F(CoffUtilsTest, VisitCoffSymbols) {
  ASSERT_NO_FATAL_FAILURE(DecomposeOriginal());

  BlockGraph::Block* symbols_block = NULL;
  BlockGraph::Block* strings_block = NULL;
  ASSERT_TRUE(FindCoffSpecialBlocks(&block_graph_,
                                    NULL,
                                    &symbols_block,
                                    &strings_block));

  VisitCoffSymbolCallback callback = base::Bind(
      &CoffUtilsTest::VisitCoffSymbol, base::Unretained(this));

  // Expect the visitor to fail if the callback does.
  EXPECT_CALL(*this, VisitCoffSymbol(symbols_block,
                                     strings_block,
                                     _)).WillOnce(Return(false));
  EXPECT_FALSE(VisitCoffSymbols(callback, &block_graph_));

  // Now expect the visitor to succeed.
  EXPECT_CALL(*this, VisitCoffSymbol(symbols_block,
                                     strings_block,
                                     _)).
      WillRepeatedly(Return(true));
  EXPECT_TRUE(VisitCoffSymbols(callback, &block_graph_));
}

TEST_F(CoffUtilsTest, GetCoffSymbolName) {
  ASSERT_NO_FATAL_FAILURE(DecomposeOriginal());

  StringSet names;
  VisitCoffSymbolCallback callback = base::Bind(
      &VisitCoffSymbolAndGrabName, base::Unretained(&names));

  EXPECT_TRUE(VisitCoffSymbols(callback, &block_graph_));
  EXPECT_FALSE(names.empty());
}

TEST_F(CoffUtilsTest, FindCoffSymbolInvalid) {
  ASSERT_NO_FATAL_FAILURE(DecomposeOriginal());

  BlockGraph::Offset offset = 0;
  EXPECT_TRUE(FindCoffSymbol("_foo_bar_baz", &block_graph_, &offset));
  EXPECT_EQ(kInvalidCoffSymbol, offset);
}

TEST_F(CoffUtilsTest, FindCoffSymbolDuplicate) {
  ASSERT_NO_FATAL_FAILURE(DecomposeOriginal());

  BlockGraph::Offset offset = 0;
  EXPECT_TRUE(FindCoffSymbol(kDebugS, &block_graph_, &offset));
  EXPECT_EQ(kDuplicateCoffSymbol, offset);
}

TEST_F(CoffUtilsTest, FindCoffSymbolSucceeds) {
  ASSERT_NO_FATAL_FAILURE(DecomposeOriginal());

  BlockGraph::Offset offset = kInvalidCoffSymbol;
  EXPECT_TRUE(FindCoffSymbol(kFunction2, &block_graph_, &offset));
  EXPECT_LE(0, offset);
}

TEST_F(CoffUtilsTest, BuildCoffSymbolNameOffsetMap) {
  ASSERT_NO_FATAL_FAILURE(DecomposeOriginal());

  CoffSymbolNameOffsetMap map;
  EXPECT_TRUE(BuildCoffSymbolNameOffsetMap(&block_graph_, &map));

  EXPECT_FALSE(map.empty());
  CoffSymbolNameOffsetMap::const_iterator it = map.find(kFunction2);
  ASSERT_TRUE(it != map.end());
  EXPECT_LE(0, it->second);

  it = map.find(kDebugS);
  ASSERT_TRUE(it != map.end());
  EXPECT_EQ(kDuplicateCoffSymbol, it->second);
}

}  // namespace pe
