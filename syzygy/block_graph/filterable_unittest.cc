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

#include "syzygy/block_graph/filterable.h"

#include "gtest/gtest.h"
#include "syzygy/assm/unittest_util.h"
#include "syzygy/block_graph/basic_block_subgraph.h"

namespace block_graph {

namespace {

typedef core::RelativeAddress RelativeAddress;
typedef RelativeAddressFilter::Range Range;

}  // namespace

TEST(FilterableTest, DefaultConstructor) {
  Filterable f;
  EXPECT_TRUE(f.filter() == NULL);
}

TEST(FilterableTest, ConstructorWithFilter) {
  RelativeAddressFilter raf;
  Filterable f(&raf);
  EXPECT_EQ(&raf, f.filter());
}

TEST(FilterableTest, Accessors)  {
  Filterable f;

  RelativeAddressFilter raf;
  f.set_filter(&raf);
  EXPECT_EQ(&raf, f.filter());

  f.set_filter(NULL);
  EXPECT_TRUE(f.filter() == NULL);
}

TEST(FilterableTest, IsFiltered) {
  Filterable f;

  const uint8_t data[10] = {};

  BlockGraph block_graph;
  BasicBlockSubGraph subgraph;

  // Create some dummy blocks, etc. Initially they have no source ranges so
  // should all pass as instrumentable.
  BlockGraph::Block* block =
      block_graph.AddBlock(BlockGraph::CODE_BLOCK, 10, "block");
  Instruction inst;
  EXPECT_TRUE(Instruction::FromBuffer(testing::kNop1,
                                      arraysize(testing::kNop1), &inst));
  BasicCodeBlock* code_bb = subgraph.AddBasicCodeBlock("code_bb");
  code_bb->instructions().push_back(inst);
  BasicDataBlock* data_bb =
      subgraph.AddBasicDataBlock("data_bb", arraysize(data), data);
  BasicBlock* code_bb_ptr = code_bb;
  BasicBlock* data_bb_ptr = data_bb;

  // We expect nothing to be filtered because there is none.
  EXPECT_FALSE(f.IsFiltered(block));
  EXPECT_FALSE(f.IsFiltered(code_bb));
  EXPECT_FALSE(f.IsFiltered(data_bb));
  EXPECT_FALSE(f.IsFiltered(code_bb_ptr));
  EXPECT_FALSE(f.IsFiltered(data_bb_ptr));
  EXPECT_FALSE(f.IsFiltered(inst));

  // Create a filter and pass it to the Filterable object.
  RelativeAddressFilter raf(Range(RelativeAddress(0), 100));
  raf.Mark(Range(RelativeAddress(10), 10));
  f.set_filter(&raf);

  // Give all of the test data source ranges, but that don't conflict with
  // any of the ranges in the filter.
  EXPECT_TRUE(block->source_ranges().Push(
        BlockGraph::Block::SourceRanges::SourceRange(0, 10),
        BlockGraph::Block::SourceRanges::DestinationRange(
            RelativeAddress(35), 10)));
  inst.set_source_range(
      Range(RelativeAddress(32), arraysize(testing::kNop1)));
  code_bb->instructions().begin()->set_source_range(
      Range(RelativeAddress(38), arraysize(testing::kNop1)));
  data_bb->set_source_range(Range(RelativeAddress(29), arraysize(data)));

  // We expect nothing to be filtered.
  EXPECT_FALSE(f.IsFiltered(block));
  EXPECT_FALSE(f.IsFiltered(code_bb));
  EXPECT_FALSE(f.IsFiltered(data_bb));
  EXPECT_FALSE(f.IsFiltered(code_bb_ptr));
  EXPECT_FALSE(f.IsFiltered(data_bb_ptr));
  EXPECT_FALSE(f.IsFiltered(inst));

  // Now mark a conflicting range in the filter.
  raf.Mark(Range(RelativeAddress(30), 10));

  // We expect everything to be filtered.
  EXPECT_TRUE(f.IsFiltered(block));
  EXPECT_TRUE(f.IsFiltered(code_bb));
  EXPECT_TRUE(f.IsFiltered(data_bb));
  EXPECT_TRUE(f.IsFiltered(code_bb_ptr));
  EXPECT_TRUE(f.IsFiltered(data_bb_ptr));
  EXPECT_TRUE(f.IsFiltered(inst));
}

}  // namespace block_graph
