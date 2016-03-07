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

#include "syzygy/block_graph/filter_util.h"

#include "gtest/gtest.h"
#include "syzygy/assm/unittest_util.h"
#include "syzygy/block_graph/basic_block_subgraph.h"

namespace block_graph {

namespace {

typedef core::RelativeAddress RelativeAddress;
typedef RelativeAddressFilter::Range Range;

}  // namespace

TEST(FilterUtilTest, IsFiltered) {
  const uint8_t data[10] = {};

  // Create some dummy blocks, etc. Initially they have no source ranges so
  // should all pass as instrumentable.
  BlockGraph block_graph;
  BasicBlockSubGraph subgraph;
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

  // Create a filter.
  RelativeAddressFilter f(Range(RelativeAddress(0), 100));
  f.Mark(Range(RelativeAddress(10), 10));

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
  EXPECT_FALSE(IsFiltered(f, block));
  EXPECT_FALSE(IsFiltered(f, code_bb));
  EXPECT_FALSE(IsFiltered(f, data_bb));
  EXPECT_FALSE(IsFiltered(f, code_bb_ptr));
  EXPECT_FALSE(IsFiltered(f, data_bb_ptr));
  EXPECT_FALSE(IsFiltered(f, inst));

  // Now mark a conflicting range in the filter.
  f.Mark(Range(RelativeAddress(30), 10));

  // We expect everything to be filtered.
  EXPECT_TRUE(IsFiltered(f, block));
  EXPECT_TRUE(IsFiltered(f, code_bb));
  EXPECT_TRUE(IsFiltered(f, data_bb));
  EXPECT_TRUE(IsFiltered(f, code_bb_ptr));
  EXPECT_TRUE(IsFiltered(f, data_bb_ptr));
  EXPECT_TRUE(IsFiltered(f, inst));
}

}  // namespace block_graph
