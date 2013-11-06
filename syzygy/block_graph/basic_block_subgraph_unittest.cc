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
//
// Tests for BasicBlockSubGraph.

#include "syzygy/block_graph/basic_block_subgraph.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/block_graph/basic_block.h"
#include "syzygy/block_graph/basic_block_assembler.h"
#include "syzygy/block_graph/block_graph.h"
#include "syzygy/core/assembler.h"

namespace block_graph {

namespace {

using block_graph::BasicBlock;
using block_graph::BasicBlockReference;
using block_graph::BasicBlockReferrer;
using block_graph::BlockGraph;
using block_graph::Instruction;
using block_graph::Successor;

typedef BasicBlockSubGraph::BlockDescription BlockDescription;
typedef BlockGraph::Reference Reference;

// Some handy constants.
const size_t kDataSize = 32;
const uint8 kData[kDataSize] = {0};

// A derived class to expose protected members for unit-testing.
class TestBasicBlockSubGraph : public BasicBlockSubGraph {
 public:
  using BasicBlockSubGraph::HasValidReferrers;
  using BasicBlockSubGraph::HasValidSuccessors;
  using BasicBlockSubGraph::MapsBasicBlocksToAtMostOneDescription;
};

}  // namespace

TEST(BasicBlockSubGraphTest, AddBasicBlock) {
  BlockGraph block_graph;
  BlockGraph::Block* block =
      block_graph.AddBlock(BlockGraph::CODE_BLOCK, 0, "dummy");
  BasicBlockSubGraph subgraph;
  subgraph.set_original_block(block);
  block->set_size(kDataSize);
  block->SetData(kData, kDataSize);

  // Add a basic data block.
  BasicDataBlock* bb1 = subgraph.AddBasicDataBlock("bb1", kDataSize, kData);
  EXPECT_EQ(0U, bb1->id());
  ASSERT_FALSE(bb1 == NULL);
  ASSERT_EQ(bb1, BasicDataBlock::Cast(bb1));
  ASSERT_TRUE(BasicCodeBlock::Cast(bb1) == NULL);
  EXPECT_EQ("bb1", bb1->name());
  EXPECT_EQ(BasicBlock::BASIC_DATA_BLOCK, bb1->type());
  EXPECT_EQ(kDataSize, bb1->size());
  EXPECT_EQ(kData, bb1->data());
  EXPECT_EQ(BasicBlock::kNoOffset, bb1->offset());

  // Add one that overlaps.
  BasicDataBlock* bb2 =
      subgraph.AddBasicDataBlock("bb2", kDataSize / 2, kData + kDataSize / 2);
  EXPECT_EQ(1U, bb2->id());
  ASSERT_FALSE(bb1 == NULL);
  ASSERT_EQ(bb2, BasicDataBlock::Cast(bb2));
  ASSERT_TRUE(BasicCodeBlock::Cast(bb2) == NULL);
  EXPECT_EQ("bb2", bb2->name());
  EXPECT_EQ(BasicBlock::BASIC_DATA_BLOCK, bb2->type());
  EXPECT_EQ(kDataSize / 2, bb2->size());
  EXPECT_EQ(kData + kDataSize / 2, bb2->data());
  EXPECT_EQ(BasicBlock::kNoOffset, bb2->offset());

  // Add a code block.
  BasicCodeBlock* bb3 = subgraph.AddBasicCodeBlock("bb3");
  EXPECT_EQ(2U, bb3->id());
  ASSERT_FALSE(bb3 == NULL);
  ASSERT_EQ(bb3, BasicCodeBlock::Cast(bb3));
  EXPECT_EQ("bb3", bb3->name());
  ASSERT_TRUE(BasicDataBlock::Cast(bb3) == NULL);

  // And they were not the same basic-block.
  ASSERT_NE(bb1, bb2);
  ASSERT_NE(implicit_cast<BasicBlock*>(bb1), bb3);
  ASSERT_NE(implicit_cast<BasicBlock*>(bb2), bb3);

  // Check BBCollection ordering.
  const BasicBlockSubGraph::BBCollection& blocks = subgraph.basic_blocks();
  BasicBlockSubGraph::BBCollection::const_iterator it = blocks.begin();
  BasicBlockSubGraph::BlockId current_id = (*it)->id();
  ++it;
  for (; it != blocks.end(); ++ it) {
    EXPECT_LT(current_id, (*it)->id());
    current_id = (*it)->id();
  }
}

TEST(BasicBlockSubGraphTest, AddBlockDescription) {
  TestBasicBlockSubGraph subgraph;
  BlockDescription* b1 = subgraph.AddBlockDescription(
      "b1", "b1.obj", BlockGraph::CODE_BLOCK, 7, 2, 42);
  ASSERT_FALSE(b1 == NULL);
  EXPECT_EQ("b1", b1->name);
  EXPECT_EQ(BlockGraph::CODE_BLOCK, b1->type);
  EXPECT_EQ(7, b1->section);
  EXPECT_EQ(2, b1->alignment);
  EXPECT_EQ(42, b1->attributes);
  EXPECT_TRUE(b1->basic_block_order.empty());
}

TEST(BasicBlockSubGraphTest, MapsBasicBlocksToAtMostOneDescription) {
  TestBasicBlockSubGraph subgraph;
  uint8 data[32] = {0};

  // Add three basic code blocks.
  BasicBlock* bb1 = subgraph.AddBasicCodeBlock("bb1");
  ASSERT_FALSE(bb1 == NULL);
  BasicBlock* bb2 = subgraph.AddBasicCodeBlock("bb2");
  ASSERT_FALSE(bb2 == NULL);
  BasicBlock* bb3 = subgraph.AddBasicCodeBlock("bb3");
  ASSERT_FALSE(bb3 == NULL);

  // They should all be different blocks.
  ASSERT_FALSE(bb1 == bb2);
  ASSERT_FALSE(bb2 == bb3);
  ASSERT_FALSE(bb1 == bb3);

  // Add a block description for a mythical b1.
  BlockDescription* b1 = subgraph.AddBlockDescription(
      "b1", "b1.obj", BlockGraph::CODE_BLOCK, 0, 1, 0);
  ASSERT_FALSE(b1 == NULL);

  // Add a block description for a mythical b2.
  BlockDescription* b2 = subgraph.AddBlockDescription(
      "b2", "b2.obj", BlockGraph::CODE_BLOCK, 0, 1, 0);
  ASSERT_FALSE(b2 == NULL);

  // There are no blocks assigned twice (bb1 and bb2 are in separate blocks).
  ASSERT_TRUE(subgraph.MapsBasicBlocksToAtMostOneDescription());

  // Adding bb3 to b1 is still valid.
  b1->basic_block_order.push_back(bb3);
  ASSERT_TRUE(subgraph.MapsBasicBlocksToAtMostOneDescription());

  // But adding bb3 to b2, as well, is no longer valid.
  b2->basic_block_order.push_back(bb3);
  ASSERT_FALSE(subgraph.MapsBasicBlocksToAtMostOneDescription());
}

TEST(BasicBlockSubGraphTest, GetReachabilityMap) {
  BlockGraph block_graph;
  BlockGraph::Block* external_block =
      block_graph.AddBlock(BlockGraph::CODE_BLOCK, 0, "dummy");
  BasicBlockSubGraph subgraph;
  static const uint8 kData[Reference::kMaximumSize] = { 0 };

  // Create basic-blocks.
  BasicCodeBlock* bb1 = subgraph.AddBasicCodeBlock("bb1");
  ASSERT_FALSE(bb1 == NULL);
  BasicCodeBlock* bb2 = subgraph.AddBasicCodeBlock("bb2");
  ASSERT_FALSE(bb2 == NULL);
  BasicCodeBlock* bb3 = subgraph.AddBasicCodeBlock("bb3");
  ASSERT_FALSE(bb3 == NULL);
  BasicCodeBlock* bb4 = subgraph.AddBasicCodeBlock("bb4");
  ASSERT_FALSE(bb4 == NULL);
  BasicDataBlock* data = subgraph.AddBasicDataBlock(
      "data", sizeof(kData), kData);
  ASSERT_FALSE(data == NULL);

  // Setup references.
  static const uint8 kJmp[] = { 0xFF, 0x24, 0x8D, 0xCA, 0xFE, 0xBA, 0xBE };
  static const uint8 kRet[] = { 0xC3 };
  Instruction jmp;
  ASSERT_TRUE(Instruction::FromBuffer(kJmp, sizeof(kJmp), &jmp));
  Instruction ret;
  ASSERT_TRUE(Instruction::FromBuffer(kRet, sizeof(kRet), &ret));
  bb1->referrers().insert(BasicBlockReferrer(external_block, 0));
  bb1->instructions().push_back(jmp);
  bb1->instructions().back().SetReference(
      3, BasicBlockReference(BlockGraph::RELATIVE_REF,
                             BlockGraph::Reference::kMaximumSize,
                             data));
  data->SetReference(0, BasicBlockReference(BlockGraph::RELATIVE_REF,
                                            BlockGraph::Reference::kMaximumSize,
                                            bb2));
  bb2->successors().push_back(
      Successor(Successor::kConditionTrue,
                BasicBlockReference(BlockGraph::RELATIVE_REF,
                                    BlockGraph::Reference::kMaximumSize,
                                    bb3),
                0));
  bb3->instructions().push_back(ret);

  // Check reachability.
  BasicBlockSubGraph::ReachabilityMap expected_rm;
  expected_rm.insert(std::make_pair(bb1, true));
  expected_rm.insert(std::make_pair(bb2, true));
  expected_rm.insert(std::make_pair(bb3, true));
  expected_rm.insert(std::make_pair(bb4, false));
  expected_rm.insert(std::make_pair(data, true));

  BasicBlockSubGraph::ReachabilityMap actual_rm;
  subgraph.GetReachabilityMap(&actual_rm);
  EXPECT_THAT(actual_rm, testing::ContainerEq(expected_rm));
}

TEST(BasicBlockSubGraphTest, HasValidSuccessors) {
  BlockGraph block_graph;
  BlockGraph::Block* external_block =
      block_graph.AddBlock(BlockGraph::CODE_BLOCK, 0, "dummy");
  TestBasicBlockSubGraph subgraph;

  BasicCodeBlock* bb1 = subgraph.AddBasicCodeBlock("bb1");
  ASSERT_FALSE(bb1 == NULL);
  bb1->referrers().insert(BasicBlockReferrer(external_block, 0));

  BasicCodeBlock* bb2 = subgraph.AddBasicCodeBlock("bb2");
  ASSERT_FALSE(bb2 == NULL);

  // Add a block description for a mythical b1.
  BlockDescription* b1 = subgraph.AddBlockDescription(
      "b1", "b1.obj", BlockGraph::CODE_BLOCK, 0, 1, 0);
  ASSERT_FALSE(b1 == NULL);
  b1->basic_block_order.push_back(bb1);

  // Add a block description for a mythical b2.
  BlockDescription* b2 = subgraph.AddBlockDescription(
      "b2", "b2.obj", BlockGraph::CODE_BLOCK, 0, 1, 0);
  ASSERT_FALSE(b2 == NULL);
  b2->basic_block_order.push_back(bb2);

  // Successors are not valid yet.
  EXPECT_FALSE(subgraph.HasValidSuccessors());

  // Add an unconditional succession from bb1 to bb2.
  bb1->successors().push_back(
      Successor(Successor::kConditionTrue,
                BasicBlockReference(BlockGraph::RELATIVE_REF, 4, bb2),
                0));

  // Successors are still not valid.
  EXPECT_FALSE(subgraph.HasValidSuccessors());

  // Add half of a conditional succession from bb2 to bb1.
  bb2->successors().push_back(
      Successor(Successor::kConditionAbove,
                BasicBlockReference(BlockGraph::RELATIVE_REF, 4, bb1),
                0));

  // Successors are still not valid.
  EXPECT_FALSE(subgraph.HasValidSuccessors());

  // Add second conditional succession from bb2 to bb1, but not the inverse
  // of the first condition.
  bb2->successors().push_back(
      Successor(Successor::kConditionAboveOrEqual,
                BasicBlockReference(BlockGraph::RELATIVE_REF, 4, bb1),
                0));

  // Successors are still not valid because the conditions are not inverses.
  EXPECT_FALSE(subgraph.HasValidSuccessors());

  // Remove the bad successor and add a correct secondary successor.
  bb2->successors().pop_back();
  bb2->successors().push_back(
      Successor(Successor::kConditionBelowOrEqual,
                BasicBlockReference(BlockGraph::RELATIVE_REF, 4, bb1),
                0));

  // Successors are now valid.
  EXPECT_TRUE(subgraph.HasValidSuccessors());
}

TEST(BasicBlockSubGraphTest, HasValidReferrers) {
  BlockGraph block_graph;
  BlockGraph::Block* b1 = block_graph.AddBlock(BlockGraph::DATA_BLOCK, 4, "b1");
  BlockGraph::Block* b2 = block_graph.AddBlock(BlockGraph::DATA_BLOCK, 4, "b2");

  Reference ref(BlockGraph::ABSOLUTE_REF, 4, b1, 0, 0);
  ASSERT_TRUE(b2->SetReference(0, ref));
  ASSERT_FALSE(b1->referrers().empty());

  TestBasicBlockSubGraph subgraph;
  subgraph.set_original_block(b1);

  ASSERT_FALSE(subgraph.HasValidReferrers());

  BasicDataBlock* bb1 = subgraph.AddBasicDataBlock("bb1", kDataSize, kData);
  ASSERT_FALSE(bb1 == NULL);

  BlockDescription* b1_desc = subgraph.AddBlockDescription(
      "b1_desc", "b1_desc.obj", BlockGraph::DATA_BLOCK, 0, 1, 0);
  ASSERT_FALSE(b1_desc == NULL);
  b1_desc->basic_block_order.push_back(bb1);

  ASSERT_FALSE(subgraph.HasValidReferrers());

  bb1->referrers().insert(BasicBlockReferrer(b2, 0));
  ASSERT_TRUE(subgraph.HasValidReferrers());
}

TEST(BasicBlockSubGraphTest, ToString) {
  BlockGraph block_graph;
  BlockGraph::Block* block =
      block_graph.AddBlock(BlockGraph::CODE_BLOCK, 0, "dummy");
  BasicBlockSubGraph subgraph;
  subgraph.set_original_block(block);

  BlockDescription* b1 = subgraph.AddBlockDescription(
      "b1", "b1.obj", BlockGraph::CODE_BLOCK, 7, 2, 42);

  BasicCodeBlock* bb = subgraph.AddBasicCodeBlock("BB");
  b1->basic_block_order.push_back(bb);
  BasicBlockAssembler assm(bb->instructions().begin(), &bb->instructions());
  assm.ret();

  std::string result;
  bool valid = subgraph.ToString(&result);
  EXPECT_TRUE(valid);
  EXPECT_FALSE(result.empty());
}

}  // namespace block_graph
