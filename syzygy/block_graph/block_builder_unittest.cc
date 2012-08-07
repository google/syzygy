// Copyright 2012 Google Inc.
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
// Tests for the basic block classes.

#include "syzygy/block_graph/block_builder.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/block_graph/basic_block.h"
#include "syzygy/block_graph/basic_block_subgraph.h"
#include "syzygy/block_graph/block_graph.h"

namespace block_graph {

namespace {

typedef BlockGraph::Block Block;
typedef BlockGraph::Label Label;
typedef BlockGraph::Reference Reference;
typedef Block::Referrer Referrer;

static const uint8 kEmptyData[32] = {0};

Instruction* AddInstruction(BasicBlock* bb, Instruction::Size size) {
  CHECK(bb != NULL);
  bb->instructions().push_back(
      Instruction(Instruction::Representation(), -1, size, kEmptyData));
  return &bb->instructions().back();
}

}  // namespace

// This test constructs the following subgraph then merges it into block graph.
//
// +-------+
// | Data  |
// +---+---+
//     |
//     +-->  +---------+
// bb1   0   | 5 bytes |  Ref: 4-byte ref to data block @ 1, Label1 (code+call)
//           +---------+
//           | 6 bytes |  Successor: 4-byte ref to bb1 @ 7
//           +---------+
//           | 5 bytes |  Successor: 4-byte ref to bb3 @ 11
//           +---------+
// bb2   16  | 2 bytes |  Label2 (code)
//           +---------+
//           | 3 bytes |
//           +---------+
// bb3   21  | 2 bytes |  Label3 (code).
//           +---------+
//           | 1 bytes |
//           +---------+  Successor: elided here. Label4
// bb4   24  | 7 bytes |
//           +---------+
//           | 9 bytes |
//           +---------+
//           | 5 bytes |  Successor: 4-byte ref to bb2 @ 11
// data  45  +---------+  Label5 (data).
//           | 4 bytes |  Ref: 4-byte ref to bb1 @ 45
//           +---------+
//           | 4 bytes |  Ref: 4-byte ref to bb2 @ 49
//           +---------+
//           | 4 bytes |  Ref: 4-byte ref to bb3 @ 53
//       57  +---------+
//
TEST(BlockBuilderTest, Merge) {
  BlockGraph bg;

  // Setup a code block which is referenced from a data block.
  BlockGraph::Block* original =
      bg.AddBlock(BlockGraph::CODE_BLOCK, 32, "original");
  ASSERT_TRUE(original != NULL);
  BlockGraph::BlockId original_id = original->id();
  BlockGraph::Block* other =
      bg.AddBlock(BlockGraph::DATA_BLOCK, 4, "other");
  ASSERT_TRUE(other != NULL);
  BlockGraph::BlockId other_id = other->id();
  ASSERT_TRUE(other->SetReference(
      0, BlockGraph::Reference(BlockGraph::ABSOLUTE_REF, 4, original, 0, 0)));

  // Verify some expectations.
  ASSERT_EQ(2, bg.blocks().size());
  ASSERT_EQ(1, original->referrers().size());

  // Generate a mock decomposition of the original block.
  BasicBlockSubGraph subgraph;
  subgraph.set_original_block(original);
  BasicBlock* bb1 = subgraph.AddBasicBlock(
      "bb1", BasicBlock::BASIC_CODE_BLOCK, -1, 0, NULL);
  ASSERT_TRUE(bb1 != NULL);
  BasicBlock* bb2 = subgraph.AddBasicBlock(
      "bb2", BasicBlock::BASIC_CODE_BLOCK, -1, 0, NULL);
  ASSERT_TRUE(bb2 != NULL);
  BasicBlock* bb3 = subgraph.AddBasicBlock(
      "bb3", BasicBlock::BASIC_CODE_BLOCK, -1, 0, NULL);
  ASSERT_TRUE(bb3 != NULL);
  BasicBlock* bb4 = subgraph.AddBasicBlock(
      "bb4", BasicBlock::BASIC_CODE_BLOCK, -1, 0, NULL);
  ASSERT_TRUE(bb4 != NULL);
  BasicBlock* table = subgraph.AddBasicBlock(
      "table", BasicBlock::BASIC_DATA_BLOCK, -1, 12, kEmptyData);
  ASSERT_TRUE(table != NULL);

  // Flesh out bb1 with an instruction having a reference and 2 successors.
  Instruction* inst = AddInstruction(bb1, 5);
  Label label_1("1", BlockGraph::CODE_LABEL | BlockGraph::CALL_SITE_LABEL);
  inst->set_label(label_1);
  ASSERT_TRUE(inst != NULL);
  ASSERT_TRUE(inst->references().insert(
      std::make_pair(1, BasicBlockReference(BlockGraph::ABSOLUTE_REF, 4,
                                            other, 0, 0))).second);
  bb1->successors().push_back(
      Successor(Successor::kConditionEqual,
                BasicBlockReference(BlockGraph::RELATIVE_REF, 4, bb1),
                -1, 0));
  bb1->successors().push_back(
      Successor(Successor::kConditionNotEqual,
                BasicBlockReference(BlockGraph::RELATIVE_REF, 4, bb3),
                -1, 0));
  ASSERT_TRUE(bb1->referrers().insert(BasicBlockReferrer(other, 0)).second);

  // Flesh out bb2 with some instructions and no successor.
  inst = AddInstruction(bb2, 2);
  Label label_2("2", BlockGraph::CODE_LABEL);
  inst->set_label(label_2);
  ASSERT_TRUE(inst != NULL);
  ASSERT_TRUE(AddInstruction(bb2, 3) != NULL);

  // Flesh out bb3 with some instructions and a single  successor.
  inst = AddInstruction(bb3, 2);
  Label label_3("3", BlockGraph::CODE_LABEL);
  inst->set_label(label_3);
  ASSERT_TRUE(inst != NULL);
  ASSERT_TRUE(AddInstruction(bb3, 1) != NULL);
  bb3->successors().push_back(
      Successor(Successor::kConditionTrue,
                BasicBlockReference(BlockGraph::RELATIVE_REF, 4, bb4),
                -1, 0));
  Label label_4("4", BlockGraph::CODE_LABEL);
  bb3->successors().back().set_label(label_4);

  // Flesh out bb4 with some instructions and a single  successor.
  ASSERT_TRUE(AddInstruction(bb4, 7) != NULL);
  ASSERT_TRUE(AddInstruction(bb4, 9) != NULL);
  bb4->successors().push_back(
      Successor(Successor::kConditionTrue,
                BasicBlockReference(BlockGraph::RELATIVE_REF, 4, bb2),
                -1, 0));

  // Flesh out table with references.
  Label label_5("5", BlockGraph::DATA_LABEL | BlockGraph::JUMP_TABLE_LABEL);
  table->set_label(label_5);
  ASSERT_TRUE(table->references().insert(std::make_pair(
      0, BasicBlockReference(BlockGraph::ABSOLUTE_REF, 4, bb1))).second);
  ASSERT_TRUE(table->references().insert(std::make_pair(
      4, BasicBlockReference(BlockGraph::ABSOLUTE_REF, 4, bb2))).second);
  ASSERT_TRUE(table->references().insert(std::make_pair(
      8, BasicBlockReference(BlockGraph::ABSOLUTE_REF, 4, bb3))).second);

  BasicBlockSubGraph::BlockDescription* d1 = subgraph.AddBlockDescription(
      "new_block", BlockGraph::CODE_BLOCK, 0, 1, 0);
  d1->basic_block_order.push_back(bb1);
  d1->basic_block_order.push_back(bb2);
  d1->basic_block_order.push_back(bb3);
  d1->basic_block_order.push_back(bb4);
  d1->basic_block_order.push_back(table);

  BlockBuilder builder(&bg);
  ASSERT_TRUE(builder.Merge(&subgraph));
  EXPECT_EQ(NULL, bg.GetBlockById(original_id));
  EXPECT_EQ(other, bg.GetBlockById(other_id));
  EXPECT_EQ(2, bg.blocks().size());
  ASSERT_EQ(1, builder.new_blocks().size());
  BlockGraph::Block* new_block = builder.new_blocks().front();
  EXPECT_EQ(new_block, bg.GetBlockById(new_block->id()));
  EXPECT_EQ(57U, new_block->size());
  EXPECT_EQ(new_block->data_size(), new_block->size());

  // Validate the new block's references.
  Block::ReferenceMap expected_references;
  expected_references[1] = Reference(
      BlockGraph::ABSOLUTE_REF, 4, other, 0, 0);
  expected_references[7] = Reference(
      BlockGraph::RELATIVE_REF, 4, new_block, 0, 0);
  expected_references[12] = Reference(
      BlockGraph::RELATIVE_REF, 4, new_block, 21, 21);
  expected_references[41] = Reference(
      BlockGraph::RELATIVE_REF, 4, new_block, 16, 16);
  expected_references[45] = Reference(
      BlockGraph::ABSOLUTE_REF, 4, new_block, 0, 0);
  expected_references[49] = Reference(
      BlockGraph::ABSOLUTE_REF, 4, new_block, 16, 16);
  expected_references[53] = Reference(
      BlockGraph::ABSOLUTE_REF, 4, new_block, 21, 21);
  EXPECT_EQ(expected_references, new_block->references());

  // Validate the new block's referrers.
  Block::ReferrerSet expected_referrers;
  expected_referrers.insert(Referrer(other, 0));
  expected_referrers.insert(Referrer(new_block, 7));
  expected_referrers.insert(Referrer(new_block, 12));
  expected_referrers.insert(Referrer(new_block, 41));
  expected_referrers.insert(Referrer(new_block, 45));
  expected_referrers.insert(Referrer(new_block, 49));
  expected_referrers.insert(Referrer(new_block, 53));
  EXPECT_EQ(expected_referrers, new_block->referrers());

  // Validate the references of the other block.
  Block::ReferenceMap expected_other_references;
  expected_other_references[0] = Reference(
      BlockGraph::ABSOLUTE_REF, 4, new_block, 0, 0);
  EXPECT_EQ(expected_other_references, other->references());

  // Validate the referrers of the other block.
  Block::ReferrerSet expected_other_referrers;
  expected_other_referrers.insert(Referrer(new_block, 1));
  EXPECT_EQ(expected_other_referrers, other->referrers());

  // Validate the labels.
  BlockGraph::Block::LabelMap expected_labels;
  expected_labels.insert(std::make_pair(0, label_1));
  expected_labels.insert(std::make_pair(16, label_2));
  expected_labels.insert(std::make_pair(21, label_3));
  expected_labels.insert(std::make_pair(24, label_4));
  expected_labels.insert(std::make_pair(45, label_5));
  EXPECT_EQ(expected_labels, new_block->labels());
}

}  // namespace block_graph
