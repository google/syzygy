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
// Tests for the basic block classes.

#include "syzygy/block_graph/block_builder.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/block_graph/basic_block.h"
#include "syzygy/block_graph/basic_block_subgraph.h"
#include "syzygy/block_graph/basic_block_test_util.h"
#include "syzygy/block_graph/block_graph.h"

namespace block_graph {

namespace {

typedef BlockGraph::Block Block;
typedef BlockGraph::Label Label;
typedef BlockGraph::Reference Reference;
typedef Block::Referrer Referrer;

static const uint8 kEmptyData[32] = {0};

class BlockBuilderTest : public testing::BasicBlockTest {
 public:
   static Instruction* AddInstruction(BasicCodeBlock* bb,
                                      Instruction::Size size) {
    CHECK(bb != NULL);
    bb->instructions().push_back(
        Instruction(size, kEmptyData));
    return &bb->instructions().back();
  }

  BasicCodeBlock* CreateCodeBB(const base::StringPiece& name, size_t len) {
    BasicCodeBlock* bb = subgraph_.AddBasicCodeBlock(name);
    EXPECT_TRUE(bb != NULL);
    while (len > 0) {
      size_t instr_len =
          std::min(len, core::AssemblerImpl::kMaxInstructionLength);
      len -= instr_len;
      AddInstruction(bb, instr_len);
    }
    return bb;
  }

  Block* CreateLayout(size_t size1, size_t size2, size_t size3, size_t size4) {
    // Generate a set of puzzle blocks.
    BasicCodeBlock* bb1 = CreateCodeBB("bb1", size1);
    BasicCodeBlock* bb2 = CreateCodeBB("bb2", size2);
    BasicCodeBlock* bb3 = CreateCodeBB("bb3", size3);
    BasicCodeBlock* bb4 = CreateCodeBB("bb3", size4);

    // BB1 has BB4 and BB2 as successors.
    bb1->successors().push_back(
        Successor(Successor::kConditionEqual,
                  BasicBlockReference(BlockGraph::RELATIVE_REF, 4, bb4),
                  0));
    bb1->successors().push_back(
        Successor(Successor::kConditionNotEqual,
                  BasicBlockReference(BlockGraph::RELATIVE_REF, 4, bb2),
                  0));

    // BB2 has BB1 as successor.
    bb2->successors().push_back(
        Successor(Successor::kConditionTrue,
                  BasicBlockReference(BlockGraph::RELATIVE_REF, 4, bb1),
                  0));

    // BB3 has BB4 as successor.
    bb3->successors().push_back(
        Successor(Successor::kConditionTrue,
                  BasicBlockReference(BlockGraph::RELATIVE_REF, 4, bb4),
                  0));

    BasicBlockSubGraph::BlockDescription* d1 = subgraph_.AddBlockDescription(
        "new_block", BlockGraph::CODE_BLOCK, 0, 1, 0);
    d1->basic_block_order.push_back(bb1);
    d1->basic_block_order.push_back(bb2);
    d1->basic_block_order.push_back(bb3);
    d1->basic_block_order.push_back(bb4);

    BlockBuilder builder(&block_graph_);
    EXPECT_TRUE(builder.Merge(&subgraph_));
    EXPECT_EQ(1, builder.new_blocks().size());

    Block* new_block = builder.new_blocks()[0];
    EXPECT_TRUE(new_block != NULL);
    return new_block;
  }
};

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
//           | 2 bytes |  Successor: 1-byte ref to bb1 @ 6
//           +---------+
//           | 2 bytes |  Successor: 1-byte ref to bb3 @ 8
//           +---------+
// bb2   9   | 2 bytes |  Label2 (code)
//           +---------+
//           | 3 bytes |
//           +---------+
// bb3   14  | 2 bytes |  Label3 (code).
//           +---------+
//           | 1 bytes |
//           +---------+  Successor: elided here. Label4
// bb4   17  | 7 bytes |
//           +---------+
//           | 9 bytes |
//           +---------+
//           | 2 bytes |  Successor: 1-byte ref to bb2 @ 34
// data  35  +---------+  Label5 (data).
//           | 4 bytes |  Ref: 4-byte ref to bb1 @ 35
//           +---------+
//           | 4 bytes |  Ref: 4-byte ref to bb2 @ 39
//           +---------+
//           | 4 bytes |  Ref: 4-byte ref to bb3 @ 43
//       47  +---------+
//
TEST_F(BlockBuilderTest, Merge) {
  // Setup a code block which is referenced from a data block.
  BlockGraph::Block* original =
      block_graph_.AddBlock(BlockGraph::CODE_BLOCK, 32, "original");
  ASSERT_TRUE(original != NULL);
  BlockGraph::BlockId original_id = original->id();
  BlockGraph::Block* other =
      block_graph_.AddBlock(BlockGraph::DATA_BLOCK, 4, "other");
  ASSERT_TRUE(other != NULL);
  BlockGraph::BlockId other_id = other->id();
  ASSERT_TRUE(other->SetReference(
      0, BlockGraph::Reference(BlockGraph::ABSOLUTE_REF, 4, original, 0, 0)));

  // Verify some expectations.
  ASSERT_EQ(2, block_graph_.blocks().size());
  ASSERT_EQ(1, original->referrers().size());

  // Generate a mock decomposition of the original block.
  subgraph_.set_original_block(original);
  BasicCodeBlock* bb1 = subgraph_.AddBasicCodeBlock("bb1");
  ASSERT_TRUE(bb1 != NULL);
  BasicCodeBlock* bb2 = subgraph_.AddBasicCodeBlock("bb2");
  ASSERT_TRUE(bb2 != NULL);
  BasicCodeBlock* bb3 = subgraph_.AddBasicCodeBlock("bb3");
  ASSERT_TRUE(bb3 != NULL);
  BasicCodeBlock* bb4 = subgraph_.AddBasicCodeBlock("bb4");
  ASSERT_TRUE(bb4 != NULL);
  BasicDataBlock* table = subgraph_.AddBasicDataBlock(
      "table", BasicBlock::BASIC_DATA_BLOCK, 12, kEmptyData);
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
                0));
  bb1->successors().push_back(
      Successor(Successor::kConditionNotEqual,
                BasicBlockReference(BlockGraph::RELATIVE_REF, 4, bb3),
                0));
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
                0));
  Label label_4("4", BlockGraph::CODE_LABEL);
  bb3->successors().back().set_label(label_4);

  // Flesh out bb4 with some instructions and a single  successor.
  ASSERT_TRUE(AddInstruction(bb4, 7) != NULL);
  ASSERT_TRUE(AddInstruction(bb4, 9) != NULL);
  bb4->successors().push_back(
      Successor(Successor::kConditionTrue,
                BasicBlockReference(BlockGraph::RELATIVE_REF, 4, bb2),
                0));

  // Flesh out table with references.
  Label label_5("5", BlockGraph::DATA_LABEL | BlockGraph::JUMP_TABLE_LABEL);
  table->set_label(label_5);
  ASSERT_TRUE(table->references().insert(std::make_pair(
      0, BasicBlockReference(BlockGraph::ABSOLUTE_REF, 4, bb1))).second);
  ASSERT_TRUE(table->references().insert(std::make_pair(
      4, BasicBlockReference(BlockGraph::ABSOLUTE_REF, 4, bb2))).second);
  ASSERT_TRUE(table->references().insert(std::make_pair(
      8, BasicBlockReference(BlockGraph::ABSOLUTE_REF, 4, bb3))).second);

  BasicBlockSubGraph::BlockDescription* d1 = subgraph_.AddBlockDescription(
      "new_block", BlockGraph::CODE_BLOCK, 0, 1, 0);
  d1->basic_block_order.push_back(bb1);
  d1->basic_block_order.push_back(bb2);
  d1->basic_block_order.push_back(bb3);
  d1->basic_block_order.push_back(bb4);
  d1->basic_block_order.push_back(table);

  BlockBuilder builder(&block_graph_);
  ASSERT_TRUE(builder.Merge(&subgraph_));
  EXPECT_EQ(NULL, block_graph_.GetBlockById(original_id));
  EXPECT_EQ(other, block_graph_.GetBlockById(other_id));
  EXPECT_EQ(2, block_graph_.blocks().size());
  ASSERT_EQ(1, builder.new_blocks().size());
  BlockGraph::Block* new_block = builder.new_blocks().front();
  EXPECT_EQ(new_block, block_graph_.GetBlockById(new_block->id()));
  EXPECT_EQ(47U, new_block->size());
  EXPECT_EQ(new_block->data_size(), new_block->size());

  // Validate the new block's references.
  Block::ReferenceMap expected_references;
  expected_references[1] = Reference(
      BlockGraph::ABSOLUTE_REF, 4, other, 0, 0);
  expected_references[6] = Reference(
      BlockGraph::PC_RELATIVE_REF, 1, new_block, 0, 0);
  expected_references[8] = Reference(
      BlockGraph::PC_RELATIVE_REF, 1, new_block, 14, 14);
  expected_references[34] = Reference(
      BlockGraph::PC_RELATIVE_REF, 1, new_block, 9, 9);
  expected_references[35] = Reference(
      BlockGraph::ABSOLUTE_REF, 4, new_block, 0, 0);
  expected_references[39] = Reference(
      BlockGraph::ABSOLUTE_REF, 4, new_block, 9, 9);
  expected_references[43] = Reference(
      BlockGraph::ABSOLUTE_REF, 4, new_block, 14, 14);
  EXPECT_EQ(expected_references, new_block->references());

  // Validate the new block's referrers.
  Block::ReferrerSet expected_referrers;
  expected_referrers.insert(Referrer(other, 0));
  expected_referrers.insert(Referrer(new_block, 6));
  expected_referrers.insert(Referrer(new_block, 8));
  expected_referrers.insert(Referrer(new_block, 34));
  expected_referrers.insert(Referrer(new_block, 35));
  expected_referrers.insert(Referrer(new_block, 39));
  expected_referrers.insert(Referrer(new_block, 43));
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
  expected_labels.insert(std::make_pair(9, label_2));
  expected_labels.insert(std::make_pair(14, label_3));
  expected_labels.insert(std::make_pair(17, label_4));
  expected_labels.insert(std::make_pair(35, label_5));
  EXPECT_EQ(expected_labels, new_block->labels());
}

TEST_F(BlockBuilderTest, ShortLayout) {
  // This is the block structure we construct. If either of BB1 or BB2's
  // successors is manifested too long, they will both have to grow.
  // 0    [BB1] 62 bytes
  // 62   jeq BB4 (+127 bytes).
  // 64   [BB2] 62 bytes
  // 126  jmp BB1  (-128 bytes).
  // 128  [BB3] 63 bytes.
  // 191  [BB4] 1 byte.
  Block* new_block = CreateLayout(62, 62, 63, 1);
  ASSERT_TRUE(new_block != NULL);

  EXPECT_EQ(192, new_block->size());
  Block::ReferenceMap expected_refs;
  expected_refs.insert(
      std::make_pair(63,
                     Reference(BlockGraph::PC_RELATIVE_REF,
                               1, new_block, 191, 191)));
  expected_refs.insert(
      std::make_pair(127,
                     Reference(BlockGraph::PC_RELATIVE_REF,
                               1, new_block, 0, 0)));
  EXPECT_EQ(expected_refs, new_block->references());
}

TEST_F(BlockBuilderTest, OutofReachBranchLayout) {
  // 54 + 72 + 2 = 128 - the BB1->BB4 branch is just out of reach.
  Block* new_block = CreateLayout(62, 54, 72, 1);
  ASSERT_TRUE(new_block != NULL);

  size_t expected_size = 62 +
                         core::AssemblerImpl::kLongBranchSize +
                         54 +
                         core::AssemblerImpl::kShortJumpSize +
                         72 +
                         1;
  EXPECT_EQ(expected_size, new_block->size());
  Block::ReferenceMap expected_refs;
  expected_refs.insert(
      std::make_pair(62 + core::AssemblerImpl::kLongBranchOpcodeSize,
                     Reference(BlockGraph::PC_RELATIVE_REF,
                               4,
                               new_block,
                               expected_size - 1,
                               expected_size - 1)));
  size_t succ_location = 62 +
                         core::AssemblerImpl::kLongBranchSize +
                         54 +
                         core::AssemblerImpl::kShortJumpOpcodeSize;
  expected_refs.insert(
      std::make_pair(succ_location,
                     Reference(BlockGraph::PC_RELATIVE_REF,
                               1, new_block, 0, 0)));
  EXPECT_EQ(expected_refs, new_block->references());
}

TEST_F(BlockBuilderTest, OutofReachJmpLayout) {
  // 0 - (62 + 2 + 63 + 2) = -129, the jump from BB2->BB1 is just out of reach.
  Block* new_block = CreateLayout(62, 63, 55, 1);
  ASSERT_TRUE(new_block != NULL);

  size_t expected_size = 62 +
                         core::AssemblerImpl::kShortBranchSize+
                         63 +
                         core::AssemblerImpl::kLongJumpSize+
                         55 +
                         1;
  EXPECT_EQ(expected_size, new_block->size());
  Block::ReferenceMap expected_refs;
  expected_refs.insert(
      std::make_pair(62 + core::AssemblerImpl::kShortBranchOpcodeSize,
                     Reference(BlockGraph::PC_RELATIVE_REF,
                               1,
                               new_block,
                               expected_size - 1,
                               expected_size - 1)));
  size_t succ_location = 62 +
                         core::AssemblerImpl::kShortBranchSize +
                         63 +
                         core::AssemblerImpl::kLongJumpOpcodeSize;
  expected_refs.insert(
      std::make_pair(succ_location,
                     Reference(BlockGraph::PC_RELATIVE_REF,
                               4, new_block, 0, 0)));
  EXPECT_EQ(expected_refs, new_block->references());
}

TEST_F(BlockBuilderTest, MergeAssemblesSourceRangesCorrectly) {
  ASSERT_NO_FATAL_FAILURE(InitBlockGraph());
  ASSERT_NO_FATAL_FAILURE(InitBasicBlockSubGraph());

  // Test that re-assembling this decomposition produces an unbroken,
  // identical source range as the original block had.
  BlockGraph::Block::SourceRanges expected_source_ranges(
      assembly_func_->source_ranges());

  BlockBuilder builder(&block_graph_);
  ASSERT_TRUE(builder.Merge(&subgraph_));

  ASSERT_EQ(1, builder.new_blocks().size());

  BlockGraph::Block* new_block = builder.new_blocks()[0];
  ASSERT_EQ(expected_source_ranges, new_block->source_ranges());
}

}  // namespace block_graph
