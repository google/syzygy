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

const uint8 kEmptyData[32] = { 0 };

// Instructions we'll need in order to build the test subgraph.
// TODO(rogerm): Share these definitions from a central location for all the
//     basic-block, builder and assembler/decomposer unit-tests.
const uint8 kCall[5] = { 0xE8, 0x00, 0x00, 0x00, 0x00  };
const uint8 kNop1[1] = { 0x90 };
const uint8 kNop2[2] = { 0x66, 0x90 };
const uint8 kNop3[3] = { 0x66, 0x66, 0x90 };
const uint8 kNop7[7] = { 0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00 };
const uint8 kNop9[9] = { 0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00 };

// The BlockInfo describes the minimal information needed to represent a single
// basic block within a fake flow-graph. An array of BlockInfos represents the
// full flow-graph. Fields |succ1| and |succ2| are indexes within the array.
struct BlockInfo {
  uint8 size;
  uint8 succ1;
  uint8 succ2;
};

const uint8 kNoSucc = -1;

// The following flow-graph was produced by fuzzing. It produced a corner case
// when computing basic block layout.
const BlockInfo kFixPointBasicBlockLayoutCode[] = {
    {18, 5, 6}, {26, 2, 7}, {10, 13, 14}, {10, 4, 35}, {17, 36, 37},
    {12, 1, kNoSucc}, {8, 1, kNoSucc}, {5, 2, 8}, {28, 9, 11}, {2, 10, 12},
    {10, 2, kNoSucc}, {3, 9, kNoSucc}, {3, 10, kNoSucc}, {3, 3, kNoSucc},
    {21, 15, kNoSucc}, {9, 16, 25}, {9, 17, 26}, {9, 18, 27}, {11, 28, 29},
    {3, 20, 30}, {24, 21, 31}, {11, 22, 32}, {11, 33, 34}, {12, 15, 24},
    {3, 3, kNoSucc}, {7, 16, kNoSucc}, {7, 17, kNoSucc}, {7, 18, kNoSucc},
    {7, 19, kNoSucc}, {13, 19, kNoSucc}, {7, 20, kNoSucc}, {7, 21, kNoSucc},
    {7, 22, kNoSucc}, {2, 23, kNoSucc}, {10, 23, kNoSucc}, {7, 4, kNoSucc},
    {13, kNoSucc, kNoSucc}, {21, kNoSucc, kNoSucc}
};

class BlockBuilderTest : public testing::BasicBlockTest {
 public:
  static Instruction* AddInstruction(BasicCodeBlock* bb,
                                     const uint8* buf,
                                     size_t len) {
    CHECK(bb != NULL);
    Instruction tmp;
    EXPECT_TRUE(Instruction::FromBuffer(buf, len, &tmp));
    EXPECT_EQ(len, tmp.size());

    bb->instructions().push_back(tmp);
    return &bb->instructions().back();
  }

  BasicCodeBlock* CreateCodeBB(const base::StringPiece& name,
                               size_t len) {
    Instruction nop;
    EXPECT_EQ(1U, nop.size());
    BasicCodeBlock* bb = subgraph_.AddBasicCodeBlock(name);
    EXPECT_TRUE(bb != NULL);
    for (size_t i = 0; i < len; ++i)
      bb->instructions().push_back(nop);
    return bb;
  }

  Block* CreateLayout(size_t size1, size_t size2, size_t size3, size_t size4) {
    // Generate a set of puzzle blocks.
    BasicCodeBlock* bb1 = CreateCodeBB("bb1", size1);
    BasicCodeBlock* bb2 = CreateCodeBB("bb2", size2);
    BasicCodeBlock* bb3 = CreateCodeBB("bb3", size3);
    BasicCodeBlock* bb4 = CreateCodeBB("bb4", size4);

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
        "new_block", "new_compiland", BlockGraph::CODE_BLOCK, 0, 1, 0);
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

  // For a given array of BlockInfos, this function produces a fake subgraph and
  // uses the block builder to produce a block.
  Block* CreateLayoutFromInfo(const BlockInfo* info, size_t info_length) {
    std::vector<BasicCodeBlock*> basicblocks;
    basicblocks.resize(info_length);

    // Create basic blocks.
    for (size_t i = 0; i < info_length; ++i)
      basicblocks[i] = CreateCodeBB("bb", info[i].size);

    // Add edges between blocks (successors).
     for (size_t i = 0; i < info_length; ++i) {
      size_t succ1 = info[i].succ1;
      size_t succ2 = info[i].succ2;

      if (succ1 == kNoSucc) {
        // No successor.
        continue;
      } else if (succ2 == kNoSucc) {
        // One successor.
        basicblocks[i]->successors().push_back(
            Successor(Successor::kConditionTrue,
                      BasicBlockReference(BlockGraph::RELATIVE_REF,
                                          4,
                                          basicblocks[succ1]),
                      0));
      } else {
        // Two successors.
        basicblocks[i]->successors().push_back(
            Successor(Successor::kConditionEqual,
                      BasicBlockReference(BlockGraph::RELATIVE_REF,
                                          4,
                                          basicblocks[succ1]),
                      0));
        basicblocks[i]->successors().push_back(
            Successor(Successor::kConditionNotEqual,
                      BasicBlockReference(BlockGraph::RELATIVE_REF,
                                          4,
                                          basicblocks[succ2]),
                      0));
      }
    }

    // Create block description.
    BasicBlockSubGraph::BlockDescription* d1 = subgraph_.AddBlockDescription(
        "new_block", "new_compiland", BlockGraph::CODE_BLOCK, 0, 1, 0);
    for (size_t i = 0; i < info_length; ++i)
      d1->basic_block_order.push_back(basicblocks[i]);

    // Build block.
    BlockBuilder builder(&block_graph_);
    EXPECT_TRUE(builder.Merge(&subgraph_));
    EXPECT_EQ(1, builder.new_blocks().size());

    Block* new_block = builder.new_blocks()[0];
    EXPECT_TRUE(new_block != NULL);
    return new_block;
  }

};

}  // namespace

// A comparison operator for TagInfo objects. Needed for use with ContainerEq.
bool operator==(const TagInfo& ti1, const TagInfo& ti2) {
  return ti1.type == ti2.type && ti1.block == ti2.block &&
      ti1.offset == ti2.offset && ti1.size == ti2.size;
}

// This test constructs the following subgraph then merges it into block graph.
// It adds tags to each element and also ensures that the tagging mechanism
// works as expected.
//
// +-------+
// | Data  |
// +---+---+
//     |
//     +-->  +---------+
// bb1   0   | 5 bytes |  Ref: 4-byte ref to code block @ 1, Label1 (code+call).
//           +---------+
//           | 2 bytes |  Successor: 1-byte ref to bb1 @ 6.
//           +---------+
//           | 2 bytes |  Successor: 1-byte ref to bb3 @ 8.
//           +---------+
// bb2   9   | 2 bytes |  Label2 (code).
//           +---------+
//           | 3 bytes |
//           +---------+
// bb3   14  | 2 bytes |  Label3 (code).
//           +---------+
//           | 1 byte  |
//           +---------+  Successor: elided here. Label4.
// bb4   17  | 7 bytes |
//           +---------+
//           | 9 bytes |
//           +---------+
//           | 2 bytes |  Successor: 1-byte ref to bb2 @ 34.
//           +---------+
//           | 1 byte  |  Injected NOP due to data alignment.
// data  36  +---------+  Label5 (data).
//           | 4 bytes |  Ref: 4-byte ref to bb1 @ 36.
//           +---------+
//           | 4 bytes |  Ref: 4-byte ref to bb2 @ 40.
//           +---------+
//           | 4 bytes |  Ref: 4-byte ref to bb3 @ 44.
//       48  +---------+
//
TEST_F(BlockBuilderTest, Merge) {
  // Setup a code block which is referenced from a data block and references
  // another code block.
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
  bb1->tags().insert(bb1);
  BasicCodeBlock* bb2 = subgraph_.AddBasicCodeBlock("bb2");
  ASSERT_TRUE(bb2 != NULL);
  bb2->tags().insert(bb2);
  BasicCodeBlock* bb3 = subgraph_.AddBasicCodeBlock("bb3");
  ASSERT_TRUE(bb3 != NULL);
  bb3->tags().insert(bb3);
  BasicCodeBlock* bb4 = subgraph_.AddBasicCodeBlock("bb4");
  ASSERT_TRUE(bb4 != NULL);
  bb4->tags().insert(bb4);
  BasicDataBlock* table = subgraph_.AddBasicDataBlock("table", 12, kEmptyData);
  ASSERT_TRUE(table != NULL);
  table->tags().insert(table);

  // Flesh out bb1 with an instruction having a reference and 2 successors.
  Instruction* inst = AddInstruction(bb1, kCall, sizeof(kCall));
  Label label_1("1", BlockGraph::CODE_LABEL | BlockGraph::CALL_SITE_LABEL);
  inst->set_label(label_1);
  ASSERT_TRUE(inst != NULL);
  BasicBlockReference bb1_abs_ref(BlockGraph::ABSOLUTE_REF, 4, other, 0, 0);
  bb1_abs_ref.tags().insert(&bb1_abs_ref);
  ASSERT_TRUE(inst->references().insert(std::make_pair(1, bb1_abs_ref)).second);
  Instruction* bb1_inst1 = inst;
  bb1_inst1->tags().insert(bb1_inst1);
  BasicBlockReference bb1_succ1_ref(BlockGraph::RELATIVE_REF, 4, bb1);
  bb1_succ1_ref.tags().insert(&bb1_succ1_ref);
  Successor bb1_succ1(Successor::kConditionEqual, bb1_succ1_ref, 0);
  bb1_succ1.tags().insert(&bb1_succ1);
  bb1->successors().push_back(bb1_succ1);
  bb1->successors().push_back(
      Successor(Successor::kConditionNotEqual,
                BasicBlockReference(BlockGraph::RELATIVE_REF, 4, bb3),
                0));
  ASSERT_TRUE(bb1->referrers().insert(BasicBlockReferrer(other, 0)).second);

  // Flesh out bb2 with some instructions and no successor.
  inst = AddInstruction(bb2, kNop2, sizeof(kNop2));
  Label label_2("2", BlockGraph::CODE_LABEL);
  inst->set_label(label_2);
  ASSERT_TRUE(inst != NULL);
  ASSERT_TRUE(AddInstruction(bb2, kNop3, sizeof(kNop3)) != NULL);

  // Flesh out bb3 with some instructions and a single successor.
  // We set tags on the successor and its reference. Since these are elided
  // we expect zero-sized entries in the tag info map.
  inst = AddInstruction(bb3, kNop2, sizeof(kNop2));
  Label label_3("3", BlockGraph::CODE_LABEL);
  inst->set_label(label_3);
  ASSERT_TRUE(inst != NULL);
  ASSERT_TRUE(AddInstruction(bb3, kNop1, sizeof(kNop1)) != NULL);
  BasicBlockReference bb3_succ_ref(BlockGraph::RELATIVE_REF, 4, bb4);
  bb3_succ_ref.tags().insert(&bb3_succ_ref);
  Successor bb3_succ(Successor::kConditionTrue, bb3_succ_ref, 0);
  bb3_succ.tags().insert(&bb3_succ);
  bb3->successors().push_back(bb3_succ);
  Label label_4("4", BlockGraph::CODE_LABEL);
  bb3->successors().back().set_label(label_4);

  // Flesh out bb4 with some instructions and a single successor.
  ASSERT_TRUE(AddInstruction(bb4, kNop7, sizeof(kNop7)) != NULL);
  ASSERT_TRUE(AddInstruction(bb4, kNop9, sizeof(kNop9)) != NULL);
  bb4->successors().push_back(
      Successor(Successor::kConditionTrue,
                BasicBlockReference(BlockGraph::RELATIVE_REF, 4, bb2),
                0));

  // Flesh out table with references. Make the table aligned so that we test
  // our NOP insertion code.
  Label label_5("5", BlockGraph::DATA_LABEL | BlockGraph::JUMP_TABLE_LABEL);
  table->set_label(label_5);
  table->set_alignment(4);
  ASSERT_TRUE(table->references().insert(std::make_pair(
      0, BasicBlockReference(BlockGraph::ABSOLUTE_REF, 4, bb1))).second);
  ASSERT_TRUE(table->references().insert(std::make_pair(
      4, BasicBlockReference(BlockGraph::ABSOLUTE_REF, 4, bb2))).second);
  BasicBlockReference table_ref3(BlockGraph::ABSOLUTE_REF, 4, bb3);
  table_ref3.tags().insert(&table_ref3);
  ASSERT_TRUE(table->references().insert(std::make_pair(8, table_ref3)).second);

  BasicBlockSubGraph::BlockDescription* d1 = subgraph_.AddBlockDescription(
      "new_block", "new block compiland", BlockGraph::CODE_BLOCK, 0, 1, 0);
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
  EXPECT_EQ(48U, new_block->size());
  EXPECT_EQ(new_block->data_size(), new_block->size());
  EXPECT_EQ(table->alignment(), new_block->alignment());

  // Validate the tags.
  TagInfoMap expected_tags;
  expected_tags[bb1].push_back(TagInfo(kBasicCodeBlockTag, new_block, 0, 9));
  expected_tags[bb2].push_back(TagInfo(kBasicCodeBlockTag, new_block, 9, 5));
  expected_tags[bb3].push_back(TagInfo(kBasicCodeBlockTag, new_block, 14, 3));
  expected_tags[bb4].push_back(TagInfo(kBasicCodeBlockTag, new_block, 17, 18));
  expected_tags[table].push_back(
      TagInfo(kBasicDataBlockTag, new_block, 36, 12));
  expected_tags[bb1_inst1].push_back(TagInfo(kInstructionTag, new_block, 0, 5));
  expected_tags[&bb1_abs_ref].push_back(
      TagInfo(kReferenceTag, new_block, 1, 4));
  expected_tags[&bb1_succ1_ref].push_back(
      TagInfo(kReferenceTag, new_block, 6, 1));
  expected_tags[&bb1_succ1].push_back(TagInfo(kSuccessorTag, new_block, 5, 2));
  expected_tags[&bb3_succ_ref].push_back(
      TagInfo(kReferenceTag, new_block, 17, 0));
  expected_tags[&bb3_succ].push_back(TagInfo(kSuccessorTag, new_block, 17, 0));
  expected_tags[&table_ref3].push_back(
      TagInfo(kReferenceTag, new_block, 44, 4));
  EXPECT_THAT(builder.tag_info_map(), ::testing::ContainerEq(expected_tags));

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
  expected_references[36] = Reference(
      BlockGraph::ABSOLUTE_REF, 4, new_block, 0, 0);
  expected_references[40] = Reference(
      BlockGraph::ABSOLUTE_REF, 4, new_block, 9, 9);
  expected_references[44] = Reference(
      BlockGraph::ABSOLUTE_REF, 4, new_block, 14, 14);
  EXPECT_EQ(expected_references, new_block->references());

  // Validate the new block's referrers.
  Block::ReferrerSet expected_referrers;
  expected_referrers.insert(Referrer(other, 0));
  expected_referrers.insert(Referrer(new_block, 6));
  expected_referrers.insert(Referrer(new_block, 8));
  expected_referrers.insert(Referrer(new_block, 34));
  expected_referrers.insert(Referrer(new_block, 36));
  expected_referrers.insert(Referrer(new_block, 40));
  expected_referrers.insert(Referrer(new_block, 44));
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
  expected_labels.insert(std::make_pair(36, label_5));
  EXPECT_EQ(expected_labels, new_block->labels());

  // Validate that there is a single byte NOP at position 35, just prior to the
  // table.
  EXPECT_EQ(0x90, new_block->data()[35]);
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

TEST_F(BlockBuilderTest, ComplexFixPointBasicBlockLayout) {
  // This test validates a corner case of the basic block layout algorithm. The
  // fake flow-graph |kFixPointBasicBlockLayoutCode| produces a case where the
  // estimated size of a successor was temporarily shrinking and causing a
  // DCHECK to fail.
  size_t info_length = arraysize(kFixPointBasicBlockLayoutCode);
  Block* new_block = CreateLayoutFromInfo(kFixPointBasicBlockLayoutCode,
                                          info_length);
  ASSERT_TRUE(new_block != NULL);

  EXPECT_EQ(575, new_block->size());
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

TEST_F(BlockBuilderTest, LabelsPastEndAreDropped) {
  ASSERT_NO_FATAL_FAILURE(InitBasicBlockSubGraphWithLabelPastEnd());

  BlockBuilder builder(&block_graph_);
  ASSERT_TRUE(builder.Merge(&subgraph_));

  ASSERT_EQ(1u, builder.new_blocks().size());

  BlockGraph::Block* new_block = builder.new_blocks()[0];
  ASSERT_EQ(1u, new_block->labels().size());
  ASSERT_EQ(0, new_block->labels().begin()->first);
  ASSERT_EQ(BlockGraph::CODE_LABEL | BlockGraph::DEBUG_START_LABEL,
            new_block->labels().begin()->second.attributes());

  // TODO(chrisha): When we properly handle labels of this type, ensure that
  //     they make it through the block building process. For now we simply
  //     ensure that it *doesn't* exist.
}

}  // namespace block_graph
