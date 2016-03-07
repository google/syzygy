// Copyright 2015 Google Inc. All Rights Reserved.
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

#include "syzygy/pe/transforms/pe_hot_patching_basic_block_transform.h"

#include "gtest/gtest.h"
#include "syzygy/assm/unittest_util.h"
#include "syzygy/block_graph/basic_block_decomposer.h"
#include "syzygy/block_graph/block_builder.h"
#include "syzygy/pe/pe_transform_policy.h"

namespace pe {
namespace transforms {

using block_graph::BasicBlockDecomposer;
using block_graph::BasicBlockSubGraph;
using block_graph::BlockBuilder;
using block_graph::BlockGraph;

// A subclass of PEHotPatchingBasicBlockTransform that exposes public members
// that we want to test.
class TestPEHotPatchingBasicBlockTransform :
    public PEHotPatchingBasicBlockTransform {
public:
  using PEHotPatchingBasicBlockTransform::InsertTwoByteNopAtBlockBeginning;
  using PEHotPatchingBasicBlockTransform::
      IsAtomicallyReplaceableFirstInstruction;
  using PEHotPatchingBasicBlockTransform::
      EnsureAtomicallyReplaceableFirstInstruction;
  using PEHotPatchingBasicBlockTransform::EnsurePaddingForJumpBeforeBlock;
  using PEHotPatchingBasicBlockTransform::GetFirstBasicCodeBlock;
  using PEHotPatchingBasicBlockTransform::kLongJumpInstructionLength;
};

namespace {

// _asm INC EAX (1-byte instruction)
const uint8_t kCodeIncEax[] = {0x40};

// _asm INC AX (2-byte instruction)
const uint8_t kCodeIncAx[] = {0x66, 0x40};

// _asm 3-byte NOP (3-byte instruction)
const uint8_t kCodeThreeByteNop[] = {0x66, 0x66, 0x90};

// _asm RET (1-byte instruction)
const uint8_t kCodeRet[] = {0xC3};

// _asm JMP 0 (2-byte instruction)
const uint8_t kCodeTwoByteEndlessLoop[] = {0xEB, 0xFE};

}  // namespace

// This fixture creates four code blocks:
//   - One 1 byte long instruction
//   - One 2 bytes long instruction
//   - One 3 bytes long instruction
//   - One 1 byte long control flow instruction
//   - One 2 bytes long control flow instruction
// These blocks are used to test methods of PEHotPatchingTransform that work
// on blocks.
class PEHotPatchingTransformBlockOperationTest : public ::testing::Test {
 public:

  // Create the test blocks.
  virtual void SetUp() override {
    block_1_byte_instr_ =
        block_graph_.AddBlock(BlockGraph::CODE_BLOCK, 1U, "i1byte");
    ASSERT_NE(nullptr, block_1_byte_instr_);
    block_1_byte_instr_->SetData(kCodeIncEax, 1U);

    block_2_byte_instr_ =
        block_graph_.AddBlock(BlockGraph::CODE_BLOCK, 2U, "i2byte");
    ASSERT_NE(nullptr, block_2_byte_instr_);
    block_2_byte_instr_->SetData(kCodeIncAx, 2U);

    block_3_byte_instr_ =
        block_graph_.AddBlock(BlockGraph::CODE_BLOCK, 3U, "i3byte");
    ASSERT_NE(nullptr, block_3_byte_instr_);
    block_3_byte_instr_->SetData(kCodeThreeByteNop, 3U);

    block_1_byte_cf_instr_ =
        block_graph_.AddBlock(BlockGraph::CODE_BLOCK, 1U, "i1bytecf");
    ASSERT_NE(nullptr, block_1_byte_cf_instr_);
    block_1_byte_cf_instr_->SetData(kCodeRet, 1U);

    block_2_byte_cf_instr_ =
        block_graph_.AddBlock(BlockGraph::CODE_BLOCK, 2U, "i2bytecf");
    ASSERT_NE(nullptr, block_2_byte_cf_instr_);
    block_2_byte_cf_instr_->SetData(kCodeTwoByteEndlessLoop, 2U);
  }

  TestPEHotPatchingBasicBlockTransform hp_transform_;

  BlockGraph block_graph_;

  BlockGraph::Block* block_1_byte_instr_;
  BlockGraph::Block* block_2_byte_instr_;
  BlockGraph::Block* block_3_byte_instr_;
  BlockGraph::Block* block_1_byte_cf_instr_;
  BlockGraph::Block* block_2_byte_cf_instr_;

  // The policy objects restricting how the transform is applied.
  pe::PETransformPolicy pe_policy_;

protected:

  // Decompose a block into a basic block subgraph
  void DecomposeBlock(BlockGraph::Block* block, BasicBlockSubGraph* bbsg) {
    BasicBlockDecomposer decomposer(block, bbsg);
    ASSERT_TRUE(decomposer.Decompose());
  }

  // Build a basic block subgraph to a block. If a new block is created
  // the block will be changed.
  // @param block_ptr An output parameter containing the new block that is
  //     built.
  void RebuildBlock(BlockGraph::Block** block_ptr, BasicBlockSubGraph* bbsg) {
    BlockBuilder builder(&block_graph_);
    ASSERT_TRUE(builder.Merge(bbsg));
    ASSERT_EQ(1U, builder.new_blocks().size());
    *block_ptr = builder.new_blocks().front();
  }

  // Check if a block begins with a two-byte NOP.
  // @param block The block to check.
  // @returns true iff the block begins with a two-byte NOP.
  bool StartsWithTwoByteNop(BlockGraph::Block* block) {
    if (block->data_size() < 2U)
      return false;
    if (block->data()[0] != testing::kNop2[0])
      return false;
    if (block->data()[1] != testing::kNop2[1])
      return false;

    return true;
  }

  void TestInsertTwoByteNopAtBlockBeginning(
      BlockGraph::Block** block_ptr,
      bool compare_instructions) {
    BlockGraph::Block*& block = *block_ptr;

    // Backup old data.
    size_t block_old_size = block->data_size();
    std::vector<uint8_t> block_old_data(block_old_size);
    ::memcpy(block_old_data.data(), block->data(), block_old_size);

    // Insert the two-byte NOP.
    BasicBlockSubGraph bbsg;
    DecomposeBlock(block, &bbsg);
    hp_transform_.InsertTwoByteNopAtBlockBeginning(
        hp_transform_.GetFirstBasicCodeBlock(&bbsg));
    RebuildBlock(&block, &bbsg);

    // Block should have its own data now.
    ASSERT_TRUE(block->owns_data());

    // Check the data length.
    ASSERT_EQ(block_old_size + 2, block->data_size());

    // Check if data begins with a two byte NOP.
    EXPECT_TRUE(StartsWithTwoByteNop(block));

    // Every byte should be shifted by two bytes.
    if (compare_instructions) {
      for (size_t i = 0; i < block_old_size; ++i) {
        EXPECT_EQ(block_old_data[i], block->data()[i + 2]);
      }
    }
  }

  void TestEnsurePaddingForJumpBeforeBlock(BlockGraph::Block* block) {
    BasicBlockSubGraph bbsg;
    DecomposeBlock(block, &bbsg);
    hp_transform_.EnsurePaddingForJumpBeforeBlock(&bbsg);
    RebuildBlock(&block, &bbsg);

    EXPECT_EQ(TestPEHotPatchingBasicBlockTransform::kLongJumpInstructionLength,
              block->padding_before());
  }

  void TestIsAtomicallyReplaceableFirstInstruction(
      BlockGraph::Block* block,
      bool result) {
    BasicBlockSubGraph bbsg;
    DecomposeBlock(block, &bbsg);
    ASSERT_EQ(result,
              hp_transform_.IsAtomicallyReplaceableFirstInstruction(
                  hp_transform_.GetFirstBasicCodeBlock(&bbsg)));
  }

  void ExecuteEnsureAtomicallyReplaceableFirstInstruction(
      BlockGraph::Block** block_ptr) {
    BasicBlockSubGraph bbsg;
    DecomposeBlock(*block_ptr, &bbsg);
    hp_transform_.EnsureAtomicallyReplaceableFirstInstruction(&bbsg);
    RebuildBlock(block_ptr, &bbsg);
  }
};

TEST_F(PEHotPatchingTransformBlockOperationTest,
       InsertTwoByteNopAtBlockBeginning) {
  TestInsertTwoByteNopAtBlockBeginning(&block_1_byte_instr_, true);
  TestInsertTwoByteNopAtBlockBeginning(&block_2_byte_instr_, true);
  TestInsertTwoByteNopAtBlockBeginning(&block_3_byte_instr_, true);
  TestInsertTwoByteNopAtBlockBeginning(&block_1_byte_cf_instr_, true);
  TestInsertTwoByteNopAtBlockBeginning(&block_2_byte_cf_instr_, false);

  // We can't compare the instructions in the JMP 0 testcase byte by byte as
  // prepending a NOP to a block that has a jump to its beginning should change
  // the reference.
  ASSERT_EQ(4U, block_2_byte_cf_instr_->data_size());
  // The opcode for 1-byte PC-relative JMP (0xEB) must remain the same.
  EXPECT_EQ(kCodeTwoByteEndlessLoop[0], block_2_byte_cf_instr_->data()[2]);
  // The original jump length zero (encoded by 0xFE) should be decremented by
  // two so it still jumps to the beginning of the block.
  EXPECT_EQ(kCodeTwoByteEndlessLoop[1] - 2, block_2_byte_cf_instr_->data()[3]);
}

TEST_F(PEHotPatchingTransformBlockOperationTest,
       IsAtomicallyReplaceableFirstInstruction) {
  // One byte instruction is not atomically replaceable.
  block_1_byte_instr_->set_alignment(2);
  TestIsAtomicallyReplaceableFirstInstruction(block_1_byte_instr_, false);

  // Two byte instruction with 2-byte alignment is atomically replaceable.
  block_2_byte_instr_->set_alignment(2);
  TestIsAtomicallyReplaceableFirstInstruction(block_2_byte_instr_, true);

  // Three byte instruction with 2-byte alignment is atomically replaceable.
  block_3_byte_instr_->set_alignment(2);
  TestIsAtomicallyReplaceableFirstInstruction(block_3_byte_instr_, true);

  // One byte instruction is not atomically replaceable.
  block_1_byte_cf_instr_->set_alignment(2);
  TestIsAtomicallyReplaceableFirstInstruction(block_1_byte_cf_instr_, false);

  // Two byte instruction with 2-byte alignment is atomically replaceable.
  block_2_byte_cf_instr_->set_alignment(2);
  TestIsAtomicallyReplaceableFirstInstruction(block_2_byte_cf_instr_, true);
}

TEST_F(PEHotPatchingTransformBlockOperationTest,
       EnsureAtomicallyReplaceableFirstInstruction) {
  // One byte instruction should be extended with NOP and made 2 bytes aligned
  // with alignment offset of 2.
  ExecuteEnsureAtomicallyReplaceableFirstInstruction(&block_1_byte_instr_);
  ASSERT_EQ(3U, block_1_byte_instr_->data_size());
  ASSERT_EQ(2U, block_1_byte_instr_->alignment());
  EXPECT_TRUE(StartsWithTwoByteNop(block_1_byte_instr_));

  // Two byte instruction should remain the same, but 2 bytes aligned.
  ExecuteEnsureAtomicallyReplaceableFirstInstruction(&block_2_byte_instr_);
  ASSERT_EQ(2U, block_2_byte_instr_->data_size());
  ASSERT_EQ(2U, block_2_byte_instr_->alignment());

  // Three byte instruction should remain the same, but 2 bytes aligned.
  ExecuteEnsureAtomicallyReplaceableFirstInstruction(&block_3_byte_instr_);
  ASSERT_EQ(3U, block_3_byte_instr_->data_size());
  ASSERT_EQ(2U, block_2_byte_instr_->alignment());

  // One byte instruction should be extended with NOP and made 2 bytes aligned
  // with alignment offset of 2.
  ExecuteEnsureAtomicallyReplaceableFirstInstruction(&block_1_byte_cf_instr_);
  ASSERT_EQ(3U, block_1_byte_cf_instr_->data_size());
  ASSERT_EQ(2U, block_1_byte_cf_instr_->alignment());
  EXPECT_TRUE(StartsWithTwoByteNop(block_1_byte_cf_instr_));

  // Two byte instruction should remain the same, but 2 bytes aligned.
  ExecuteEnsureAtomicallyReplaceableFirstInstruction(&block_2_byte_cf_instr_);
  ASSERT_EQ(2U, block_2_byte_cf_instr_->data_size());
  ASSERT_EQ(2U, block_2_byte_cf_instr_->alignment());
}

TEST_F(PEHotPatchingTransformBlockOperationTest,
       EnsurePaddingForJumpBeforeBlock) {
  TestEnsurePaddingForJumpBeforeBlock(block_1_byte_instr_);
  TestEnsurePaddingForJumpBeforeBlock(block_2_byte_instr_);
  TestEnsurePaddingForJumpBeforeBlock(block_3_byte_instr_);
  TestEnsurePaddingForJumpBeforeBlock(block_1_byte_cf_instr_);
  TestEnsurePaddingForJumpBeforeBlock(block_2_byte_cf_instr_);
}

}  // namespace transforms
}  // namespace pe
