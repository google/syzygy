// Copyright 2017 Google Inc. All Rights Reserved.
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

#include "syzygy/instrument/transforms/afl_transform.h"

#include "mnemonics.h"
#include "gtest/gtest.h"
#include "syzygy/block_graph/basic_block.h"
#include "syzygy/block_graph/basic_block_decomposer.h"
#include "syzygy/block_graph/basic_block_subgraph.h"
#include "syzygy/block_graph/block_graph.h"
#include "syzygy/block_graph/typed_block.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/instrument/transforms/unittest_util.h"
#include "syzygy/pe/unittest_util.h"

namespace instrument {
namespace transforms {
namespace {

using block_graph::BasicBlock;
using block_graph::BasicBlockDecomposer;
using block_graph::BasicBlockReference;
using block_graph::BasicBlockSubGraph;
using block_graph::BasicCodeBlock;
using block_graph::BlockGraph;
using block_graph::Instruction;

class TestAFLTransform : public AFLTransform {
 public:
  TestAFLTransform(const std::unordered_set<std::string>& targets,
                   bool whitelist_mode,
                   bool force_decompose,
                   bool multithread,
                   bool cookie_check_hook)
      : AFLTransform(targets,
                     whitelist_mode,
                     force_decompose,
                     multithread,
                     cookie_check_hook) {}

  using AFLTransform::afl_static_cov_data_;
  using AFLTransform::multithread_;
  using AFLTransform::targets_visited_;
  using AFLTransform::tls_afl_prev_loc_displacement_;
  using AFLTransform::total_code_blocks_;
  using AFLTransform::total_code_blocks_instrumented_;
  using AFLTransform::whitelist_mode_;
};

class AFLTransformTest : public testing::TestDllTransformTest {
 protected:
  void CheckBasicBlockInstrumentation(TestAFLTransform& afl);
  void CheckInstrumentation(BasicBlock::Instructions::const_iterator& iter,
                            const BasicBlock::Instructions::const_iterator& end,
                            TestAFLTransform& afl);
};

void AFLTransformTest::CheckInstrumentation(
    BasicBlock::Instructions::const_iterator& iter,
    const BasicBlock::Instructions::const_iterator& end,
    TestAFLTransform& afl) {
  // push eax
  const Instruction& inst1 = *iter;
  EXPECT_EQ(I_PUSH, inst1.representation().opcode);
  ASSERT_NE(++iter, end);

  // push ebx
  const Instruction& inst2 = *iter;
  EXPECT_EQ(I_PUSH, inst2.representation().opcode);
  ASSERT_NE(++iter, end);

  if (afl.multithread_) {
    // push ecx
    const Instruction& inst3 = *iter;
    EXPECT_EQ(I_PUSH, inst3.representation().opcode);
    ASSERT_NE(++iter, end);
  }

  // lahf
  const Instruction& inst4 = *iter;
  EXPECT_EQ(I_LAHF, inst4.representation().opcode);
  ASSERT_NE(++iter, end);

  // seto al
  const Instruction& inst5 = *iter;
  EXPECT_EQ(I_SETO, inst5.representation().opcode);
  ASSERT_NE(++iter, end);

  if (afl.multithread_) {
    // mov ecx, tls_index
    const Instruction& inst6 = *iter;
    const _DInst& representation6 = inst6.representation();
    EXPECT_EQ(I_MOV, representation6.opcode);
    const auto& references6 = inst6.references();
    EXPECT_EQ(1, references6.size());
    const BasicBlockReference& blockref6 = references6.cbegin()->second;
    EXPECT_EQ(AFLTransform::kOffsetTlsIndex, blockref6.offset());
    EXPECT_EQ(AFLTransform::kMetadataBlockName, blockref6.block()->name());
    EXPECT_EQ(afl.afl_static_cov_data_, blockref6.block());
    ASSERT_NE(++iter, end);

    // mov ebx, fs:[2C]
    const Instruction& inst7 = *iter;
    const _DInst& representation7 = inst7.representation();
    EXPECT_EQ(I_MOV, representation7.opcode);
    ASSERT_EQ(O_DISP, representation7.ops[1].type);
    EXPECT_EQ(AFLTransform::kOffsetTebStorage, representation7.disp);
    ASSERT_NE(++iter, end);

    // mov ecx, [ebx + ecx * 4]
    const Instruction& inst8 = *iter;
    EXPECT_EQ(I_MOV, inst8.representation().opcode);
    ASSERT_NE(++iter, end);

    // lea ecx, [ecx + offset]
    const Instruction& inst9 = *iter;
    const _DInst& representation9 = inst9.representation();
    EXPECT_EQ(I_LEA, representation9.opcode);
    ASSERT_EQ(O_SMEM, representation9.ops[1].type);
    ASSERT_EQ(afl.tls_afl_prev_loc_displacement_, representation9.disp);
    ASSERT_NE(++iter, end);
  }

  // mov ebx, ID
  const Instruction& inst10 = *iter;
  const _DInst& representation10 = inst10.representation();
  EXPECT_EQ(I_MOV, representation10.opcode);
  ASSERT_EQ(O_IMM, representation10.ops[1].type);
  ASSERT_EQ(32, representation10.ops[1].size);
  ASSERT_NE(++iter, end);
  const uint32_t rand_id = representation10.imm.dword;

  if (afl.multithread_) {
    // xor ebx, [ecx]
    const Instruction& inst11 = *iter;
    EXPECT_EQ(I_XOR, inst11.representation().opcode);
    ASSERT_NE(++iter, end);
  } else {
    // xor ebx, [afl_prev_loc]
    const Instruction& inst12 = *iter;
    EXPECT_EQ(I_XOR, inst12.representation().opcode);
    const auto& references12 = inst12.references();
    EXPECT_EQ(1, references12.size());
    const BasicBlockReference& blockref12 = references12.cbegin()->second;
    EXPECT_EQ(AFLTransform::kOffsetPrevLoc, blockref12.offset());
    EXPECT_EQ(AFLTransform::kMetadataBlockName, blockref12.block()->name());
    EXPECT_EQ(afl.afl_static_cov_data_, blockref12.block());
    ASSERT_NE(++iter, end);
  }

  // add ebx, [afl_area_ptr]
  const Instruction& inst13 = *iter;
  EXPECT_EQ(I_ADD, inst13.representation().opcode);
  const auto& references13 = inst13.references();
  EXPECT_EQ(1, references13.size());
  const BasicBlockReference& blockref13 = references13.cbegin()->second;
  EXPECT_EQ(AFLTransform::kOffsetAreaPtr, blockref13.offset());
  EXPECT_EQ(AFLTransform::kMetadataBlockName, blockref13.block()->name());
  EXPECT_EQ(afl.afl_static_cov_data_, blockref13.block());
  ASSERT_NE(++iter, end);

  // inc byte [ebx]
  const Instruction& inst14 = *iter;
  EXPECT_EQ(I_INC, inst14.representation().opcode);
  ASSERT_NE(++iter, end);

  const Instruction& inst15 = *iter;
  const _DInst& representation15 = inst15.representation();
  EXPECT_EQ(I_MOV, representation15.opcode);

  if (afl.multithread_) {
    // mov [ecx], id >> 1
  } else {
    // mov [afl_prev_loc], id >> 1
    const auto& references15 = inst15.references();
    EXPECT_EQ(1, references15.size());
    const BasicBlockReference& blockref12 = references15.cbegin()->second;
    EXPECT_EQ(AFLTransform::kOffsetPrevLoc, blockref12.offset());
    EXPECT_EQ(AFLTransform::kMetadataBlockName, blockref12.block()->name());
    EXPECT_EQ(afl.afl_static_cov_data_, blockref12.block());
  }

  EXPECT_EQ(O_IMM, representation15.ops[1].type);
  EXPECT_EQ(32, representation15.ops[1].size);
  EXPECT_EQ(rand_id >> 1, representation15.imm.dword);
  ASSERT_NE(++iter, end);

  // add al, 0x7F
  const Instruction& inst16 = *iter;
  const _DInst& representation16 = inst16.representation();
  EXPECT_EQ(I_ADD, representation16.opcode);
  EXPECT_EQ(8, representation16.ops[1].size);
  EXPECT_EQ(0x7F, representation16.imm.byte);
  ASSERT_NE(++iter, end);

  // sahf
  const Instruction& inst17 = *iter;
  EXPECT_EQ(I_SAHF, inst17.representation().opcode);
  ASSERT_NE(++iter, end);

  if (afl.multithread_) {
    // pop ecx
    const Instruction& inst18 = *iter;
    EXPECT_EQ(I_POP, inst18.representation().opcode);
    ASSERT_NE(++iter, end);
  }

  // pop ebx
  const Instruction& inst19 = *iter;
  EXPECT_EQ(I_POP, inst19.representation().opcode);
  ASSERT_NE(++iter, end);

  // pop eax
  const Instruction& inst20 = *iter;
  EXPECT_EQ(I_POP, inst20.representation().opcode);
}

void AFLTransformTest::CheckBasicBlockInstrumentation(TestAFLTransform& afl) {
  // Let's examine each eligible block to verify that its basic blocks have been
  // instrumented.
  BlockGraph::BlockMap::const_iterator block_iter =
      block_graph_.blocks().begin();
  for (; block_iter != block_graph_.blocks().end(); ++block_iter) {
    const BlockGraph::Block& block = block_iter->second;

    // Skip non-code blocks.
    if (block.type() != BlockGraph::CODE_BLOCK) {
      continue;
    }

    // Skip non-decomposable blocks.
    if (!policy_->BlockIsSafeToBasicBlockDecompose(&block)) {
      continue;
    }

    if (afl.targets_visited_.size() != 0) {
      bool hit = false;
      for (const auto& target : afl.targets_visited_) {
        if (block.name() == target.first) {
          hit = true;
          break;
        }
      }

      // In whitelist mode, if we don't have a hit we skip the block.
      // In blacklist mode, if we have a hit we skip the block.
      if ((afl.whitelist_mode_ && !hit) || (!afl.whitelist_mode_ && hit)) {
        continue;
      }
    }

    // Decompose the block to basic-blocks.
    BasicBlockSubGraph subgraph;
    BasicBlockDecomposer bb_decomposer(&block, &subgraph);
    ASSERT_TRUE(bb_decomposer.Decompose());

    // Retrieve the first basic block.
    ASSERT_EQ(1, subgraph.block_descriptions().size());
    const BasicBlockSubGraph::BasicBlockOrdering& original_order =
        subgraph.block_descriptions().front().basic_block_order;
    BasicCodeBlock* first_bb = BasicCodeBlock::Cast(*original_order.begin());
    ASSERT_NE(first_bb, nullptr);

    // Check if each non-padding basic code-block begins with the
    // instrumentation sequence.
    BasicBlockSubGraph::BBCollection::const_iterator bb_iter =
        subgraph.basic_blocks().begin();

    for (; bb_iter != subgraph.basic_blocks().end(); ++bb_iter) {
      const BasicCodeBlock* bb = BasicCodeBlock::Cast(*bb_iter);
      if (bb == nullptr || bb->is_padding()) {
        continue;
      }

      BasicBlock::Instructions::const_iterator inst_iter =
                                                   bb->instructions().begin(),
                                               end_iter =
                                                   bb->instructions().end();
      ASSERT_NE(inst_iter, end_iter);
      CheckInstrumentation(inst_iter, end_iter, afl);
    }
  }
}

}  // namespace

TEST_F(AFLTransformTest, ApplyTranform) {
  ASSERT_NO_FATAL_FAILURE(DecomposeTestDll());

  TestAFLTransform afl({},     // targets
                       false,  // whitelist_mode
                       false,  // force_decompose
                       false,  // multithread
                       false   // cookie_check_hook
                       );

  ASSERT_TRUE(block_graph::ApplyBlockGraphTransform(
      &afl, policy_, &block_graph_, header_block_));

  size_t instrumentation_percentage =
      (afl.total_code_blocks_instrumented_ * 100) / afl.total_code_blocks_;

  EXPECT_LT(70, instrumentation_percentage);

  ASSERT_NO_FATAL_FAILURE(CheckBasicBlockInstrumentation(afl));
}

TEST_F(AFLTransformTest, ApplyTranformMultithread) {
  ASSERT_NO_FATAL_FAILURE(DecomposeTestDll());

  TestAFLTransform afl_mt({},     // targets
                          false,  // whitelist_mode
                          false,  // force_decompose
                          true,   // multithread
                          false   // cookie_check_hook
                          );

  ASSERT_TRUE(block_graph::ApplyBlockGraphTransform(
      &afl_mt, policy_, &block_graph_, header_block_));

  size_t instrumentation_percentage =
      (afl_mt.total_code_blocks_instrumented_ * 100) /
      afl_mt.total_code_blocks_;

  EXPECT_LT(70, instrumentation_percentage);

  ASSERT_NO_FATAL_FAILURE(CheckBasicBlockInstrumentation(afl_mt));
}

TEST_F(AFLTransformTest, ApplyTranformWhitelist) {
  ASSERT_NO_FATAL_FAILURE(DecomposeTestDll());

  TestAFLTransform afl_whitelist(
      {"fuzzme", "pattern1", "_pattern2", "Unused::M"},  // targets
      true,                                              // whitelist_mode
      false,                                             // force_decompose
      false,                                             // multithread
      false                                              // cookie_check_hook
      );

  ASSERT_TRUE(block_graph::ApplyBlockGraphTransform(
      &afl_whitelist, policy_, &block_graph_, header_block_));

  EXPECT_EQ(1, afl_whitelist.total_code_blocks_instrumented_);

  EXPECT_FALSE(afl_whitelist.targets_visited_["fuzzme"]);
  EXPECT_FALSE(afl_whitelist.targets_visited_["pattern1"]);
  EXPECT_FALSE(afl_whitelist.targets_visited_["_pattern2"]);
  EXPECT_TRUE(afl_whitelist.targets_visited_["Unused::M"]);

  ASSERT_NO_FATAL_FAILURE(CheckBasicBlockInstrumentation(afl_whitelist));
}

TEST_F(AFLTransformTest, ApplyTranformBlacklist) {
  ASSERT_NO_FATAL_FAILURE(DecomposeTestDll());

  TestAFLTransform afl_blacklist(
      {"fuzzme", "pattern1", "_pattern2", "Unused::M"},  // targets
      false,                                             // whitelist_mode
      false,                                             // force_decompose
      false,                                             // multithread
      false                                              // cookie_check_hook
      );

  ASSERT_TRUE(block_graph::ApplyBlockGraphTransform(
      &afl_blacklist, policy_, &block_graph_, header_block_));

  size_t instrumentation_percentage =
      (afl_blacklist.total_code_blocks_instrumented_ * 100) /
      afl_blacklist.total_code_blocks_;

  EXPECT_LT(70, instrumentation_percentage);

  EXPECT_EQ(0, afl_blacklist.targets_visited_["fuzzme"]);
  EXPECT_EQ(0, afl_blacklist.targets_visited_["pattern1"]);
  EXPECT_EQ(0, afl_blacklist.targets_visited_["_pattern2"]);
  EXPECT_EQ(1, afl_blacklist.targets_visited_["Unused::M"]);

  ASSERT_NO_FATAL_FAILURE(CheckBasicBlockInstrumentation(afl_blacklist));
}

}  // namespace transforms
}  // namespace instrument
