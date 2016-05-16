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

#include "syzygy/instrument/transforms/filler_transform.h"

#include <memory>
#include <vector>

#include "gtest/gtest.h"
#include "syzygy/assm/assembler_base.h"
#include "syzygy/block_graph/basic_block.h"
#include "syzygy/block_graph/basic_block_assembler.h"
#include "syzygy/block_graph/basic_block_subgraph.h"
#include "syzygy/block_graph/basic_block_test_util.h"
#include "syzygy/block_graph/block_graph.h"
#include "syzygy/instrument/transforms/unittest_util.h"

namespace instrument {
namespace transforms {

namespace {

using block_graph::BasicBlock;
using block_graph::BlockGraph;
using block_graph::BasicCodeBlock;

const char kNopName[] = "NOP";

// Finds instruction indices and sizes of every NOP in @p instructions and
// stores the result in @p nop_indices. Returns the @p instructions count.
size_t FindAllNops(BasicBlock::Instructions* instructions,
                   std::map<size_t, int>* nop_indices) {
  size_t index = 0LL;
  BasicBlock::Instructions::iterator inst_it = instructions->begin();
  for (; inst_it != instructions->end(); ++inst_it, ++index) {
    if (!::strcmp(inst_it->GetName(), kNopName))
      (*nop_indices)[index] = inst_it->size();
  }
  return index;
}

class FillerBasicBlockTransformTest : public testing::Test {
 public:
  typedef testing::Test Super;
  typedef FillerBasicBlockTransform::NopSizes NopSizes;
  typedef FillerBasicBlockTransform::NopSpec NopSpec;

  // Creates a new length @p n instruction list for testing.
  void CreateInstructions(int n) {
    using assm::eax;
    using assm::ebp;
    using assm::esp;
    using assm::kSize32Bit;

    instructions_.reset(new BasicBlock::Instructions);
    if (n == 0)
      return;

    block_graph::BasicBlockAssembler
        assm(instructions_->begin(), instructions_.get());
    bool setup_stack = false;
    --n;  // Reserve for ret.
    if (n > 3) {
      setup_stack = true;
      n -= 3;  // Reserve for stack frame setup.
    }
    if (setup_stack) {
      assm.push(ebp);
      assm.mov(ebp, esp);
    }
    for (; n > 0; --n)
      assm.mov(eax, block_graph::Immediate(n, kSize32Bit));
    if (setup_stack)
      assm.pop(ebp);
    assm.ret(0);
  }

 protected:
  std::unique_ptr<BasicBlock::Instructions> instructions_;
};

class TestFillerTransform : public FillerTransform {
 public:
  TestFillerTransform(const std::set<std::string>& target_set,
                      bool add_copy)
      : FillerTransform(target_set, add_copy) { }
};

class FillerTransformTest : public testing::TestDllTransformTest {
 public:
  typedef testing::TestDllTransformTest Super;
  typedef BlockGraph::Block::SourceRange SourceRange;

  // Finds all blocks whose names appear in @p target_set, and writes the
  // mapping fron name to block in @p result.
  void FindAllBlocks(
      const std::set<std::string>& target_set,
      std::map<std::string, BlockGraph::Block*>* result) {
    DCHECK(result && result->empty());
    std::set<std::string> targets_remaining(target_set);
    for (auto& it : block_graph_.blocks_mutable()) {
      std::string block_name = it.second.name();
      if (targets_remaining.find(block_name) != targets_remaining.end()) {
        (*result)[block_name] = &it.second;
        targets_remaining.erase(block_name);
      }
    }
  }

  // Verifies that @p instructions contains all expected NOPs except for NOPs
  // that would be inserted beyond the last instruction.
  static void CheckNops(BasicBlock::Instructions* instructions) {
    std::map<size_t, int> nop_indices;
    size_t num_inst = FindAllNops(instructions, &nop_indices);
    // The checks here depend on how NopSpec is initialized in
    // FillerBasicBlockTransform! Currently we add NOP after every original
    // instruction, except for the last. So check every odd index for NOP.
    EXPECT_EQ(num_inst / 2, nop_indices.size());
    size_t expected_idx = 1;
    for (const auto& it : nop_indices) {
      EXPECT_EQ(expected_idx, it.first);
      EXPECT_EQ(1, it.second);  // NOP1.
      expected_idx += 2;
    }
  }

  // Verifies that all contiguous NOPs in @p instuctions are followed by a
  // non-NOP instruction, which shares the same source range as the NOP run.
  static void CheckNopSourceRange(BasicBlock::Instructions* instructions) {
    std::vector<SourceRange> range_queue;
    BasicBlock::Instructions::iterator inst_it = instructions->begin();
    for (; inst_it != instructions->end(); ++inst_it) {
      if (!::strcmp(inst_it->GetName(), kNopName)) {
        // Found NOP: add to queue.
        range_queue.push_back(inst_it->source_range());
      } else {
        // Found non-NOP: verify stored ranges in the queue and then clear it.
        for (SourceRange& nop_source_range : range_queue) {
          EXPECT_EQ(inst_it->source_range(), nop_source_range);
        }
        range_queue.clear();
      }
    }
    // Expect there's no trailing NOP.
    EXPECT_TRUE(range_queue.empty());
  }

  // Applies the Filler Transform to specified @p target_set, and adds copy iff
  // @p add_copy is true. Verifies that the transform is successful.
  void ApplyFillerTransform(const std::set<std::string> target_set,
                            bool add_copy) {
    ASSERT_NO_FATAL_FAILURE(DecomposeTestDll());

    // Apply the Filler Transform.
    TestFillerTransform tx(target_set, add_copy);
    tx.set_debug_friendly(true);  // Copy source ranges to injected NOPs.
    ASSERT_TRUE(block_graph::ApplyBlockGraphTransform(
        &tx, policy_, &block_graph_, header_block_));

    // Find and store target blocks for later verification.
    EXPECT_EQ(target_set.size(), tx.num_targets_updated());
    std::map<std::string, BlockGraph::Block*> target_map;
    FindAllBlocks(target_set, &target_map);
    EXPECT_EQ(target_set.size(), target_map.size());

    // Verify that each target has been properly modified.
    for (auto& it : target_map) {
      BlockGraph::Block* target_block = it.second;

      // Decompose target block to subgraph.
      block_graph::BasicBlockSubGraph subgraph;
      block_graph::BasicBlockDecomposer bb_decomposer(target_block, &subgraph);
      ASSERT_TRUE(bb_decomposer.Decompose());

      // For each basic code block, verify that NOPs are properly placed.
      block_graph::BasicBlockSubGraph::BBCollection& basic_blocks =
          subgraph.basic_blocks();
      for (auto bb = basic_blocks.begin(); bb != basic_blocks.end(); ++bb) {
        BasicCodeBlock* bc_block = BasicCodeBlock::Cast(*bb);
        if (bc_block != nullptr) {
          CheckNops(&bc_block->instructions());
          CheckNopSourceRange(&bc_block->instructions());
        }
      }
    }
  }

  void ApplyFillerTransformTest(bool add_copy) {
    std::set<std::string> targets = {
      "Used::M",
      "TestUnusedFuncs"
    };

    ASSERT_NO_FATAL_FAILURE(ApplyFillerTransform(targets, add_copy));

    // Expect original targets to remain, and with copies if |add_copy|.
    std::set<std::string> targets_with_copies(targets);
    for (const auto& target : targets)
      targets_with_copies.insert(target + "_copy");
    std::set<std::string> expected_results(
        add_copy ? targets_with_copies : targets);

    // Search for original targets + copies, verify match with expected results.
    std::map<std::string, BlockGraph::Block*> results;
    FindAllBlocks(targets_with_copies, &results);
    EXPECT_EQ(expected_results.size(), results.size());
    for (const std::string target : expected_results)
      EXPECT_NE(results.end(), results.find(target)) << target << " not found.";
  }
};

}  // namespace

// Sanity check for helper CreateInstructions().
TEST_F(FillerBasicBlockTransformTest, CreateInstructions) {
  for (int i = 0; i < 10; ++i) {
    CreateInstructions(i);
    size_t count = 0;
    for (auto inst : *instructions_.get())
      ++count;
    EXPECT_EQ(i, count);
  }
}

TEST_F(FillerBasicBlockTransformTest, InjectRegular) {
  CreateInstructions(8);
  NopSpec nop_spec = {
    {1, NopSizes::NOP3},
    {2, NopSizes::NOP1},
    {3, NopSizes::NOP4},
    {6, NopSizes::NOP1},
    {8, NopSizes::NOP5},
    {9, NopSizes::NOP9}};
  FillerBasicBlockTransform::InjectNop(nop_spec, false, instructions_.get());
  std::map<size_t, int> nop_indices;
  EXPECT_EQ(8U + 6U, FindAllNops(instructions_.get(), &nop_indices));
  EXPECT_EQ(6U, nop_indices.size());
  EXPECT_EQ(3U, nop_indices[1]);
  EXPECT_EQ(1U, nop_indices[2]);
  EXPECT_EQ(4U, nop_indices[3]);
  EXPECT_EQ(1U, nop_indices[6]);
  EXPECT_EQ(5U, nop_indices[8]);
  EXPECT_EQ(9U, nop_indices[9]);
}

TEST_F(FillerBasicBlockTransformTest, InjectToStart) {
  CreateInstructions(5);
  NopSpec nop_spec1 = {{0, NopSizes::NOP4}};
  FillerBasicBlockTransform::InjectNop(nop_spec1, false, instructions_.get());
  std::map<size_t, int> nop_indices1;
  EXPECT_EQ(5U + 1U, FindAllNops(instructions_.get(), &nop_indices1));
  EXPECT_EQ(1U, nop_indices1.size());
  EXPECT_EQ(4U, nop_indices1[0]);

  // Inject another NOP, when a NOP already exists.
  NopSpec nop_spec2 = {{0, NopSizes::NOP1}};
  FillerBasicBlockTransform::InjectNop(nop_spec2, false, instructions_.get());
  std::map<size_t, int> nop_indices2;
  EXPECT_EQ(5U + 1U + 1U, FindAllNops(instructions_.get(), &nop_indices2));
  EXPECT_EQ(2U, nop_indices2.size());  // New + existing.
  EXPECT_EQ(1U, nop_indices2[0]);  // From |nop_spec2|.
  EXPECT_EQ(4U, nop_indices2[1]);  // From |nop_spec1|.
}

TEST_F(FillerBasicBlockTransformTest, InjectToBeforeEnd) {
  CreateInstructions(7);
  NopSpec nop_spec = {{6, NopSizes::NOP2}};
  FillerBasicBlockTransform::InjectNop(nop_spec, false, instructions_.get());
  std::map<size_t, int> nop_indices;
  EXPECT_EQ(7U + 1U, FindAllNops(instructions_.get(), &nop_indices));
  EXPECT_EQ(1U, nop_indices.size());
  EXPECT_EQ(2U, nop_indices[6]);
}

TEST_F(FillerBasicBlockTransformTest, CannotInjectBeyondEnd) {
  CreateInstructions(7);
  NopSpec nop_spec = {{7, NopSizes::NOP1}, {17, NopSizes::NOP1}};
  FillerBasicBlockTransform::InjectNop(nop_spec, false, instructions_.get());
  std::map<size_t, int> nop_indices;
  EXPECT_EQ(7U, FindAllNops(instructions_.get(), &nop_indices));
  EXPECT_EQ(0U, nop_indices.size());
}

TEST_F(FillerBasicBlockTransformTest, InjectToEmpty) {
  CreateInstructions(0);
  NopSpec nop_spec = {{0, NopSizes::NOP1}, {1, NopSizes::NOP2}};
  FillerBasicBlockTransform::InjectNop(nop_spec, false, instructions_.get());
  std::map<size_t, int> nop_indices;
  EXPECT_EQ(0U, FindAllNops(instructions_.get(), &nop_indices));
  EXPECT_EQ(0U, nop_indices.size());
}

TEST_F(FillerBasicBlockTransformTest, InjectToSingle) {
  CreateInstructions(1);
  NopSpec nop_spec = {
    {0, NopSizes::NOP5},
    {1, NopSizes::NOP8},
    {3, NopSizes::NOP2}};  // Gets ignored.
  FillerBasicBlockTransform::InjectNop(nop_spec, false, instructions_.get());
  std::map<size_t, int> nop_indices;
  EXPECT_EQ(1U + 2U, FindAllNops(instructions_.get(), &nop_indices));
  EXPECT_EQ(2U, nop_indices.size());
  EXPECT_EQ(5U, nop_indices[0]);
  EXPECT_EQ(8U, nop_indices[1]);
}

TEST_F(FillerBasicBlockTransformTest, InjectNone) {
  CreateInstructions(7);
  NopSpec nop_spec = {};
  FillerBasicBlockTransform::InjectNop(nop_spec, false, instructions_.get());
  std::map<size_t, int> nop_indices;
  EXPECT_EQ(7U, FindAllNops(instructions_.get(), &nop_indices));
  EXPECT_EQ(0U, nop_indices.size());
}

TEST_F(FillerBasicBlockTransformTest, InjectConsecutive) {
  CreateInstructions(4);
  NopSpec nop_spec = {
      {0, NopSizes::NOP1},
      {1, NopSizes::NOP2},
      {2, NopSizes::NOP3},
      {3, NopSizes::NOP5},
      {4, NopSizes::NOP7},
      {5, NopSizes::NOP11}};
  FillerBasicBlockTransform::InjectNop(nop_spec, false, instructions_.get());
  std::map<size_t, int> nop_indices;
  EXPECT_EQ(4U + 6U, FindAllNops(instructions_.get(), &nop_indices));
  EXPECT_EQ(6U, nop_indices.size());
  EXPECT_EQ(1U, nop_indices[0]);
  EXPECT_EQ(2U, nop_indices[1]);
  EXPECT_EQ(3U, nop_indices[2]);
  EXPECT_EQ(5U, nop_indices[3]);
  EXPECT_EQ(7U, nop_indices[4]);
  EXPECT_EQ(11U, nop_indices[5]);
}

TEST_F(FillerBasicBlockTransformTest, InjectAlternate) {
  CreateInstructions(4);
  NopSpec nop_spec = {
      {0, NopSizes::NOP10},
      {2, NopSizes::NOP9},
      {4, NopSizes::NOP8},
      {6, NopSizes::NOP7},
      {8, NopSizes::NOP6},  // Gets ignored.
      {10, NopSizes::NOP5}};  // Gets ignored.
  FillerBasicBlockTransform::InjectNop(nop_spec, false, instructions_.get());
  std::map<size_t, int> nop_indices;
  EXPECT_EQ(4U + 4U, FindAllNops(instructions_.get(), &nop_indices));
  EXPECT_EQ(4U, nop_indices.size());
  EXPECT_EQ(10U, nop_indices[0]);
  EXPECT_EQ(9U, nop_indices[2]);
  EXPECT_EQ(8U, nop_indices[4]);
  EXPECT_EQ(7U, nop_indices[6]);
}

TEST_F(FillerTransformTest, Apply) {
  ASSERT_NO_FATAL_FAILURE(ApplyFillerTransformTest(true));
}

TEST_F(FillerTransformTest, ApplyNoAddCopy) {
  ASSERT_NO_FATAL_FAILURE(ApplyFillerTransformTest(false));
}

}  // namespace transforms
}  // namespace instrument
