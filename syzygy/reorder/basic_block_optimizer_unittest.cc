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

#include "syzygy/reorder/basic_block_optimizer.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/block_graph/basic_block_test_util.h"
#include "syzygy/block_graph/block_graph.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/pe_utils.h"
#include "syzygy/reorder/order_generator_test.h"

#include "mnemonics.h"  // NOLINT

namespace reorder {
namespace {

using block_graph::BasicBlock;
using block_graph::BasicCodeBlock;
using block_graph::BasicDataBlock;
using block_graph::BlockGraph;
using core::RelativeAddress;
using grinder::basic_block_util::EntryCountType;
using grinder::basic_block_util::IndexedFrequencyInformation;
using grinder::basic_block_util::IndexedFrequencyMap;
using grinder::basic_block_util::LoadBasicBlockRanges;
using grinder::basic_block_util::RelativeAddressRange;
using grinder::basic_block_util::RelativeAddressRangeVector;
using pe::ImageLayout;
using testing::GetExeTestDataRelativePath;

typedef Reorderer::Order Order;

class TestBasicBlockOrderer : public BasicBlockOptimizer::BasicBlockOrderer {
 public:
  using BasicBlockOptimizer::BasicBlockOrderer::GetBasicBlockEntryCount;
  using BasicBlockOptimizer::BasicBlockOrderer::GetWarmestSuccessor;
  using BasicBlockOptimizer::BasicBlockOrderer::GetSortedJumpTargets;
  using BasicBlockOptimizer::BasicBlockOrderer::AddRecursiveDataReferences;
  using BasicBlockOptimizer::BasicBlockOrderer::AddWarmDataReferences;

  TestBasicBlockOrderer(
      const BasicBlockSubGraph& subgraph,
      const RelativeAddress& addr,
      Size size,
      const IndexedFrequencyInformation& entry_counts)
          : BasicBlockOptimizer::BasicBlockOrderer(
                subgraph, addr, size, entry_counts) {
  }
};

class BasicBlockOrdererTest : public testing::BasicBlockTest {
 public:
  virtual void SetUp() OVERRIDE {
    ASSERT_NO_FATAL_FAILURE(testing::BasicBlockTest::SetUp());
    ASSERT_NO_FATAL_FAILURE(InitBlockGraph());
    ASSERT_NO_FATAL_FAILURE(InitBasicBlockSubGraph());
    ASSERT_NO_FATAL_FAILURE(SetEntryCounts(0, 0, 0, 0, 0, 0, 0, 0));
    orderer_.reset(new TestBasicBlockOrderer(subgraph_,
                                             start_addr_,
                                             assembly_func_->size(),
                                             entry_counts_));
    ASSERT_TRUE(orderer_.get() != NULL);
  }

  RelativeAddressRange MakeRange(BlockGraph::Offset offset,
                                 BlockGraph::Size size) {
    return RelativeAddressRange(start_addr_ + offset, size);
  }

  BasicBlock* FindBasicBlockAt(BlockGraph::Offset offset) {
    typedef BasicBlockSubGraph::BBCollection BBCollection;
    BasicBlockSubGraph::BBCollection::iterator it =
        subgraph_.basic_blocks().begin();
    for (; it != subgraph_.basic_blocks().end(); ++it) {
      if ((*it)->offset() == offset)
        return *it;
    }
    return NULL;
  }

  void SetEntryCounts(uint32 bb0, uint32 bb1, uint32 bb2, uint32 bb3,
                      uint32 bb4, uint32 bb5, uint32 bb6, uint32 bb7) {
    entry_counts_.num_entries = kNumCodeBasicBlocks;
    entry_counts_.num_columns = 1;
    entry_counts_.data_type =
        ::common::IndexedFrequencyData::BASIC_BLOCK_ENTRY;
    entry_counts_.frequency_size = 4;

    IndexedFrequencyMap& frequency_map = entry_counts_.frequency_map;
    frequency_map.clear();

    uint32 start = start_addr_.value();
    frequency_map[std::make_pair(start_addr_ + kBasicBlockOffsets[0], 0)] = bb0;
    frequency_map[std::make_pair(start_addr_ + kBasicBlockOffsets[1], 0)] = bb1;
    frequency_map[std::make_pair(start_addr_ + kBasicBlockOffsets[2], 0)] = bb2;
    frequency_map[std::make_pair(start_addr_ + kBasicBlockOffsets[3], 0)] = bb3;
    frequency_map[std::make_pair(start_addr_ + kBasicBlockOffsets[4], 0)] = bb4;
    frequency_map[std::make_pair(start_addr_ + kBasicBlockOffsets[5], 0)] = bb5;
    frequency_map[std::make_pair(start_addr_ + kBasicBlockOffsets[6], 0)] = bb6;
    frequency_map[std::make_pair(start_addr_ + kBasicBlockOffsets[7], 0)] = bb7;
    ASSERT_EQ(kNumCodeBasicBlocks, frequency_map.size());
  }

  static const size_t kBasicBlockOffsets[kNumCodeBasicBlocks];

  IndexedFrequencyInformation entry_counts_;
  scoped_ptr<TestBasicBlockOrderer> orderer_;
};

const size_t BasicBlockOrdererTest::kBasicBlockOffsets[kNumCodeBasicBlocks] =
    { 0, 23, 24, 31, 36, 37, 42, 49 };

class BasicBlockOptimizerTest : public testing::OrderGeneratorTest {
 public:
  typedef testing::OrderGeneratorTest Super;

  BasicBlockOptimizerTest()
      : num_decomposable_blocks_(0),
        num_non_decomposable_blocks_(0),
        num_non_code_blocks_(0) {
  }

  virtual void SetUp() OVERRIDE {
    ASSERT_NO_FATAL_FAILURE(Super::SetUp());
    ASSERT_NO_FATAL_FAILURE(InitBlockCounts());
    base::FilePath pdb_path(GetExeTestDataRelativePath(
        testing::kBBEntryInstrumentedTestDllPdbName));
  }

  void InitBlockCounts() {
    ASSERT_EQ(0U, num_decomposable_blocks_);
    ASSERT_EQ(0U, num_non_decomposable_blocks_);
    ASSERT_EQ(0U, num_non_code_blocks_);

    for (size_t i = 0; i < image_layout_.sections.size(); ++i) {
      const ImageLayout::SectionInfo& section_info = image_layout_.sections[i];
      BlockGraph::AddressSpace::RangeMapConstIterPair ip =
          image_layout_.blocks.GetIntersectingBlocks(section_info.addr,
                                                     section_info.size);
      for (; ip.first != ip.second; ++ip.first) {
        const BlockGraph::Block* block = ip.first->second;
        if (block->type() != BlockGraph::CODE_BLOCK) {
          ++num_non_code_blocks_;
        } else if (policy_.BlockIsSafeToBasicBlockDecompose(block)) {
          ++num_decomposable_blocks_;
        } else {
          ++num_non_decomposable_blocks_;
        }
      }
    }
  }

  bool FindBlockByName(const base::StringPiece& name,
                       const BlockGraph::Block** block,
                       BlockGraph::AddressSpace::Range* range) {
    DCHECK(block != NULL);
    DCHECK(range != NULL);
    BlockGraph::AddressSpace::RangeMapConstIter it =
        image_layout_.blocks.begin();
    for (; it != image_layout_.blocks.end(); ++it) {
      if (it->second->name() == name) {
        *range = it->first;
        *block = it->second;
        return true;
      }
    }
    return false;
  }

 protected:
  pe::PETransformPolicy policy_;
  BasicBlockOptimizer optimizer_;
  size_t num_decomposable_blocks_;
  size_t num_non_decomposable_blocks_;
  size_t num_non_code_blocks_;
};

}  // namespace

TEST_F(BasicBlockOrdererTest, GetBlockEntryCount) {
  ASSERT_NO_FATAL_FAILURE(SetEntryCounts(1, 0, 1, 5, 1, 0, 0, 0));
  EntryCountType entry_count = 0;
  EXPECT_TRUE(orderer_->GetBlockEntryCount(&entry_count));
  EXPECT_EQ(1U, entry_count);

  ASSERT_NO_FATAL_FAILURE(SetEntryCounts(17, 0, 1, 5, 1, 0, 0, 0));
  EXPECT_TRUE(orderer_->GetBlockEntryCount(&entry_count));
  EXPECT_EQ(17U, entry_count);
}

TEST_F(BasicBlockOrdererTest, GetWarmestSuccessor) {
  const BasicCodeBlock* sub = BasicCodeBlock::Cast(FindBasicBlockAt(31));
  ASSERT_TRUE(sub != NULL);

  const BasicCodeBlock* ret = BasicCodeBlock::Cast(FindBasicBlockAt(36));
  ASSERT_TRUE(ret != NULL);

  TestBasicBlockOrderer::BasicBlockSet placed_bbs;
  const BasicBlock* succ = NULL;

  // Make the fall-through as the warmest successor.
  ASSERT_NO_FATAL_FAILURE(SetEntryCounts(0, 0, 0, 5, 10, 0, 0, 0));
  ASSERT_TRUE(orderer_->GetWarmestSuccessor(sub, placed_bbs, &succ));
  ASSERT_EQ(ret, succ);

  // Make the branch taken as the warmest successor.
  succ = NULL;
  ASSERT_NO_FATAL_FAILURE(SetEntryCounts(0, 0, 0, 10, 5, 0, 0, 0));
  ASSERT_TRUE(orderer_->GetWarmestSuccessor(sub, placed_bbs, &succ));
  ASSERT_EQ(sub, succ);

  // Give both branches the same warmth. Should preserve ordering.
  succ = NULL;
  ASSERT_NO_FATAL_FAILURE(SetEntryCounts(0, 0, 0, 10, 10, 0, 0, 0));
  ASSERT_TRUE(orderer_->GetWarmestSuccessor(sub, placed_bbs, &succ));
  ASSERT_EQ(ret, succ);

  // Let the warmest branch already be placed, should return the other branch.
  succ = NULL;
  placed_bbs.insert(ret);
  ASSERT_NO_FATAL_FAILURE(SetEntryCounts(0, 0, 0, 5, 10, 0, 0, 0));
  ASSERT_TRUE(orderer_->GetWarmestSuccessor(sub, placed_bbs, &succ));
  ASSERT_EQ(sub, succ);

  // Let the warmest branch already be placed, should return the other branch.
  // Note that we initialize succ to non NULL to verify that it becomes NULL.
  succ = sub;
  placed_bbs.insert(sub);
  placed_bbs.insert(ret);
  ASSERT_NO_FATAL_FAILURE(SetEntryCounts(0, 0, 0, 5, 10, 0, 0, 0));
  ASSERT_TRUE(orderer_->GetWarmestSuccessor(sub, placed_bbs, &succ));
  ASSERT_EQ(NULL, succ);
}

TEST_F(BasicBlockOrdererTest, AddWarmDataReferences) {
  // Get basic block pointers to the switch, jump table, and case table.
  const BasicCodeBlock* code_bb = BasicCodeBlock::Cast(FindBasicBlockAt(0));
  const BasicDataBlock* jump_table = BasicDataBlock::Cast(FindBasicBlockAt(52));
  const BasicDataBlock* case_table = BasicDataBlock::Cast(FindBasicBlockAt(64));
  ASSERT_TRUE(code_bb != NULL);
  ASSERT_TRUE(jump_table != NULL);
  ASSERT_TRUE(case_table != NULL);

  // Capture the references from the switch basic block (offset 0).
  TestBasicBlockOrderer::BasicBlockSet references;
  ASSERT_TRUE(orderer_->AddWarmDataReferences(code_bb, &references));
  EXPECT_EQ(2U, references.size());
  EXPECT_EQ(1U, references.count(jump_table));
  EXPECT_EQ(1U, references.count(case_table));

  // Capture the references from the case_0 basic block (offset 24).
  references.clear();
  code_bb = BasicCodeBlock::Cast(FindBasicBlockAt(24));
  ASSERT_TRUE(orderer_->AddWarmDataReferences(code_bb, &references));
  EXPECT_TRUE(references.empty());
}

TEST_F(BasicBlockOrdererTest, GetSortedJumpTargets) {
  ASSERT_NO_FATAL_FAILURE(SetEntryCounts(0, 0, 2, 0, 0, 1, 3, 0));
  const BasicCodeBlock* first_bb = BasicCodeBlock::Cast(FindBasicBlockAt(0));
  ASSERT_TRUE(first_bb->successors().empty());
  ASSERT_TRUE(!first_bb->instructions().empty());
  const block_graph::Instruction& jmp_inst = first_bb->instructions().back();
  ASSERT_EQ(I_JMP, jmp_inst.representation().opcode);
  logging::SetMinLogLevel(-1);
  std::vector<const BasicCodeBlock*> targets;
  ASSERT_TRUE(orderer_->GetSortedJumpTargets(jmp_inst, &targets));
  ASSERT_THAT(targets,
              testing::ElementsAre(
                  BasicCodeBlock::Cast(FindBasicBlockAt(42)),
                  BasicCodeBlock::Cast(FindBasicBlockAt(24)),
                  BasicCodeBlock::Cast(FindBasicBlockAt(37))));
}

TEST_F(BasicBlockOrdererTest, GetStableSortedJumpTargets) {
  ASSERT_NO_FATAL_FAILURE(SetEntryCounts(0, 0, 1, 0, 0, 2, 1, 0));
  const BasicCodeBlock* first_bb = BasicCodeBlock::Cast(FindBasicBlockAt(0));
  ASSERT_TRUE(first_bb->successors().empty());
  ASSERT_TRUE(!first_bb->instructions().empty());
  const block_graph::Instruction& jmp_inst = first_bb->instructions().back();
  ASSERT_EQ(I_JMP, jmp_inst.representation().opcode);
  logging::SetMinLogLevel(-1);
  std::vector<const BasicCodeBlock*> targets;
  ASSERT_TRUE(orderer_->GetSortedJumpTargets(jmp_inst, &targets));
  ASSERT_THAT(targets,
              testing::ElementsAre(
                  BasicCodeBlock::Cast(FindBasicBlockAt(37)),
                  BasicCodeBlock::Cast(FindBasicBlockAt(24)),
                  BasicCodeBlock::Cast(FindBasicBlockAt(42))));
}

TEST_F(BasicBlockOrdererTest, HotColdSeparation) {
  ASSERT_NO_FATAL_FAILURE(SetEntryCounts(1, 0, 1, 5, 1, 0, 0, 0));
  Order::OffsetVector warm;
  Order::OffsetVector cold;
  ASSERT_TRUE(orderer_->GetBasicBlockOrderings(&warm, &cold));
  // Note that the bb's at 52 and 64 are the jump and case tables, respectively.
  EXPECT_THAT(warm, testing::ElementsAre(0, 24, 31, 36, 52, 64));
  EXPECT_THAT(cold, testing::ElementsAre(23, 37, 42, 49));
}

TEST_F(BasicBlockOrdererTest, PathStraightening) {
  // The default control flow of the block we construct isn't very interesting
  // from a path straightening perspective. So, we modify it here such that the
  // jnz instruction the end of the basic block at offset 31 branches to case_1
  // (at offset 37), and then give that basic-block an elevated entry count.
  BasicCodeBlock* case_1 = BasicCodeBlock::Cast(FindBasicBlockAt(37));
  ASSERT_TRUE(case_1 != NULL);
  ASSERT_EQ(1U, case_1->instructions().size());
  ASSERT_EQ(I_CALL, case_1->instructions().front().representation().opcode);

  BasicCodeBlock* jnz_bb = BasicCodeBlock::Cast(FindBasicBlockAt(31));
  ASSERT_TRUE(jnz_bb != NULL);
  ASSERT_EQ(1U, jnz_bb->instructions().size());
  ASSERT_EQ(I_SUB, jnz_bb->instructions().front().representation().opcode);
  ASSERT_EQ(2U, jnz_bb->successors().size());
  ASSERT_EQ(block_graph::Successor::kConditionNotEqual,
            jnz_bb->successors().front().condition());
  jnz_bb->successors().front().set_reference(
      block_graph::BasicBlockReference(BlockGraph::PC_RELATIVE_REF, 1, case_1));

  // Setup the entry counts such that the jump table stays in the same order
  // but case 1 is promoted to follow the jnz basic block.
  ASSERT_NO_FATAL_FAILURE(SetEntryCounts(1, 0, 10, 5, 1, 7, 0, 0));
  Order::OffsetVector warm;
  Order::OffsetVector cold;
  ASSERT_TRUE(orderer_->GetBasicBlockOrderings(&warm, &cold));
  // Note that the bb's at 52 and 64 are the jump and case tables, respectively.
  EXPECT_THAT(warm, testing::ElementsAre(0, 24, 31, 37, 36, 52, 64));
  EXPECT_THAT(cold, testing::ElementsAre(42, 23, 49));
}

TEST_F(BasicBlockOrdererTest, PathStraighteningAcrossJumpTable) {
  // Setup the entry counts such that case 1 (at offset 37) is promoted to be
  // the warmest path through the jump table.
  ASSERT_NO_FATAL_FAILURE(SetEntryCounts(1, 0, 1, 5, 1, 7, 0, 0));
  Order::OffsetVector warm;
  Order::OffsetVector cold;
  ASSERT_TRUE(orderer_->GetBasicBlockOrderings(&warm, &cold));
  // Note that the bb's at 52 and 64 are the jump and case tables, respectively.
  EXPECT_THAT(warm, testing::ElementsAre(0, 37, 24, 31, 36, 52, 64));
  EXPECT_THAT(cold, testing::ElementsAre(42, 23, 49));
}

TEST_F(BasicBlockOptimizerTest, Accessors) {
  const std::string kSectionName(".froboz");
  EXPECT_TRUE(!optimizer_.cold_section_name().empty());
  EXPECT_NE(kSectionName, optimizer_.cold_section_name());
  optimizer_.set_cold_section_name(kSectionName);
  EXPECT_EQ(kSectionName, optimizer_.cold_section_name());
}

TEST_F(BasicBlockOptimizerTest, EmptyOrderingAllCold) {
  Order order;
  IndexedFrequencyInformation entry_counts;
  entry_counts.num_entries = 0;
  entry_counts.num_columns = 1;
  entry_counts.data_type = ::common::IndexedFrequencyData::BASIC_BLOCK_ENTRY;
  entry_counts.frequency_size = 4;

  ASSERT_TRUE(
      optimizer_.Optimize(image_layout_, entry_counts, &order));

  EXPECT_EQ(image_layout_.sections.size() + 1, order.sections.size());
  EXPECT_EQ(optimizer_.cold_section_name(), order.sections.back().name);
  EXPECT_EQ(Order::SectionSpec::kNewSectionId, order.sections.back().id);
  EXPECT_EQ(pe::kCodeCharacteristics, order.sections.back().characteristics);

  // Count the blocks left in the original sections. This should only include
  // non-code blocks.
  size_t num_non_code_blocks = 0;
  size_t num_non_decomposable_blocks = 0;
  for (size_t i = 0; i < image_layout_.sections.size(); ++i) {
    for (size_t k = 0; k < order.sections[i].blocks.size(); ++k) {
      const BlockGraph::Block* block = order.sections[i].blocks[k].block;
      ASSERT_TRUE(block != NULL);
      ASSERT_NE(BlockGraph::CODE_BLOCK, block->type());
      ++num_non_code_blocks;
    }
  }

  // Validate that we have the expected numbers of blocks.
  EXPECT_EQ(num_non_code_blocks_, num_non_code_blocks);
  EXPECT_EQ(num_decomposable_blocks_ + num_non_decomposable_blocks_,
            order.sections.back().blocks.size());
  for (size_t i = 0; i < order.sections.back().blocks.size(); ++i) {
    EXPECT_TRUE(order.sections.back().blocks[i].basic_block_offsets.empty());
  }
}

TEST_F(BasicBlockOptimizerTest, HotCold) {
  // This test does a simple manipulation of the entry counts for DllMain and
  // validates that some minimum number of its blocks get moved into the cold
  // section. We defer to the BasicBlockOrdererTest instances above for the
  // details Hot/Cold and Path Straightening tests.
  const BlockGraph::Block* dllmain = NULL;
  BlockGraph::AddressSpace::Range range;
  ASSERT_TRUE(FindBlockByName("DllMain", &dllmain, &range));
  ASSERT_TRUE(dllmain != NULL);

  using block_graph::BasicBlockSubGraph;
  using block_graph::BasicBlockDecomposer;

  BasicBlockSubGraph subgraph;
  BasicBlockDecomposer decomposer(dllmain, &subgraph);
  ASSERT_TRUE(decomposer.Decompose());
  ASSERT_EQ(1U, subgraph.block_descriptions().size());

  // Generate an entry count map with a non-zero count for every other BB.
  IndexedFrequencyInformation entry_counts;
  entry_counts.num_entries = 0;
  entry_counts.num_columns = 1;
  entry_counts.data_type = ::common::IndexedFrequencyData::BASIC_BLOCK_ENTRY;
  entry_counts.frequency_size = 4;
  IndexedFrequencyMap& frequency_map = entry_counts.frequency_map;

  const BasicBlockSubGraph::BlockDescription& desc =
      subgraph.block_descriptions().front();
  BasicBlockSubGraph::BasicBlockOrdering::const_iterator it(
      desc.basic_block_order.begin());
  size_t num_basic_blocks = desc.basic_block_order.size();
  size_t num_hot_blocks = 0;

  bool is_hot = true;
  BlockGraph::RelativeAddress start_offs = subgraph.original_block()->addr();
  for (; it != desc.basic_block_order.end(); ++it) {
    if (is_hot && BasicCodeBlock::Cast(*it) != NULL) {
      frequency_map[std::make_pair(start_offs + (*it)->offset(), 0)] = 1;
      ++num_hot_blocks;
    }

    // Toggle hotness for next block.
    is_hot = !is_hot;
  }

  // Create an ordering that moves dllmain to a new section.
  std::string section_name(".dllmain");
  Order order;
  order.sections.resize(1);
  order.sections[0].id = Order::SectionSpec::kNewSectionId;
  order.sections[0].name = section_name;
  order.sections[0].characteristics = pe::kCodeCharacteristics;
  order.sections[0].blocks.push_back(Order::BlockSpec(dllmain));

  ASSERT_TRUE(
      optimizer_.Optimize(image_layout_, entry_counts, &order));

  ASSERT_EQ(image_layout_.sections.size() + 2, order.sections.size());
  ASSERT_EQ(section_name, order.sections[0].name);
  ASSERT_EQ(1U, order.sections[0].blocks.size());
  ASSERT_TRUE(!order.sections.back().blocks.empty());
  ASSERT_EQ(dllmain, order.sections[0].blocks[0].block);
  ASSERT_EQ(dllmain, order.sections.back().blocks[0].block);
  ASSERT_LE(num_hot_blocks,
            order.sections[0].blocks[0].basic_block_offsets.size());

  // Since data BBs that are referred to by 'hot' code BBs also make
  // it into the hot BB list, there could be fewer cold blocks than expected.
  ASSERT_GE(num_basic_blocks - num_hot_blocks,
            order.sections.back().blocks[0].basic_block_offsets.size());
}

}  // namespace reorder
