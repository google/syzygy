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
#include "syzygy/pe/block_util.h"
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
using grinder::basic_block_util::BasicBlockIdMap;
using grinder::basic_block_util::EntryCountType;
using grinder::basic_block_util::EntryCountVector;
using grinder::basic_block_util::LoadBasicBlockRanges;
using grinder::basic_block_util::RelativeAddressRange;
using grinder::basic_block_util::RelativeAddressRangeVector;
using pe::ImageLayout;
using testing::GetExeTestDataRelativePath;

typedef Reorderer::Order Order;

const wchar_t kInstrumentedPdbName[] =
    L"basic_block_entry_instrumented_test_dll.pdb";

class TestBasicBlockOrderer : public BasicBlockOptimizer::BasicBlockOrderer {
 public:
  using BasicBlockOptimizer::BasicBlockOrderer::GetBasicBlockEntryCount;
  using BasicBlockOptimizer::BasicBlockOrderer::GetEntryCountByOffset;
  using BasicBlockOptimizer::BasicBlockOrderer::GetWarmestSuccessor;
  using BasicBlockOptimizer::BasicBlockOrderer::AddRecursiveDataReferences;
  using BasicBlockOptimizer::BasicBlockOrderer::AddWarmDataReferences;

  TestBasicBlockOrderer(
      const BasicBlockSubGraph& subgraph,
      const RelativeAddress& addr,
      Size size,
      const EntryCountVector& entry_counts,
      const BasicBlockIdMap& bb_id_map)
          : BasicBlockOptimizer::BasicBlockOrderer(
                subgraph, addr, size, entry_counts, bb_id_map) {
  }
};

class BasicBlockOrdererTest : public testing::BasicBlockTest {
 public:
  virtual void SetUp() OVERRIDE {
    ASSERT_NO_FATAL_FAILURE(testing::BasicBlockTest::SetUp());
    ASSERT_NO_FATAL_FAILURE(InitBlockGraph());
    ASSERT_NO_FATAL_FAILURE(InitBasicBlockSubGraph());
    ASSERT_NO_FATAL_FAILURE(InitBasicBlockRanges());
    ASSERT_NO_FATAL_FAILURE(SetEntryCounts(0, 0, 0, 0, 0, 0, 0, 0));
    ASSERT_TRUE(bb_id_map_.Init(bb_ranges_));
    ASSERT_EQ(entry_counts_.size(), bb_id_map_.Size());
    orderer_.reset(new TestBasicBlockOrderer(subgraph_,
                                             start_addr_,
                                             assembly_func_->size(),
                                             entry_counts_,
                                             bb_id_map_));
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

  void InitBasicBlockRanges() {
    // Create the basic-block ranges as described in the documentation for
    // testing::BasicBlockTest. Note that no bb ranges are created for the
    // data ranges.
    // TODO(rogerm): Host this into BasicBlockTest, which implies hoisting some
    //     types and utilities from grinder::basic_block_util.
    bb_ranges_.clear();
    bb_ranges_.reserve(kNumBasicBlockRanges);
    bb_ranges_.push_back(MakeRange(0, 23));
    bb_ranges_.push_back(MakeRange(23, 1));  // Unreachable code.
    bb_ranges_.push_back(MakeRange(24, 7));
    bb_ranges_.push_back(MakeRange(31, 53));
    bb_ranges_.push_back(MakeRange(36, 1));
    bb_ranges_.push_back(MakeRange(37, 5));
    bb_ranges_.push_back(MakeRange(42, 7));
    bb_ranges_.push_back(MakeRange(49, 1));
    ASSERT_EQ(kNumBasicBlockRanges, bb_ranges_.size());
    ASSERT_TRUE(bb_id_map_.Init(bb_ranges_));
  }

  void SetEntryCounts(uint32 bb0, uint32 bb1, uint32 bb2, uint32 bb3,
                      uint32 bb4, uint32 bb5, uint32 bb6, uint32 bb7) {
    entry_counts_.clear();
    entry_counts_.reserve(kNumBasicBlockRanges);
    entry_counts_.push_back(bb0);
    entry_counts_.push_back(bb1);
    entry_counts_.push_back(bb2);
    entry_counts_.push_back(bb3);
    entry_counts_.push_back(bb4);
    entry_counts_.push_back(bb5);
    entry_counts_.push_back(bb6);
    entry_counts_.push_back(bb7);
    ASSERT_EQ(kNumBasicBlockRanges, entry_counts_.size());
  }

  static const size_t kNumBasicBlockRanges =
      kNumCodeBasicBlocks + kNumPaddingBasicBlocks;

  RelativeAddressRangeVector bb_ranges_;
  EntryCountVector entry_counts_;
  BasicBlockIdMap bb_id_map_;
  scoped_ptr<TestBasicBlockOrderer> orderer_;
};

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
    FilePath pdb_path(GetExeTestDataRelativePath(kInstrumentedPdbName));
    ASSERT_TRUE(LoadBasicBlockRanges(pdb_path, &bb_ranges_));
    ASSERT_TRUE(bb_id_map_.Init(bb_ranges_));
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
        } else if (pe::CodeBlockIsBasicBlockDecomposable(block)) {
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
  RelativeAddressRangeVector bb_ranges_;
  BasicBlockIdMap bb_id_map_;
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
  const BasicDataBlock* jump_table = BasicDataBlock::Cast(FindBasicBlockAt(50));
  const BasicDataBlock* case_table = BasicDataBlock::Cast(FindBasicBlockAt(62));
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

TEST_F(BasicBlockOrdererTest, HotColdSeparation) {
  ASSERT_NO_FATAL_FAILURE(SetEntryCounts(1, 0, 1, 5, 1, 0, 0, 0));
  Order::OffsetVector warm;
  Order::OffsetVector cold;
  ASSERT_TRUE(orderer_->GetBasicBlockOrderings(&warm, &cold));
  // Note that the bb's at 50 and 62 are the jump and case tables, respectively.
  EXPECT_THAT(warm, testing::ElementsAre(0, 24, 31, 36, 50, 62));
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

  ASSERT_NO_FATAL_FAILURE(SetEntryCounts(1, 0, 1, 5, 1, 7, 0, 0));
  Order::OffsetVector warm;
  Order::OffsetVector cold;
  ASSERT_TRUE(orderer_->GetBasicBlockOrderings(&warm, &cold));
  // Note that the bb's at 50 and 62 are the jump and case tables, respectively.
  EXPECT_THAT(warm, testing::ElementsAre(0, 24, 31, 37, 36, 50, 62));
  EXPECT_THAT(cold, testing::ElementsAre(23, 42, 49));
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
  EntryCountVector entry_counts;
  entry_counts.resize(bb_ranges_.size());
  ASSERT_TRUE(
      optimizer_.Optimize(image_layout_, bb_ranges_, entry_counts, &order));

  EXPECT_EQ(image_layout_.sections.size() + 1, order.sections.size());
  EXPECT_EQ(optimizer_.cold_section_name(), order.sections.back().name);
  EXPECT_EQ(Order::SectionSpec::kNewSectionId, order.sections.back().id);
  EXPECT_EQ(pe::kCodeCharacteristics, order.sections.back().characteristics);

  // Count the blocks left in the original sections. This should only include
  // non-code and non-decomposable blocks, which we'll count separately.
  // TODO(rogerm): When we thunk in a BB entry count update for non-decomposable
  //     function blocks, update this to expect non-decomposable blocks to also
  //     move to the cold sections.
  size_t num_non_code_blocks = 0;
  size_t num_non_decomposable_blocks = 0;
  for (size_t i = 0; i < image_layout_.sections.size(); ++i) {
    for (size_t k = 0; k < order.sections[i].blocks.size(); ++k) {
      const BlockGraph::Block* block = order.sections[i].blocks[k].block;
      ASSERT_TRUE(block != NULL);
      if (block->type() != BlockGraph::CODE_BLOCK) {
        ++num_non_code_blocks;
      } else {
        ASSERT_FALSE(pe::CodeBlockIsBasicBlockDecomposable(block));
        EXPECT_TRUE(order.sections[i].blocks[k].basic_block_offsets.empty());
        ++num_non_decomposable_blocks;
      }
    }
  }

  // Validate that we have the expected numbers of blocks.
  EXPECT_EQ(num_non_code_blocks_, num_non_code_blocks);
  EXPECT_EQ(num_non_decomposable_blocks_, num_non_decomposable_blocks);
  EXPECT_EQ(num_decomposable_blocks_, order.sections.back().blocks.size());
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

  // Assign zero and non-zero counts to alternating basic-blocks of DllMain.
  // Put a non-zero entry count everywhere else.
  EntryCountVector entry_counts(bb_ranges_.size(), 1);
  BasicBlockIdMap::ConstIterator iter = bb_id_map_.LowerBound(range.start());
  BasicBlockIdMap::ConstIterator iter_end =
      bb_id_map_.UpperBound(range.start() + range.size());
  size_t num_basic_blocks = std::distance(iter, iter_end);
  for (EntryCountType count = 1; iter != iter_end; ++iter, count = 1 - count) {
    ASSERT_TRUE(range.Contains(iter->first));
    ASSERT_EQ(bb_ranges_[iter->second].start(), iter->first);
    entry_counts[iter->second] = count;
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
      optimizer_.Optimize(image_layout_, bb_ranges_, entry_counts, &order));

  ASSERT_EQ(image_layout_.sections.size() + 2, order.sections.size());
  ASSERT_EQ(section_name, order.sections[0].name);
  ASSERT_EQ(1U, order.sections[0].blocks.size());
  ASSERT_TRUE(!order.sections.back().blocks.empty());
  ASSERT_EQ(dllmain, order.sections[0].blocks[0].block);
  ASSERT_EQ(dllmain, order.sections.back().blocks[0].block);
  ASSERT_LE((num_basic_blocks + 1) / 2,
            order.sections[0].blocks[0].basic_block_offsets.size());
  ASSERT_LE(num_basic_blocks / 2,
            order.sections.back().blocks[0].basic_block_offsets.size());
}

}  // namespace reorder
