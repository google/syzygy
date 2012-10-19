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

#include "gtest/gtest.h"
#include "syzygy/block_graph/block_graph.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/block_util.h"
#include "syzygy/pe/pe_utils.h"
#include "syzygy/reorder/order_generator_test.h"

namespace reorder {
namespace {

using block_graph::BlockGraph;
using core::RelativeAddress;
using grinder::basic_block_util::BasicBlockIdMap;
using grinder::basic_block_util::EntryCountType;
using grinder::basic_block_util::EntryCountVector;
using grinder::basic_block_util::LoadBasicBlockRanges;
using grinder::basic_block_util::RelativeAddressRangeVector;
using pe::ImageLayout;
using testing::GetExeTestDataRelativePath;

const wchar_t kInstrumentedPdbName[] =
    L"basic_block_entry_instrumented_test_dll.pdb";

class BasicBlockOptimizerTest : public testing::OrderGeneratorTest {
 public:
  typedef testing::OrderGeneratorTest Super;
  typedef Reorderer::Order Order;

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

TEST_F(BasicBlockOptimizerTest, GetBlockEntryCount) {
  // TODO(rogerm): Write me!
}

TEST_F(BasicBlockOptimizerTest, GetWarmestSuccessor) {
  // TODO(rogerm): Write me!
}

TEST_F(BasicBlockOptimizerTest, AddWarmDataReferences) {
  // TODO(rogerm): Write me!
}

TEST_F(BasicBlockOptimizerTest, GetBasicBlockOrderings) {
  // TODO(rogerm): Write me!
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
  // TODO(rogerm): Refactor this test to use a constructed block from our
  //     standard basic-block subgraph test fixture.
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

TEST_F(BasicBlockOptimizerTest, PathStraightening) {
  // TODO(rogerm): Assign entry counts to basic-blocks such that a path is
  //     rearranged to straighten it. Also check that if the entry count is
  //     the same for both successors that relative ordering is preserved.
}

}  // namespace reorder
