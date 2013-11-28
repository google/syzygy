// Copyright 2013 Google Inc. All Rights Reserved.
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

#include "syzygy/optimize/application_profile.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/block_graph/basic_block_decomposer.h"
#include "syzygy/block_graph/basic_block_subgraph.h"

namespace optimize {

namespace {

using block_graph::BasicBlockDecomposer;
using block_graph::BasicBlockSubGraph;
using block_graph::BlockGraph;
using grinder::basic_block_util::IndexedFrequencyMap;
using grinder::basic_block_util::IndexedFrequencyOffset;
using testing::ContainerEq;

typedef ApplicationProfile::BlockProfile BlockProfile;
typedef BasicBlockSubGraph::BasicCodeBlock BasicCodeBlock;
typedef BlockGraph::Offset Offset;
typedef SubGraphProfile::BasicBlockProfile BasicBlockProfile;
typedef core::RelativeAddress RelativeAddress;
typedef grinder::basic_block_util::EntryCountType EntryCountType;
typedef pe::ImageLayout ImageLayout;

const size_t kEntryCountColumn = 0;
const size_t kTakenCountColumn = 1;
const size_t kMissPredictedColumn = 2;

const size_t kBlock1Count = 42;
const size_t kBlock2Count = 128;
const size_t kBlock2BodyCount = 256;
const size_t kBlock3Count = 0;

const core::RelativeAddress kSmallCodeAddress(0x3000);
const Offset kBasicBlockOffset0 = 0;
const Offset kBasicBlockOffset1 = 4;
const Offset kBasicBlockOffset2 = 7;
const EntryCountType kBasicBlockCount0 = 100;
const EntryCountType kBasicBlockCount1 = 80;
const EntryCountType kBasicBlockCount2 = 20;
const uint8 kSmallCode[] = {
    0x3B, 0xC1,  // cmp %eax, %ecx
    0x7D, 0x03,  // jge +7
    0x03, 0xC1,  // add %eax, %ecx
    0xC3,        // ret
    0x2B, 0xC1,  // sub %eax, %ecx
    0xC3         // ret
};

class TestBlockProfile : public ApplicationProfile::BlockProfile {
 public:
  using ApplicationProfile::BlockProfile::count_;
  using ApplicationProfile::BlockProfile::temperature_;
  using ApplicationProfile::BlockProfile::percentile_;
};

class TestAplicationProfile : public ApplicationProfile {
 public:
  using ApplicationProfile::frequencies_;
  using ApplicationProfile::image_layout_;
  using ApplicationProfile::global_temperature_;
  using ApplicationProfile::profiles_;
  using ApplicationProfile::empty_profile_;

  explicit TestAplicationProfile(ImageLayout* layout)
      : ApplicationProfile(layout) {
    DCHECK_NE(reinterpret_cast<ImageLayout*>(NULL), layout);
  }
};

class ApplicationProfileTest : public testing::Test  {
 public:
  ApplicationProfileTest() : layout_(&block_graph_) {
  }

  void PopulateLayout() {
    // Build a dummy block graph.
    BlockGraph::Section* section1 = block_graph_.AddSection(".text", 0);
    BlockGraph::Section* section2 = block_graph_.AddSection(".text_cold", 0);
    BlockGraph::Section* section3 = block_graph_.AddSection(".text_sub", 0);
    block1_ = block_graph_.AddBlock(BlockGraph::CODE_BLOCK, 10, "block1");
    block2_ = block_graph_.AddBlock(BlockGraph::CODE_BLOCK, 10, "block2");
    block3_ = block_graph_.AddBlock(BlockGraph::CODE_BLOCK, 10, "block3");
    block1_->set_section(section1->id());
    block2_->set_section(section2->id());
    block3_->set_section(section2->id());

    block_code_ = block_graph_.AddBlock(BlockGraph::CODE_BLOCK,
                                        sizeof(kSmallCode),
                                        "SmallCode");

    // Build a dummy image layout.
    pe::ImageLayout::SectionInfo section_info1 = {};
    section_info1.name = section1->name();
    section_info1.addr = core::RelativeAddress(0x1000);
    section_info1.size = 0x1000;
    section_info1.data_size = 0x1000;
    layout_.sections.push_back(section_info1);

    pe::ImageLayout::SectionInfo section_info2 = {};
    section_info2.name = section2->name();
    section_info2.addr = core::RelativeAddress(0x2000);
    section_info2.size = 0x1000;
    section_info2.data_size = 0x1000;
    layout_.sections.push_back(section_info2);

    pe::ImageLayout::SectionInfo section_info3 = {};
    section_info3.name = section3->name();
    section_info3.addr = kSmallCodeAddress;
    section_info3.size = 0x1000;
    section_info3.data_size = 0x1000;
    layout_.sections.push_back(section_info3);

    // Insert blocks into the image layout.
    layout_.blocks.InsertBlock(section_info1.addr, block1_);
    layout_.blocks.InsertBlock(section_info2.addr, block2_);
    layout_.blocks.InsertBlock(section_info2.addr + block2_->size(), block3_);
    layout_.blocks.InsertBlock(section_info3.addr, block_code_);

    block_code_->SetData(kSmallCode, sizeof(kSmallCode));
  }

  void PopulateFrequencies(IndexedFrequencyMap* frequencies) {
    // Insert frequency for block 1.
    const RelativeAddress kBlock1Address = RelativeAddress(0x1000);
    (*frequencies)[std::make_pair(kBlock1Address, kEntryCountColumn)] =
        kBlock1Count;

    // Insert frequency for block 2 (inner basic block at block + 2).
    const RelativeAddress kBlock2Address = RelativeAddress(0x2000);
    (*frequencies)[std::make_pair(kBlock2Address, kEntryCountColumn)] =
        kBlock2Count;

    const RelativeAddress kBlock2AddressBB = RelativeAddress(0x2000 + 2);
    (*frequencies)[std::make_pair(kBlock2AddressBB, kEntryCountColumn)] =
        kBlock2BodyCount;
  }

  void PopulateSubgraphFrequencies(IndexedFrequencyMap* frequencies) {
    // Insert frequencies for SmallCode.
    const RelativeAddress kBlockAddress0 =
        RelativeAddress(kSmallCodeAddress + kBasicBlockOffset0);
    const RelativeAddress kBlockAddress1 =
        RelativeAddress(kSmallCodeAddress + kBasicBlockOffset1);
    const RelativeAddress kBlockAddress2 =
        RelativeAddress(kSmallCodeAddress + kBasicBlockOffset2);

    (*frequencies)[std::make_pair(kBlockAddress0, kEntryCountColumn)] =
        kBasicBlockCount0;
    (*frequencies)[std::make_pair(kBlockAddress1, kEntryCountColumn)] =
        kBasicBlockCount1;
    (*frequencies)[std::make_pair(kBlockAddress2, kEntryCountColumn)] =
        kBasicBlockCount2;

    (*frequencies)[std::make_pair(kBlockAddress0, kTakenCountColumn)] =
        kBasicBlockCount2;

    (*frequencies)[std::make_pair(kBlockAddress0, kMissPredictedColumn)] =
        kBasicBlockCount2;
  }

  BlockGraph block_graph_;
  ImageLayout layout_;
  BlockGraph::Block* block1_;
  BlockGraph::Block* block2_;
  BlockGraph::Block* block3_;
  BlockGraph::Block* block_code_;
};

}  // namespace

TEST(BlockProfileTest, Constructor) {
  ApplicationProfile::BlockProfile profile(0, 0);
  EXPECT_EQ(0U, profile.count());
  EXPECT_EQ(0, profile.temperature());
  EXPECT_EQ(0, profile.percentile());
}

TEST(BlockProfileTest, ConstructorWithValues) {
  ApplicationProfile::BlockProfile profile(12, 42);
  EXPECT_EQ(12U, profile.count());
  EXPECT_EQ(42, profile.temperature());

  EXPECT_EQ(0, profile.percentile());
  profile.set_percentile(0.05);
  EXPECT_EQ(0.05, profile.percentile());
}

TEST_F(ApplicationProfileTest, DefaultConstructor) {
  TestAplicationProfile app(&layout_);

  EXPECT_TRUE(app.frequencies_.empty());
  EXPECT_EQ(&layout_, app.image_layout_);
  EXPECT_EQ(0, app.global_temperature_);
  EXPECT_TRUE(app.profiles_.empty());
}

TEST_F(ApplicationProfileTest, BuildApplicationProfile) {
  TestAplicationProfile app(&layout_);
  IndexedFrequencyMap frequencies;
  ASSERT_NO_FATAL_FAILURE(PopulateLayout());
  ASSERT_NO_FATAL_FAILURE(PopulateFrequencies(&frequencies));
  ASSERT_TRUE(app.ImportFrequencies(frequencies));
  ASSERT_TRUE(app.ComputeGlobalProfile());

  // Check the global temperature.
  EXPECT_THAT(frequencies, ContainerEq(app.frequencies_));
  EXPECT_EQ(static_cast<double>(kBlock1Count + kBlock2Count + kBlock2BodyCount),
            app.global_temperature());

  // Retrieve and check block profile.
  const BlockProfile* profile1 = app.GetBlockProfile(block1_);
  const BlockProfile* profile2 = app.GetBlockProfile(block2_);
  const BlockProfile* profile3 = app.GetBlockProfile(block3_);

  ASSERT_NE(reinterpret_cast<const BlockProfile*>(NULL), profile1);
  ASSERT_NE(reinterpret_cast<const BlockProfile*>(NULL), profile2);
  ASSERT_NE(reinterpret_cast<const BlockProfile*>(NULL), profile3);

  EXPECT_EQ(kBlock1Count, profile1->count());
  EXPECT_EQ(kBlock2Count, profile2->count());

  EXPECT_EQ(kBlock1Count, profile1->temperature());
  EXPECT_EQ(kBlock2Count + kBlock2BodyCount, profile2->temperature());

  EXPECT_LT(0.90, profile1->percentile());
  EXPECT_GT(0.10, profile2->percentile());

  EXPECT_EQ(app.empty_profile_.get(), profile3);
  EXPECT_EQ(1.0, app.empty_profile_->percentile());
}

TEST_F(ApplicationProfileTest, ComputeSubGraphProfile) {
  // Build global profile.
  TestAplicationProfile app(&layout_);
  IndexedFrequencyMap frequencies;
  ASSERT_NO_FATAL_FAILURE(PopulateLayout());
  ASSERT_NO_FATAL_FAILURE(PopulateSubgraphFrequencies(&frequencies));
  ASSERT_TRUE(app.ImportFrequencies(frequencies));
  ASSERT_TRUE(app.ComputeGlobalProfile());

  // Decompose to subgraph.
  BasicBlockSubGraph subgraph;
  BasicBlockDecomposer decomposer(block_code_, &subgraph);
  ASSERT_TRUE(decomposer.Decompose());

  // Build subgraph profile.
  scoped_ptr<SubGraphProfile> subgraph_profile;
  ASSERT_NO_FATAL_FAILURE(
      app.ComputeSubGraphProfile(&subgraph, &subgraph_profile));

  // Retrieve Basic Blocks.
  ASSERT_EQ(1U,  subgraph.block_descriptions().size());
  const BasicBlockSubGraph::BasicBlockOrdering& original_order =
      subgraph.block_descriptions().front().basic_block_order;
  ASSERT_EQ(3U, original_order.size());
  BasicBlockSubGraph::BasicBlockOrdering::const_iterator it =
      original_order.begin();
  BasicCodeBlock* bb0 = BasicCodeBlock::Cast(*it);
  ++it;
  BasicCodeBlock* bb1 = BasicCodeBlock::Cast(*it);
  ++it;
  BasicCodeBlock* bb2 = BasicCodeBlock::Cast(*it);

  ASSERT_NE(reinterpret_cast<BasicCodeBlock*>(NULL), bb0);
  ASSERT_NE(reinterpret_cast<BasicCodeBlock*>(NULL), bb1);
  ASSERT_NE(reinterpret_cast<BasicCodeBlock*>(NULL), bb2);

  ASSERT_EQ(kBasicBlockOffset0, bb0->offset());
  ASSERT_EQ(kBasicBlockOffset1, bb1->offset());
  ASSERT_EQ(kBasicBlockOffset2, bb2->offset());

  // Retrieve basic block profiles.
  const BasicBlockProfile* profile0 =
      subgraph_profile->GetBasicBlockProfile(bb0);
  const BasicBlockProfile* profile1 =
      subgraph_profile->GetBasicBlockProfile(bb1);
  const BasicBlockProfile* profile2 =
      subgraph_profile->GetBasicBlockProfile(bb2);

  ASSERT_NE(reinterpret_cast<const BasicBlockProfile*>(NULL), profile0);
  ASSERT_NE(reinterpret_cast<const BasicBlockProfile*>(NULL), profile1);
  ASSERT_NE(reinterpret_cast<const BasicBlockProfile*>(NULL), profile2);

  // Validate basic block profiles.
  EXPECT_EQ(100, profile0->count());
  EXPECT_EQ(80, profile1->count());
  EXPECT_EQ(20, profile2->count());

  EXPECT_EQ(.20, profile0->GetMispredictedRatio());
  EXPECT_EQ(0, profile1->GetMispredictedRatio());
  EXPECT_EQ(0, profile2->GetMispredictedRatio());

  EXPECT_EQ(0, profile0->GetSuccessorCount(bb0));
  EXPECT_EQ(80, profile0->GetSuccessorCount(bb1));
  EXPECT_EQ(20, profile0->GetSuccessorCount(bb2));

  EXPECT_EQ(0, profile0->GetSuccessorRatio(bb0));
  EXPECT_EQ(.80, profile0->GetSuccessorRatio(bb1));
  EXPECT_EQ(.20, profile0->GetSuccessorRatio(bb2));
}

}  // namespace optimize
