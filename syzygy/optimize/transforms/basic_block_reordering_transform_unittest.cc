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

#include "syzygy/optimize/transforms/basic_block_reordering_transform.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/block_graph/basic_block_decomposer.h"
#include "syzygy/block_graph/block_builder.h"
#include "syzygy/block_graph/block_graph.h"
#include "syzygy/pe/pe_transform_policy.h"

namespace optimize {
namespace transforms {

namespace {

using block_graph::BasicBlock;
using block_graph::BasicBlockDecomposer;
using block_graph::BasicBlockReference;
using block_graph::BasicBlockSubGraph;
using block_graph::BasicCodeBlock;
using block_graph::BlockBuilder;
using block_graph::BlockGraph;
using block_graph::Successor;
using pe::ImageLayout;
using testing::ElementsAre;
using testing::ElementsAreArray;

typedef block_graph::analysis::ControlFlowAnalysis::BasicBlockOrdering
    BasicBlockOrdering;
typedef grinder::basic_block_util::EntryCountType EntryCountType;

// _asm je  here
// _asm xor eax, eax
// here:
// _asm ret
const uint8 kCodeJump[] = { 0x74, 0x02, 0x33, 0xC0, 0xC3 };

// _asm jne here
// leave:
// _asm ret
// here:
// _asm xor eax, eax
// _asm jmp leave
const uint8 kCodeJumpInv[] = { 0x75, 0x01, 0xC3, 0x33, 0xC0, 0xEB, 0xFB };

const EntryCountType kRunMoreThanOnce = 100;
const EntryCountType kHot = 100;

class TestApplicationProfile : public ApplicationProfile {
 public:
  explicit TestApplicationProfile(const ImageLayout* image_layout)
      : ApplicationProfile(image_layout) {
  }

  using ApplicationProfile::profiles_;
};

class TestSubGraphProfile : public SubGraphProfile {
 public:
  using SubGraphProfile::basic_blocks_;
};

class TestBasicBlockProfile : public SubGraphProfile::BasicBlockProfile {
 public:
  using SubGraphProfile::BasicBlockProfile::count_;
  using SubGraphProfile::BasicBlockProfile::mispredicted_;
  using SubGraphProfile::BasicBlockProfile::successors_;

  TestBasicBlockProfile(EntryCountType count,
                        EntryCountType mispredicted,
                        EntryCountType taken) {
    count_ = count;
    mispredicted_ = mispredicted;
    taken_ = taken;
  }

  EntryCountType taken_;
};

class TestBasicBlockReorderingTransform : public BasicBlockReorderingTransform {
 public:
  using BasicBlockReorderingTransform::EvaluateCost;
  using BasicBlockReorderingTransform::CommitOrdering;
  using BasicBlockReorderingTransform::FlattenStructuralTreeToAnOrder;
};

class BasicBlockReorderingTransformTest : public testing::Test {
 public:
  BasicBlockReorderingTransformTest()
      : image_(&block_graph_),
        profile_(&image_) {
  }

  void SetUp() OVERRIDE;
  void ApplyTransform(BlockGraph::Block** block);
  void ApplyTransform(BlockGraph::Block** block,
                      TestBasicBlockProfile* bb_profiles,
                      size_t bb_profiles_length);
 protected:
  pe::PETransformPolicy policy_;
  BlockGraph block_graph_;
  BasicBlockSubGraph subgraph_;
  ImageLayout image_;
  BasicBlockReorderingTransform tx_;
  TestApplicationProfile profile_;
  TestSubGraphProfile subgraph_profile_;
  BasicCodeBlock* b1_;
  BasicCodeBlock* b2_;
  BasicCodeBlock* b3_;
  BasicCodeBlock* b4_;
  BasicCodeBlock* b5_;
};

void AddSuccessorBetween(
    Successor::Condition condition,
    BasicCodeBlock* from,
    BasicCodeBlock* to) {
  DCHECK_NE(reinterpret_cast<BasicCodeBlock*>(NULL), from);
  DCHECK_NE(reinterpret_cast<BasicCodeBlock*>(NULL), to);
  DCHECK_LT(from->successors().size(), 2U);

  from->successors().push_back(
      Successor(condition,
                BasicBlockReference(BlockGraph::RELATIVE_REF,
                                    BlockGraph::Reference::kMaximumSize,
                                    to),
                0));
}

void Connect1(BasicCodeBlock* from,
              BasicCodeBlock* to,
              size_t to_count,
              TestBasicBlockProfile* profile) {
  DCHECK_NE(reinterpret_cast<BasicCodeBlock*>(NULL), from);
  DCHECK_NE(reinterpret_cast<BasicCodeBlock*>(NULL), to);
  DCHECK_NE(reinterpret_cast<TestBasicBlockProfile*>(NULL), profile);
  DCHECK_LT(from->successors().size(), 1U);

  AddSuccessorBetween(Successor::kConditionTrue, from, to);

  profile->successors_[to] = to_count;
}

void Connect2(BasicCodeBlock* from,
              BasicCodeBlock* to1,
              BasicCodeBlock* to2,
              size_t to1_count,
              size_t to2_count,
              TestBasicBlockProfile* profile) {
  DCHECK_NE(reinterpret_cast<BasicCodeBlock*>(NULL), from);
  DCHECK_NE(reinterpret_cast<BasicCodeBlock*>(NULL), to1);
  DCHECK_NE(reinterpret_cast<BasicCodeBlock*>(NULL), to2);
  DCHECK_LT(from->successors().size(), 1U);

  AddSuccessorBetween(Successor::kConditionEqual, from, to1);
  AddSuccessorBetween(Successor::kConditionNotEqual, from, to2);

  profile->successors_[to1] = to1_count;
  profile->successors_[to2] = to2_count;
}

void BasicBlockReorderingTransformTest::SetUp() {
  // The control flow graph and frequencies built.
  //
  //              /------\
  //      (b1 [10])      |
  //      /      \       |
  // (b2 [4])  (b3 [6])  |
  //      \      /       |
  //      (b4 [10])------/
  //          |
  //        (b5 [1])

  b1_ = subgraph_.AddBasicCodeBlock("b1");
  b2_ = subgraph_.AddBasicCodeBlock("b2");
  b3_ = subgraph_.AddBasicCodeBlock("b3");
  b4_ = subgraph_.AddBasicCodeBlock("b4");
  b5_ = subgraph_.AddBasicCodeBlock("b5");

  ASSERT_NE(reinterpret_cast<BasicCodeBlock*>(NULL), b1_);
  ASSERT_NE(reinterpret_cast<BasicCodeBlock*>(NULL), b2_);
  ASSERT_NE(reinterpret_cast<BasicCodeBlock*>(NULL), b3_);
  ASSERT_NE(reinterpret_cast<BasicCodeBlock*>(NULL), b4_);
  ASSERT_NE(reinterpret_cast<BasicCodeBlock*>(NULL), b5_);

  TestBasicBlockProfile profile_b1(10, 0, 6);
  TestBasicBlockProfile profile_b2(4, 0, 4);
  TestBasicBlockProfile profile_b3(6, 0, 6);
  TestBasicBlockProfile profile_b4(10, 0, 9);
  TestBasicBlockProfile profile_b5(1, 0, 1);

  Connect2(b1_, b2_, b3_, 4, 6, &profile_b1);
  Connect1(b2_, b4_, 4, &profile_b2);
  Connect1(b3_, b4_, 6, &profile_b3);
  Connect2(b4_, b1_, b5_, 9, 1, &profile_b4);

  subgraph_profile_.basic_blocks_[b1_] = profile_b1;
  subgraph_profile_.basic_blocks_[b2_] = profile_b2;
  subgraph_profile_.basic_blocks_[b3_] = profile_b3;
  subgraph_profile_.basic_blocks_[b4_] = profile_b4;
  subgraph_profile_.basic_blocks_[b5_] = profile_b5;

  BasicBlockSubGraph::BlockDescription* description =
      subgraph_.AddBlockDescription(
          "bb1", "test.obj", BlockGraph::CODE_BLOCK, 7, 2, 42);
  description->basic_block_order.push_back(b1_);
  description->basic_block_order.push_back(b5_);
  description->basic_block_order.push_back(b4_);
  description->basic_block_order.push_back(b3_);
  description->basic_block_order.push_back(b2_);
}

void BasicBlockReorderingTransformTest::ApplyTransform(
    BlockGraph::Block** block) {
  ApplyTransform(block, NULL, 0);
}

// Apply a basic block reordering pass on |block| driven by the basic block
// profiles received in |bb_profiles|.
//
// This method
//   - decomposes the block into a subgraph,
//   - populates a subgraph profile based on |bb_profiles|,
//   - applies the transform,
//   - rebuilds the block.
//
// The |bb_profiles| is an array of |bb_profiles_length| profiles which maps
// one to one to the basic code blocks in the decomposed basic block.
// The parameter |block| receives the rebuilt block.
void BasicBlockReorderingTransformTest::ApplyTransform(
    BlockGraph::Block** block,
    TestBasicBlockProfile* bb_profiles,
    size_t bb_profiles_length) {
  // Decompose to subgraph.
  BasicBlockSubGraph subgraph;
  BasicBlockDecomposer decomposer(*block, &subgraph);
  ASSERT_TRUE(decomposer.Decompose());

  // Apply the requested basic block profiles.
  if (bb_profiles != NULL) {
    // Retrieve the original ordering of this subgraph.
    BasicBlockSubGraph::BlockDescriptionList& descriptions =
        subgraph.block_descriptions();
    DCHECK_EQ(1U, descriptions.size());
    BasicBlockSubGraph::BasicBlockOrdering& order =
        descriptions.begin()->basic_block_order;

    // There's no profile for the trailing end-block.
    DCHECK_EQ(subgraph.basic_blocks().size(), bb_profiles_length + 1);
    DCHECK_EQ(order.size(), bb_profiles_length + 1);

    // Commit the basic block profiles in the subgraph profile.
    size_t i = 0;
    BasicBlockSubGraph::BasicBlockOrdering::iterator bb = order.begin();
    for (; i < bb_profiles_length && bb != order.end(); ++i, ++bb) {
      BasicCodeBlock* code = BasicCodeBlock::Cast(*bb);
      DCHECK_NE(reinterpret_cast<BasicCodeBlock*>(NULL), code);

      // Commit successors profile in the subgraph profile.
      const BasicBlock::Successors& successors = code->successors();
      switch (successors.size()) {
        case 1: {
          BasicCodeBlock* succ = BasicCodeBlock::Cast(
              successors.front().reference().basic_block());
          DCHECK_NE(reinterpret_cast<BasicCodeBlock*>(NULL), succ);
          bb_profiles[i].successors_[succ] = bb_profiles[i].taken_;
          break;
        }
        case 2: {
          BasicCodeBlock* succ1 = BasicCodeBlock::Cast(
              successors.front().reference().basic_block());
          BasicCodeBlock* succ2 =  BasicCodeBlock::Cast(
              successors.back().reference().basic_block());
          DCHECK_NE(reinterpret_cast<BasicCodeBlock*>(NULL), succ1);
          DCHECK_NE(reinterpret_cast<BasicCodeBlock*>(NULL), succ2);

          EntryCountType untaken =
              bb_profiles[i].count_ - bb_profiles[i].taken_;

          bb_profiles[i].successors_[succ1] = bb_profiles[i].taken_;
          bb_profiles[i].successors_[succ2] = untaken;
          break;
        }
      }

      subgraph_profile_.basic_blocks_[code] = bb_profiles[i];
    }
  }

  // Apply block transform.
  ASSERT_TRUE(
      tx_.TransformBasicBlockSubGraph(&policy_, &block_graph_, &subgraph,
                                      &profile_, &subgraph_profile_));

  // Rebuild block.
  BlockBuilder builder(&block_graph_);
  ASSERT_TRUE(builder.Merge(&subgraph));
  CHECK_EQ(1u, builder.new_blocks().size());
  *block = *builder.new_blocks().begin();
}

}  // namespace

TEST_F(BasicBlockReorderingTransformTest, EvaluateSequentialCost) {
  // Validate a sequential ordering.
  BasicBlockOrdering order;
  order.push_back(b1_);
  order.push_back(b2_);
  order.push_back(b3_);
  order.push_back(b4_);
  order.push_back(b5_);
  uint64 expected_cost = 19;
  EXPECT_EQ(expected_cost,
            TestBasicBlockReorderingTransform::EvaluateCost(order,
                                                            subgraph_profile_));
}

TEST_F(BasicBlockReorderingTransformTest, EvaluateIfUnlikelyCost) {
  // Validate an unlikely-if ordering.
  BasicBlockOrdering order;
  order.push_back(b1_);
  order.push_back(b3_);
  order.push_back(b4_);
  order.push_back(b5_);
  order.push_back(b2_);
  uint64 expected_cost = 17;
  EXPECT_EQ(expected_cost,
            TestBasicBlockReorderingTransform::EvaluateCost(order,
                                                            subgraph_profile_));
}

TEST_F(BasicBlockReorderingTransformTest, EvaluateBadOrderCost) {
  // Validate a really bad ordering.
  BasicBlockOrdering order;
  order.push_back(b1_);
  order.push_back(b5_);
  order.push_back(b4_);
  order.push_back(b3_);
  order.push_back(b2_);
  uint64 expected_cost = 30;
  EXPECT_EQ(expected_cost,
            TestBasicBlockReorderingTransform::EvaluateCost(order,
                                                            subgraph_profile_));
}

TEST_F(BasicBlockReorderingTransformTest, CommitOrdering) {
  // Create an original order.
  BasicBlockSubGraph::BasicBlockOrdering target;
  target.push_back(b1_);
  target.push_back(b2_);
  target.push_back(b3_);
  target.push_back(b4_);
  target.push_back(b5_);

  // Create the requested order.
  BasicBlockOrdering order;
  order.push_back(b1_);
  order.push_back(b5_);
  order.push_back(b4_);
  order.push_back(b3_);
  order.push_back(b2_);

  // Commit the requested order.
  ASSERT_NO_FATAL_FAILURE(TestBasicBlockReorderingTransform::CommitOrdering(
      order, NULL, &target));

  EXPECT_EQ(5U, target.size());
  EXPECT_THAT(target, ElementsAre(b1_, b5_, b4_, b3_, b2_));
}

TEST_F(BasicBlockReorderingTransformTest, FlattenStructuralTreeToAnOrder) {
  // Flatten to a structural tree and perform reordering for a block without
  // profile information.
  TestSubGraphProfile subgraph_profile;
  BasicBlockOrdering order;
  ASSERT_TRUE(
      TestBasicBlockReorderingTransform::FlattenStructuralTreeToAnOrder(
          &subgraph_, &subgraph_profile_, &order));

  EXPECT_EQ(5U, order.size());
  EXPECT_THAT(order, ElementsAre(b1_, b2_, b3_, b4_, b5_));
}

TEST_F(BasicBlockReorderingTransformTest, ApplyTransformWithoutProfile) {
  BlockGraph::Block* block =
      block_graph_.AddBlock(BlockGraph::CODE_BLOCK, sizeof(kCodeJump), "jump");
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), block);
  block->SetData(kCodeJump, sizeof(kCodeJump));

  ASSERT_NO_FATAL_FAILURE(ApplyTransform(&block));

  // This block has a profile been never run, thus it must be unchanged.
  EXPECT_THAT(kCodeJump, ElementsAreArray(block->data(), block->size()));
}

TEST_F(BasicBlockReorderingTransformTest, ApplyTransformWithProfile) {
  BlockGraph::Block* block =
      block_graph_.AddBlock(BlockGraph::CODE_BLOCK, sizeof(kCodeJump), "jump");
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), block);
  block->SetData(kCodeJump, sizeof(kCodeJump));

  // Insert the block profile into the profile map.
  ApplicationProfile::BlockProfile block_profile(kRunMoreThanOnce, kHot);
  profile_.profiles_.insert(std::make_pair(block->id(), block_profile));

  ASSERT_NO_FATAL_FAILURE(ApplyTransform(&block));

  // This block must be unchanged.
  EXPECT_THAT(kCodeJump, ElementsAreArray(block->data(), block->size()));
}

TEST_F(BasicBlockReorderingTransformTest, ApplyTransformWithProfileAndGain) {
  BlockGraph::Block* block =
      block_graph_.AddBlock(BlockGraph::CODE_BLOCK,
                            sizeof(kCodeJumpInv),
                            "jump");
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), block);
  block->SetData(kCodeJumpInv, sizeof(kCodeJumpInv));

  // Insert the block profile into the profile map.
  ApplicationProfile::BlockProfile block_profile(kRunMoreThanOnce, kHot);
  profile_.profiles_.insert(std::make_pair(block->id(), block_profile));

  TestBasicBlockProfile bb_profiles[] = {
    TestBasicBlockProfile(kRunMoreThanOnce, kHot, kRunMoreThanOnce),
    TestBasicBlockProfile(kRunMoreThanOnce, kHot, kRunMoreThanOnce),
    TestBasicBlockProfile(kRunMoreThanOnce, kHot, kRunMoreThanOnce)
  };

  ASSERT_NO_FATAL_FAILURE(
      ApplyTransform(&block, bb_profiles, arraysize(bb_profiles)));

  // This block must be changed to a less expensive block.
  EXPECT_THAT(kCodeJump, ElementsAreArray(block->data(), block->size()));
}

}  // namespace transforms
}  // namespace optimize
