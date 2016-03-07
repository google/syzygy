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
// Unittests for the random orderer.

#include "syzygy/block_graph/orderers/random_orderer.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace block_graph {
namespace orderers {

namespace {

using testing::ContainerEq;

class RandomOrdererTest : public testing::Test {
 public:
  virtual void SetUp() {
    section1_ = block_graph_.AddSection("foo", 0);
    section2_ = block_graph_.AddSection("bar", 0);
  }

  BlockGraph block_graph_;
  BlockGraph::Section* section1_;
  BlockGraph::Section* section2_;
};

template<typename Container>
void ToVector(const Container& container,
              std::vector<typename Container::value_type>* vector) {
  DCHECK(vector != NULL);
  vector->assign(container.begin(), container.end());
}

template<typename Container>
Container Sorted(const Container& container) {
  Container copy(container);
  std::sort(copy.begin(), copy.end());
  return copy;
}

}  // namespace

TEST_F(RandomOrdererTest, DefaultShuffleTrue) {
  RandomOrderer random(true);
  EXPECT_TRUE(random.ShouldShuffleSection(section1_));
  EXPECT_TRUE(random.ShouldShuffleSection(section2_));

  random.SetShuffleSection(section1_, false);
  EXPECT_FALSE(random.ShouldShuffleSection(section1_));
  EXPECT_TRUE(random.ShouldShuffleSection(section2_));

  random.SetShuffleSection(section1_, true);
  EXPECT_TRUE(random.ShouldShuffleSection(section1_));
  EXPECT_TRUE(random.ShouldShuffleSection(section2_));
}

TEST_F(RandomOrdererTest, DefaultShuffleFalse) {
  RandomOrderer random(false);
  EXPECT_FALSE(random.ShouldShuffleSection(section1_));
  EXPECT_FALSE(random.ShouldShuffleSection(section2_));

  random.SetShuffleSection(section2_, true);
  EXPECT_FALSE(random.ShouldShuffleSection(section1_));
  EXPECT_TRUE(random.ShouldShuffleSection(section2_));

  random.SetShuffleSection(section2_, false);
  EXPECT_FALSE(random.ShouldShuffleSection(section1_));
  EXPECT_FALSE(random.ShouldShuffleSection(section2_));
}

TEST_F(RandomOrdererTest, Shuffle) {
  // Put some blocks in each section.
  for (size_t i = 0; i < 2; ++i) {
    BlockGraph::SectionId section_id = (i == 0 ? section1_ : section2_)->id();

    for (size_t j = 0; j < 30; ++j) {
      BlockGraph::Block* block =
          block_graph_.AddBlock(BlockGraph::CODE_BLOCK, 10, "block");
      block->set_section(section_id);
    }
  }

  // We have 30! possible permutations, which is far greater than the number
  // of possible seed values. Thus, our chances of hitting a seed that causes
  // the identity ordering is quite small, and pretty much impossible for 5
  // consecutive seed values.

  size_t shuffled = 0;
  for (uint32_t i = 0; i < 5; ++i) {
    OrderedBlockGraph obg(&block_graph_);

    // Get the original order.
    BlockVector blocks1, blocks2;
    ToVector(obg.ordered_section(section1_).ordered_blocks(), &blocks1);
    ToVector(obg.ordered_section(section2_).ordered_blocks(), &blocks2);

    // Shuffle the blocks.
    RandomOrderer random(true, i);
    EXPECT_TRUE(random.OrderBlockGraph(&obg, NULL));

    // Get the shuffled order.
    BlockVector shuffled1, shuffled2;
    ToVector(obg.ordered_section(section1_).ordered_blocks(), &shuffled1);
    ToVector(obg.ordered_section(section2_).ordered_blocks(), &shuffled2);

    EXPECT_THAT(Sorted(blocks1), ContainerEq(Sorted(shuffled1)));
    EXPECT_THAT(Sorted(blocks2), ContainerEq(Sorted(shuffled2)));

    if (blocks1 != shuffled1 && blocks2 != shuffled2)
      ++shuffled;
  }
  EXPECT_LT(0u, shuffled);
}

}  // namespace orderers
}  // namespace block_graph
