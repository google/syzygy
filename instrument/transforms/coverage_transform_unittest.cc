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
// Coverage instrumentation transform unittests.

#include "syzygy/instrument/transforms/coverage_transform.h"

#include "gtest/gtest.h"
#include "syzygy/block_graph/transform.h"
#include "syzygy/block_graph/typed_block.h"
#include "syzygy/common/basic_block_frequency_data.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/instrument/transforms/unittest_util.h"
#include "syzygy/pe/decomposer.h"
#include "syzygy/pe/unittest_util.h"

namespace instrument {
namespace transforms {

namespace {

using common::BasicBlockFrequencyData;
using block_graph::BlockGraph;

class CoverageInstrumentationTransformTest
    : public testing::TestDllTransformTest {
 public:
  virtual void SetUp() OVERRIDE {
    ASSERT_NO_FATAL_FAILURE(DecomposeTestDll());
  }
};

}  // namespace

TEST_F(CoverageInstrumentationTransformTest, FailsWhenCoverageSectionExists) {
  BlockGraph::Section* section = block_graph_.AddSection(
      common::kBasicBlockFrequencySectionName,
      common::kBasicBlockFrequencySectionCharacteristics);
  ASSERT_TRUE(section != NULL);

  CoverageInstrumentationTransform tx;
  ASSERT_FALSE(block_graph::ApplyBlockGraphTransform(
      &tx, &block_graph_, dos_header_block_));
}

TEST_F(CoverageInstrumentationTransformTest, Apply) {
  CoverageInstrumentationTransform tx;
  ASSERT_TRUE(block_graph::ApplyBlockGraphTransform(
      &tx, &block_graph_, dos_header_block_));

  // There should be a frequency data section.
  BlockGraph::Section* section = block_graph_.FindSection(
      common::kBasicBlockFrequencySectionName);
  ASSERT_TRUE(section != NULL);

  // The section should contain exactly 1 block.
  const BlockGraph::Block* coverage_block = NULL;
  BlockGraph::BlockMap::const_iterator it = block_graph_.blocks().begin();
  for (; it != block_graph_.blocks().end(); ++it) {
    if (it->second.section() == section->id()) {
      ASSERT_TRUE(coverage_block == NULL);
      coverage_block = &it->second;
    }
  }
  ASSERT_TRUE(coverage_block != NULL);

  // The coverage block should have the appropriate size, etc.
  ASSERT_EQ(sizeof(BasicBlockFrequencyData), coverage_block->data_size());

  block_graph::ConstTypedBlock<BasicBlockFrequencyData> coverage_data;
  ASSERT_TRUE(coverage_data.Init(0, coverage_block));
  EXPECT_EQ(common::kBasicBlockCoverageAgentId, coverage_data->agent_id);
  EXPECT_EQ(common::kBasicBlockFrequencyDataVersion, coverage_data->version);
  EXPECT_EQ(tx.bb_ranges().size(), coverage_data->num_basic_blocks);
  EXPECT_LT(0u, tx.conditional_ranges().size());
  EXPECT_TRUE(coverage_data.HasReferenceAt(
      coverage_data.OffsetOf(coverage_data->frequency_data)));
  EXPECT_EQ(sizeof(BasicBlockFrequencyData) + coverage_data->num_basic_blocks,
            coverage_block->size());
}

}  // namespace transforms
}  // namespace instrument
