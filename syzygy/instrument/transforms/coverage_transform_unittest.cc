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
#include "syzygy/common/indexed_frequency_data.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/instrument/transforms/unittest_util.h"
#include "syzygy/pe/decomposer.h"
#include "syzygy/pe/unittest_util.h"

namespace instrument {
namespace transforms {

namespace {

using common::IndexedFrequencyData;
using block_graph::BlockGraph;

class CoverageInstrumentationTransformTest
    : public testing::TestDllTransformTest {
 public:
  virtual void SetUp() OVERRIDE {
    ASSERT_NO_FATAL_FAILURE(DecomposeTestDll());
  }
};

}  // namespace

TEST_F(CoverageInstrumentationTransformTest, Apply) {
  CoverageInstrumentationTransform tx;
  ASSERT_TRUE(block_graph::ApplyBlockGraphTransform(
      &tx, policy_, &block_graph_, header_block_));

  BlockGraph::Block* frequency_data_block = tx.frequency_data_block();

  block_graph::ConstTypedBlock<IndexedFrequencyData> coverage_data;
  ASSERT_TRUE(coverage_data.Init(0, frequency_data_block));

  // The frequency data block should have the appropriate size.
  ASSERT_EQ(sizeof(IndexedFrequencyData), frequency_data_block->size());
  ASSERT_EQ(sizeof(IndexedFrequencyData), frequency_data_block->data_size());
  EXPECT_EQ(coverage_data->num_entries,
            tx.frequency_data_buffer_block()->size());

  EXPECT_EQ(common::kBasicBlockCoverageAgentId, coverage_data->agent_id);
  EXPECT_EQ(common::kBasicBlockFrequencyDataVersion, coverage_data->version);
  EXPECT_EQ(IndexedFrequencyData::COVERAGE, coverage_data->data_type);
  EXPECT_EQ(tx.bb_ranges().size(), coverage_data->num_entries);
  EXPECT_TRUE(coverage_data.HasReferenceAt(
      coverage_data.OffsetOf(coverage_data->frequency_data)));
}

}  // namespace transforms
}  // namespace instrument
