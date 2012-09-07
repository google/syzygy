// Copyright 2012 Google Inc.
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
// Add basic block frequency transform unittests.

#include "syzygy/instrument/transforms/add_basic_block_frequency_data_transform.h"

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

using block_graph::BlockGraph;
using common::BasicBlockFrequencyData;
using common::kBasicBlockFrequencyDataVersion;
using common::kBasicBlockFrequencySectionName;
using common::kBasicBlockFrequencySectionCharacteristics;

const uint32 kAgentId = 0xDEADBEEF;
const uint32 kNumBasicBlocks = 7;
const uint8 kFrequencySize = 4;

class AddBasicBlockFrequencyDataTransformTest
    : public testing::TestDllTransformTest {
 public:
  virtual void SetUp() OVERRIDE {
    ASSERT_NO_FATAL_FAILURE(DecomposeTestDll());
  }
};

}  // namespace

TEST_F(AddBasicBlockFrequencyDataTransformTest, FailsWhenSectionExists) {
  BlockGraph::Section* section = block_graph_.AddSection(
      kBasicBlockFrequencySectionName,
      kBasicBlockFrequencySectionCharacteristics);
  ASSERT_TRUE(section != NULL);

  AddBasicBlockFrequencyDataTransform tx(kAgentId);
  EXPECT_TRUE(tx.frequency_data_block() == NULL);
  EXPECT_FALSE(block_graph::ApplyBlockGraphTransform(
      &tx, &block_graph_, dos_header_block_));
  EXPECT_TRUE(tx.frequency_data_block() == NULL);
}

TEST_F(AddBasicBlockFrequencyDataTransformTest, Apply) {
  ASSERT_TRUE(
      block_graph_.FindSection(kBasicBlockFrequencySectionName) == NULL);

  AddBasicBlockFrequencyDataTransform tx(kAgentId);
  ASSERT_TRUE(block_graph::ApplyBlockGraphTransform(
      &tx, &block_graph_, dos_header_block_));

  // There should be a frequency data section, and it should contain 1 block.
  BlockGraph::Section* section =
      block_graph_.FindSection(kBasicBlockFrequencySectionName);
  ASSERT_TRUE(section != NULL);

  // The frequency data section should contain just one block.
  const BlockGraph::Block* frequency_data_block = NULL;
  BlockGraph::BlockMap::const_iterator it = block_graph_.blocks().begin();
  for (; it != block_graph_.blocks().end(); ++it) {
    if (it->second.section() == section->id()) {
      ASSERT_TRUE(frequency_data_block == NULL);
      frequency_data_block = &it->second;
    }
  }
  ASSERT_TRUE(frequency_data_block != NULL);
  ASSERT_EQ(tx.frequency_data_block(), frequency_data_block);

  // The frequency data block should have the appropriate size.
  ASSERT_EQ(sizeof(BasicBlockFrequencyData), frequency_data_block->data_size());
  ASSERT_EQ(sizeof(BasicBlockFrequencyData), frequency_data_block->size());

  // The frequency data block should be appropriately initialized.
  block_graph::ConstTypedBlock<BasicBlockFrequencyData> frequency_data;
  ASSERT_TRUE(frequency_data.Init(0, frequency_data_block));
  EXPECT_EQ(kAgentId, frequency_data->agent_id);
  EXPECT_EQ(kBasicBlockFrequencyDataVersion, frequency_data->version);
  EXPECT_EQ(TLS_OUT_OF_INDEXES, frequency_data->tls_index);
  EXPECT_EQ(0U, frequency_data->num_basic_blocks);
  EXPECT_EQ(0U, frequency_data->frequency_size);
  EXPECT_EQ(0U, frequency_data->initialization_attempted);
  EXPECT_TRUE(frequency_data.HasReferenceAt(
      frequency_data.OffsetOf(frequency_data->frequency_data)));

  // Allocate the frequency data buffer.
  ASSERT_TRUE(tx.AllocateFrequencyDataBuffer(kNumBasicBlocks, kFrequencySize));
  EXPECT_EQ(kNumBasicBlocks, frequency_data->num_basic_blocks);
  EXPECT_EQ(kFrequencySize, frequency_data->frequency_size);
  EXPECT_EQ(sizeof(BasicBlockFrequencyData), frequency_data_block->data_size());
  EXPECT_EQ(
    sizeof(BasicBlockFrequencyData) + (kNumBasicBlocks * kFrequencySize),
    frequency_data_block->size());

  // Reallocate the frequency data buffer. While not expected that you'll
  // need to do this in practice, this is a safe and fast operation (for
  // example, one could incrementally expand the frequency data buffer as
  // basic-blocks are instrumented... but it's simpler to just perform the
  // allocation at the end.
  static const uint32 kNewNumBasicBlocks = kNumBasicBlocks + 7;
  ASSERT_TRUE(
      tx.AllocateFrequencyDataBuffer(kNewNumBasicBlocks, kFrequencySize));
  EXPECT_EQ(kNewNumBasicBlocks, frequency_data->num_basic_blocks);
  EXPECT_EQ(kFrequencySize, frequency_data->frequency_size);
  EXPECT_EQ(sizeof(BasicBlockFrequencyData), frequency_data_block->data_size());
  EXPECT_EQ(
    sizeof(BasicBlockFrequencyData) + (kNewNumBasicBlocks * kFrequencySize),
    frequency_data_block->size());
}

}  // namespace transforms
}  // namespace instrument
