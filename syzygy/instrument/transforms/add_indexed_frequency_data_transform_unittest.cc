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
// Add indexed block frequency transform unittests.

#include "syzygy/instrument/transforms/add_indexed_frequency_data_transform.h"

#include "gtest/gtest.h"
#include "syzygy/block_graph/transform.h"
#include "syzygy/block_graph/typed_block.h"
#include "syzygy/common/indexed_frequency_data.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/instrument/transforms/unittest_util.h"
#include "syzygy/pe/decomposer.h"
#include "syzygy/pe/pe_utils.h"
#include "syzygy/pe/unittest_util.h"

namespace instrument {
namespace transforms {

namespace {

using block_graph::BlockGraph;
using common::IndexedFrequencyData;

const uint32 kAgentId = 0xDEADBEEF;
const uint32 kAgentVersion = 5;
const uint32 kNumEntries = 7;
const uint8 kFrequencySize = 4;

class AddFrequencyDataTransformTest
    : public testing::TestDllTransformTest {
 public:
  virtual void SetUp() OVERRIDE {
    ASSERT_NO_FATAL_FAILURE(DecomposeTestDll());
  }
};

}  // namespace

TEST_F(AddFrequencyDataTransformTest, Apply) {
  AddIndexedFrequencyDataTransform tx(kAgentId, "Test", kAgentVersion);
  ASSERT_TRUE(block_graph::ApplyBlockGraphTransform(
      &tx, &block_graph_, dos_header_block_));

  BlockGraph::Block* frequency_data_block = tx.frequency_data_block();

  // The frequency data block should have the appropriate size.
  ASSERT_EQ(sizeof(IndexedFrequencyData), frequency_data_block->data_size());
  ASSERT_EQ(sizeof(IndexedFrequencyData), frequency_data_block->size());

  // The frequency data block should be appropriately initialized.
  block_graph::ConstTypedBlock<IndexedFrequencyData> frequency_data;
  ASSERT_TRUE(frequency_data.Init(0, frequency_data_block));
  EXPECT_EQ(kAgentId, frequency_data->agent_id);
  EXPECT_EQ(kAgentVersion, frequency_data->version);
  EXPECT_EQ(TLS_OUT_OF_INDEXES, frequency_data->tls_index);
  EXPECT_EQ(0U, frequency_data->num_entries);
  EXPECT_EQ(0U, frequency_data->frequency_size);
  EXPECT_EQ(0U, frequency_data->initialization_attempted);

  // Configure the frequency data buffer.
  ASSERT_TRUE(tx.ConfigureFrequencyDataBuffer(kNumEntries,
                                              kFrequencySize));
  BlockGraph::Block* buffer_block = tx.frequency_data_buffer_block();
  EXPECT_TRUE(buffer_block != NULL);

  EXPECT_TRUE(frequency_data.HasReferenceAt(
      frequency_data.OffsetOf(frequency_data->frequency_data)));

  EXPECT_EQ(kNumEntries, frequency_data->num_entries);
  EXPECT_EQ(kFrequencySize, frequency_data->frequency_size);
  EXPECT_EQ(0, buffer_block->data_size());
  EXPECT_EQ((kNumEntries * kFrequencySize), buffer_block->size());
}

}  // namespace transforms
}  // namespace instrument
