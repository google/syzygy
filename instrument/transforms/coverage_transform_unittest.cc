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
// Coverage instrumentation transform unittests.

#include "syzygy/instrument/transforms/coverage_transform.h"

#include "gtest/gtest.h"
#include "syzygy/block_graph/transform.h"
#include "syzygy/block_graph/typed_block.h"
#include "syzygy/common/basic_block_frequency_data.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/decomposer.h"
#include "syzygy/pe/unittest_util.h"

namespace instrument {
namespace transforms {

using common::BasicBlockFrequencyData;
using block_graph::BlockGraph;

class CoverageInstrumentationTransformTest : public testing::PELibUnitTest {
 public:
  CoverageInstrumentationTransformTest() : dos_header_block_(NULL) { }

  virtual void SetUp() OVERRIDE {
  }

  void DecomposeTestDll() {
    FilePath test_dll_path = ::testing::GetOutputRelativePath(kDllName);

    ASSERT_TRUE(pe_file_.Init(test_dll_path));

    pe::ImageLayout layout(&block_graph_);
    pe::Decomposer decomposer(pe_file_);
    ASSERT_TRUE(decomposer.Decompose(&layout));

    dos_header_block_ = layout.blocks.GetBlockByAddress(
        core::RelativeAddress(0));
    ASSERT_TRUE(dos_header_block_ != NULL);
  }

  pe::PEFile pe_file_;
  BlockGraph block_graph_;
  BlockGraph::Block* dos_header_block_;
};

TEST_F(CoverageInstrumentationTransformTest, FailsWhenCoverageSectionExists) {
  ASSERT_NO_FATAL_FAILURE(DecomposeTestDll());

  BlockGraph::Section* coverage_section = block_graph_.AddSection(
      common::kBasicBlockFrequencySectionName,
      common::kBasicBlockFrequencySectionCharacteristics);
  ASSERT_TRUE(coverage_section != NULL);

  CoverageInstrumentationTransform tx;
  ASSERT_FALSE(block_graph::ApplyBlockGraphTransform(
      &tx, &block_graph_, dos_header_block_));
}

TEST_F(CoverageInstrumentationTransformTest, Apply) {
  ASSERT_NO_FATAL_FAILURE(DecomposeTestDll());

  CoverageInstrumentationTransform tx;
  ASSERT_TRUE(block_graph::ApplyBlockGraphTransform(
      &tx, &block_graph_, dos_header_block_));

  // There should be a coverage section, and it should contain 1 block.
  BlockGraph::Section* coverage_section = block_graph_.FindSection(
      common::kBasicBlockFrequencySectionName);
  ASSERT_TRUE(coverage_section != NULL);

  const BlockGraph::Block* coverage_block = NULL;
  BlockGraph::BlockMap::const_iterator it = block_graph_.blocks().begin();
  for (; it != block_graph_.blocks().end(); ++it) {
    if (it->second.section() == coverage_section->id()) {
      ASSERT_TRUE(coverage_block == NULL);
      coverage_block = &it->second;
    }
  }
  ASSERT_TRUE(coverage_block != NULL);

  // The coverage block should have the appropriate size, etc.
  ASSERT_EQ(sizeof(BasicBlockFrequencyData), coverage_block->size());
  ASSERT_EQ(sizeof(BasicBlockFrequencyData), coverage_block->data_size());

  block_graph::ConstTypedBlock<BasicBlockFrequencyData> coverage_data;
  ASSERT_TRUE(coverage_data.Init(0, coverage_block));
  ASSERT_EQ(common::kBasicBlockCoverageAgentId, coverage_data->agent_id);
  ASSERT_EQ(common::kBasicBlockFrequencyDataVersion, coverage_data->version);
  ASSERT_EQ(tx.bb_ranges().size(), coverage_data->num_basic_blocks);
  ASSERT_LT(0u, tx.conditional_ranges().size());
  ASSERT_TRUE(coverage_data.HasReferenceAt(
      coverage_data.OffsetOf(coverage_data->frequency_data)));
}

}  // namespace transforms
}  // namespace instrument
