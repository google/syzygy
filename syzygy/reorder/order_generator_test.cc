// Copyright 2011 Google Inc. All Rights Reserved.
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

#include "syzygy/reorder/order_generator_test.h"

#include "syzygy/block_graph/block_graph.h"
#include "syzygy/core/address.h"
#include "syzygy/core/unittest_util.h"

namespace testing {

using block_graph::BlockGraph;
using core::RelativeAddress;

typedef reorder::Reorderer::Order::BlockSpec BlockSpec;
typedef reorder::Reorderer::Order::SectionSpec SectionSpec;
typedef reorder::Reorderer::Order::SectionSpecVector SectionSpecVector;

OrderGeneratorTest::OrderGeneratorTest() : image_layout_(&block_graph_) {
}

void OrderGeneratorTest::SetUp() {
  base::FilePath test_data_dir = testing::GetExeRelativePath(L"test_data");
  base::FilePath input_dll_path = test_data_dir.Append(testing::kTestDllName);

  ASSERT_TRUE(input_dll_.Init(input_dll_path));
  pe::Decomposer decomposer(input_dll_);
  ASSERT_TRUE(decomposer.Decompose(&image_layout_));
}

reorder::Reorderer::UniqueTime OrderGeneratorTest::GetSystemTime() {
  return reorder::Reorderer::UniqueTime(base::Time::NowFromSystemTime());
}

void OrderGeneratorTest::ExpectNoDuplicateBlocks() {
  // Verifies that there are no duplicate blocks for each section.
  SectionSpecVector::const_iterator it = order_.sections.begin();
  for (; it != order_.sections.end(); ++it) {
    std::set<const BlockGraph::Block*> block_set;
    for (size_t i = 0; i < it->blocks.size(); ++i) {
      EXPECT_TRUE(block_set.insert(it->blocks[i].block).second);
    }
  }
}

void OrderGeneratorTest::ExpectMatchingMetadata(
    const IMAGE_SECTION_HEADER* section, const SectionSpec& section_spec) {
  DCHECK(section != NULL);
  // If specified, the section spec's name and characteristics should match.
  if (!section_spec.name.empty()) {
    EXPECT_EQ(1, ::strncmp(reinterpret_cast<const char*>(&section->Name[0]),
                           section_spec.name.c_str(),
                           sizeof(section->Name)));
    EXPECT_EQ(section->Characteristics, section_spec.characteristics);
  }
}

void OrderGeneratorTest::ExpectSameOrder(const IMAGE_SECTION_HEADER* section,
                                         const BlockSpecVector& block_specs) {
  DCHECK(section != NULL);
  // Verifies that the blocks in block_list match the order of the blocks
  // in the specified section. If the specified section is empty, then it
  // implies that original block ordering should be reused.
  if (!block_specs.empty()) {
    BlockSpecVector original_block_specs;
    GetBlockListForSection(section, &original_block_specs);
    ASSERT_EQ(original_block_specs.size(), block_specs.size());
    EXPECT_TRUE(std::equal(original_block_specs.begin(),
                           original_block_specs.end(),
                           block_specs.begin(),
                           &BlockSpecsAreEqual));
  }
}

void OrderGeneratorTest::ExpectDifferentOrder(
    const IMAGE_SECTION_HEADER* section, const BlockSpecVector& block_specs) {
  DCHECK(section != NULL);
  // Verifies that the blocks in block_list match the order of the blocks
  // in the specified section. If the specified section is empty, then it
  // implies that original block ordering should be reused.
  if (!block_specs.empty()) {
    BlockSpecVector original_block_specs;
    GetBlockListForSection(section, &original_block_specs);
    ASSERT_EQ(original_block_specs.size(), block_specs.size());
    EXPECT_FALSE(std::equal(original_block_specs.begin(),
                            original_block_specs.end(),
                            block_specs.begin(),
                            &BlockSpecsAreEqual));
  }
}

void OrderGeneratorTest::GetBlockListForSection(
    const IMAGE_SECTION_HEADER* section, BlockSpecVector* block_specs) {
  DCHECK(section != NULL);
  DCHECK(block_specs != NULL);

  RelativeAddress section_start = RelativeAddress(section->VirtualAddress);
  BlockGraph::AddressSpace::RangeMapConstIterPair section_blocks =
      image_layout_.blocks.GetIntersectingBlocks(
          section_start, section->Misc.VirtualSize);
  BlockGraph::AddressSpace::RangeMapConstIter& section_it =
      section_blocks.first;
  const BlockGraph::AddressSpace::RangeMapConstIter& section_end =
      section_blocks.second;

  for (; section_it != section_end; ++section_it) {
    block_specs->push_back(BlockSpec(section_it->second));
  }
}

bool BlockSpecsAreEqual(const reorder::Reorderer::Order::BlockSpec& lhs,
                        const reorder::Reorderer::Order::BlockSpec& rhs) {
  // Each block should be the same.
  if (lhs.block != rhs.block)
    return false;

  // They should have the same number of block offsets.
  if (lhs.basic_block_offsets.size() != rhs.basic_block_offsets.size())
    return false;

  // They should have identical block offsets.
  if (!std::equal(lhs.basic_block_offsets.begin(),
                  lhs.basic_block_offsets.end(),
                  rhs.basic_block_offsets.begin())) {
    return false;
  }

  // If we get here then the block specs are identical.
  return true;
}

bool SectionSpecsAreEqual(const reorder::Reorderer::Order::SectionSpec& lhs,
                          const reorder::Reorderer::Order::SectionSpec& rhs) {
  // Each IDs should be the same.
  if (lhs.id != rhs.id)
    return false;

  // Each names should be the same.
  if (lhs.name != rhs.name)
    return false;

  // The characteristics should be the same.
  if (lhs.characteristics != rhs.characteristics)
    return false;

  // They must have the same number of blocks specs.
  if (lhs.blocks.size() != rhs.blocks.size())
    return false;

  // The blocks specifications should be identical.
  if (!std::equal(lhs.blocks.begin(),
                  lhs.blocks.end(),
                  rhs.blocks.begin(),
                  &BlockSpecsAreEqual)) {
    return false;
  }

  // If we reach here then the section specs are identical.
  return true;
}

bool OrdersAreEqual(const reorder::Reorderer::Order& lhs,
                    const reorder::Reorderer::Order& rhs) {
  // The comments should be the same.
  if (lhs.comment != rhs.comment)
    return false;

  // They should have the same number of sections.
  if (lhs.sections.size() != rhs.sections.size())
    return false;

  // The sections should be identical.
  if (!std::equal(lhs.sections.begin(),
                  lhs.sections.end(),
                  rhs.sections.begin(),
                  &SectionSpecsAreEqual)) {
    return false;
  }

  // If we reach here then the orders are identical.
  return true;
}

}  // namespace testing
