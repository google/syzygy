// Copyright 2011 Google Inc.
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

#include "syzygy/core/address.h"
#include "syzygy/core/block_graph.h"

using core::BlockGraph;
using core::RelativeAddress;

namespace testing {

OrderGeneratorTest::OrderGeneratorTest() : image_layout_(&block_graph_) {
}

void OrderGeneratorTest::SetUp() {
  FilePath test_data_dir = GetExeRelativePath(L"test_data");
  FilePath input_dll_path = test_data_dir.Append(kDllName);

  ASSERT_TRUE(input_dll_.Init(input_dll_path));
  pe::Decomposer decomposer(input_dll_);
  ASSERT_TRUE(decomposer.Decompose(&image_layout_));
}

reorder::Reorderer::UniqueTime OrderGeneratorTest::GetSystemTime() {
  return reorder::Reorderer::UniqueTime(base::Time::NowFromSystemTime());
}

void OrderGeneratorTest::ExpectNoDuplicateBlocks() {
  // Verifies that there are no duplicate blocks for each section.
  reorder::Reorderer::Order::BlockListMap::const_iterator it =
      order_.section_block_lists.begin();
  for (; it != order_.section_block_lists.end(); ++it) {
    std::set<const core::BlockGraph::Block*> block_set;
    for (size_t i = 0; i < it->second.size(); ++i) {
      EXPECT_TRUE(block_set.insert(it->second[i]).second);
    }
  }
}

void OrderGeneratorTest::ExpectNoReorder(
    const IMAGE_SECTION_HEADER* section,
    const reorder::Reorderer::Order::BlockList& block_list) {
  // Verifies that the blocks in block_list match the order of the blocks
  // in the specified section.
  reorder::Reorderer::Order::BlockList original_block_list;
  GetBlockListForSection(section, &original_block_list);
  EXPECT_EQ(original_block_list.size(), block_list.size());
  EXPECT_TRUE(std::equal(original_block_list.begin(),
                         original_block_list.end(),
                         block_list.begin()));
}

void OrderGeneratorTest::GetBlockListForSection(
    const IMAGE_SECTION_HEADER* section,
    reorder::Reorderer::Order::BlockList* block_list) {
  DCHECK(section != NULL);
  DCHECK(block_list != NULL);

  RelativeAddress section_start =
      RelativeAddress(section->VirtualAddress);
  BlockGraph::AddressSpace::RangeMapConstIterPair section_blocks =
      image_layout_.blocks.GetIntersectingBlocks(
          section_start, section->Misc.VirtualSize);
  BlockGraph::AddressSpace::RangeMapConstIter& section_it =
      section_blocks.first;
  const BlockGraph::AddressSpace::RangeMapConstIter& section_end =
      section_blocks.second;

  for (; section_it != section_end; ++section_it) {
    block_list->push_back(section_it->second);
  }
}

}  // namespace testing
