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

#include "syzygy/reorder/random_order_generator.h"

#include "gtest/gtest.h"
#include "syzygy/reorder/order_generator_test.h"

namespace {

const DWORD kDataCharacteristics =
    IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_CNT_UNINITIALIZED_DATA;

}  // namespace

class RandomOrderGeneratorTest : public testing::OrderGeneratorTest {
 protected:
  RandomOrderGeneratorTest() : order_generator_(1234) {}

  void ExpectRandomOrder(
      const IMAGE_SECTION_HEADER* section,
      const reorder::Reorderer::Order::BlockList& block_list) {
    // Verifies that the blocks in block_list match in count but not in order
    // to the blocks in the specified section.
    reorder::Reorderer::Order::BlockList original_block_list;
    GetBlockListForSection(section, &original_block_list);
    EXPECT_EQ(original_block_list.size(), block_list.size());
    EXPECT_FALSE(std::equal(original_block_list.begin(),
                            original_block_list.end(),
                            block_list.begin()));
  }

  reorder::RandomOrderGenerator order_generator_;
};

TEST_F(RandomOrderGeneratorTest, DoNotReorder) {
  EXPECT_TRUE(order_generator_.CalculateReordering(input_dll_,
                                                   image_,
                                                   false,
                                                   false,
                                                   &order_));

  ExpectNoDuplicateBlocks();

  // Verify that the order found in order_ matches the original decomposed
  // image.
  reorder::Reorderer::Order::BlockListMap::const_iterator it =
      order_.section_block_lists.begin();
  for (; it != order_.section_block_lists.end(); ++it) {
    const IMAGE_SECTION_HEADER* section = input_dll_.section_header(it->first);
    ExpectNoReorder(section, it->second);
  }
}

TEST_F(RandomOrderGeneratorTest, ReorderCode) {
  EXPECT_TRUE(order_generator_.CalculateReordering(input_dll_,
                                                   image_,
                                                   true,
                                                   false,
                                                   &order_));

  ExpectNoDuplicateBlocks();

  // Verify that code blocks have been reordered and that data blocks have not.
  reorder::Reorderer::Order::BlockListMap::const_iterator it =
      order_.section_block_lists.begin();
  for (; it != order_.section_block_lists.end(); ++it) {
    const IMAGE_SECTION_HEADER* section = input_dll_.section_header(it->first);
    if (section->Characteristics & IMAGE_SCN_CNT_CODE) {
      ExpectRandomOrder(section, it->second);
    } else {
      ExpectNoReorder(section, it->second);
    }
  }
}

TEST_F(RandomOrderGeneratorTest, ReorderData) {
  EXPECT_TRUE(order_generator_.CalculateReordering(input_dll_,
                                                   image_,
                                                   false,
                                                   true,
                                                   &order_));

  ExpectNoDuplicateBlocks();

  // Verify that data blocks have been reordered and that code blocks have not.
  reorder::Reorderer::Order::BlockListMap::const_iterator it =
      order_.section_block_lists.begin();
  for (; it != order_.section_block_lists.end(); ++it) {
    const IMAGE_SECTION_HEADER* section = input_dll_.section_header(it->first);
    if (section->Characteristics & kDataCharacteristics) {
      std::string name = input_dll_.GetSectionName(*section);
      // .tls and .rsrc only have one block.
      if (name != ".tls" && name != ".rsrc")
        ExpectRandomOrder(section, it->second);
    } else {
      ExpectNoReorder(section, it->second);
    }
  }
}
