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

#include "syzygy/reorder/random_order_generator.h"

#include "gtest/gtest.h"
#include "syzygy/pe/pe_utils.h"
#include "syzygy/reorder/order_generator_test.h"

namespace reorder {

namespace {

typedef Reorderer::Order::BlockSpec BlockSpec;
typedef Reorderer::Order::SectionSpecVector SectionSpecVector;

class RandomOrderGeneratorTest : public testing::OrderGeneratorTest {
 protected:
  RandomOrderGeneratorTest() : order_generator_(1234) {}

  RandomOrderGenerator order_generator_;
};

}  // namespace

TEST_F(RandomOrderGeneratorTest, DoNotReorder) {
  EXPECT_TRUE(order_generator_.CalculateReordering(input_dll_,
                                                   image_layout_,
                                                   false,
                                                   false,
                                                   &order_));

  ExpectNoDuplicateBlocks();

  // Verify that the order found in order_ matches the original decomposed
  // image.
  for (size_t i = 0; i != order_.sections.size(); ++i) {
    const IMAGE_SECTION_HEADER* section = input_dll_.section_header(i);
    ExpectSameOrder(section, order_.sections[i].blocks);
  }
}

TEST_F(RandomOrderGeneratorTest, ReorderCode) {
  EXPECT_TRUE(order_generator_.CalculateReordering(input_dll_,
                                                   image_layout_,
                                                   true,
                                                   false,
                                                   &order_));

  ExpectNoDuplicateBlocks();

  // Verify that code blocks have been reordered and that data blocks have not.
  for (size_t i = 0; i != order_.sections.size(); ++i) {
    const IMAGE_SECTION_HEADER* section = input_dll_.section_header(i);
    if ((section->Characteristics & IMAGE_SCN_CNT_CODE) != 0) {
      ExpectDifferentOrder(section, order_.sections[i].blocks);
    } else {
      ExpectSameOrder(section, order_.sections[i].blocks);
    }
  }
}

TEST_F(RandomOrderGeneratorTest, ReorderData) {
  EXPECT_TRUE(order_generator_.CalculateReordering(input_dll_,
                                                   image_layout_,
                                                   false,
                                                   true,
                                                   &order_));

  ExpectNoDuplicateBlocks();

  // Verify that data blocks have been reordered and that code blocks have not.
  for (size_t i = 0; i != order_.sections.size(); ++i) {
    const IMAGE_SECTION_HEADER* section = input_dll_.section_header(i);
    if ((section->Characteristics & IMAGE_SCN_CNT_CODE) == 0) {
      std::string name = input_dll_.GetSectionName(*section);
      // .tls and .rsrc only have one block.
      if (name == ".tls" || name == ".rsrc") {
        EXPECT_EQ(1U, order_.sections[i].blocks.size());
      } else {
        // In VS2013 the .reloc section may contain only one block.
        if (order_.sections[i].blocks.size() > 1)
          ExpectDifferentOrder(section, order_.sections[i].blocks);
      }
    } else {
      ExpectSameOrder(section, order_.sections[i].blocks);
    }
  }
}

}  // namespace reorder
