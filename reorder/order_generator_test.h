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

#ifndef SYZYGY_REORDER_ORDER_GENERATOR_TEST_H_
#define SYZYGY_REORDER_ORDER_GENERATOR_TEST_H_

#include "gtest/gtest.h"
#include "syzygy/pe/unittest_util.h"
#include "syzygy/reorder/reorderer.h"

namespace testing {

class OrderGeneratorTest : public PELibUnitTest {
 protected:
  OrderGeneratorTest();

  void SetUp();

  void ExpectNoDuplicateBlocks();
  void ExpectNoReorder(const IMAGE_SECTION_HEADER* section,
                       const reorder::Reorderer::Order::BlockList& block_list);

  void GetBlockListForSection(const IMAGE_SECTION_HEADER* section,
                              reorder::Reorderer::Order::BlockList* block_list);

  pe::PEFile input_dll_;
  core::BlockGraph block_graph_;
  pe::ImageLayout image_layout_;
  reorder::Reorderer::Order order_;
};

}  // namespace testing

#endif  // SYZYGY_REORDER_ORDER_GENERATOR_TEST_H_
