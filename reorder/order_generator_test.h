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

#ifndef SYZYGY_REORDER_ORDER_GENERATOR_TEST_H_
#define SYZYGY_REORDER_ORDER_GENERATOR_TEST_H_

#include "gtest/gtest.h"
#include "syzygy/pe/unittest_util.h"
#include "syzygy/reorder/reorderer.h"

namespace testing {

class OrderGeneratorTest : public PELibUnitTest {
 protected:
  typedef reorder::Reorderer::Order Order;
  typedef Order::BlockSpec BlockSpec;
  typedef Order::BlockSpecVector BlockSpecVector;
  typedef Order::SectionSpec SectionSpec;
  typedef Order::SectionSpecVector SectionSpecVector;

  OrderGeneratorTest();

  void SetUp();

  reorder::Reorderer::UniqueTime GetSystemTime();

  void ExpectMatchingMetadata(const IMAGE_SECTION_HEADER* section,
                              const SectionSpec& section_specs);

  void ExpectNoDuplicateBlocks();

  void ExpectSameOrder(const IMAGE_SECTION_HEADER* section,
                       const BlockSpecVector& block_specs);

  void ExpectDifferentOrder(const IMAGE_SECTION_HEADER* section,
                            const BlockSpecVector& block_specs);

  void GetBlockListForSection(const IMAGE_SECTION_HEADER* section,
                              BlockSpecVector* block_specs);

  pe::PEFile input_dll_;
  block_graph::BlockGraph block_graph_;
  pe::ImageLayout image_layout_;
  Order order_;
};

// Comparison functions for Orders and their parts.
bool BlockSpecsAreEqual(const reorder::Reorderer::Order::BlockSpec& lhs,
                        const reorder::Reorderer::Order::BlockSpec& rhs);
bool SectionSpecsAreEqual(const reorder::Reorderer::Order::SectionSpec& lhs,
                          const reorder::Reorderer::Order::SectionSpec& rhs);
bool OrdersAreEqual(const reorder::Reorderer::Order& lhs,
                    const reorder::Reorderer::Order& rhs);

}  // namespace testing

#endif  // SYZYGY_REORDER_ORDER_GENERATOR_TEST_H_
