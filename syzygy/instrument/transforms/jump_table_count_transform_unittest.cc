// Copyright 2013 Google Inc. All Rights Reserved.
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
// Jump-table case count instrumentation transform unit-tests.

#include "syzygy/instrument/transforms/jump_table_count_transform.h"

#include "gtest/gtest.h"
#include "syzygy/instrument/transforms/unittest_util.h"

namespace instrument {
namespace transforms {

namespace {

typedef testing::TestDllTransformTest JumpTableCaseCountTransformTest;

}  // namespace

TEST_F(JumpTableCaseCountTransformTest, Apply) {
  ASSERT_NO_FATAL_FAILURE(DecomposeTestDll());

  // Apply the transform.
  JumpTableCaseCountTransform tx;
  ASSERT_TRUE(block_graph::ApplyBlockGraphTransform(&tx, &block_graph_,
                                                    dos_header_block_));
}

}  // namespace transforms
}  // namespace instrument
