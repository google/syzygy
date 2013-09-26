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
// A common test fixture which knows how to decompose the test dll.

#ifndef SYZYGY_INSTRUMENT_TRANSFORMS_UNITTEST_UTIL_H_
#define SYZYGY_INSTRUMENT_TRANSFORMS_UNITTEST_UTIL_H_

#include "syzygy/block_graph/block_graph.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/pe_file.h"
#include "syzygy/pe/pe_transform_policy.h"
#include "syzygy/pe/unittest_util.h"

namespace testing {

// A common test fixture which knows how to decompose the "standard" test dll.
class TestDllTransformTest : public testing::PELibUnitTest {
 public:
  TestDllTransformTest();

  // Decomposes the test_dll into block_graph_ and sets dos_header_block_.
  // Typically, you would call inside an ASSERT_NO_FATAL_FAILURE clause.
  void DecomposeTestDll();

  // The policy object restricting how the transform is applied.
  pe::PETransformPolicy policy_;

  // The PEFile instance referring to test_dll.
  pe::PEFile pe_file_;

  // The block graph for test_dll.
  block_graph::BlockGraph block_graph_;

  // The DOS header block for test_dll.
  block_graph::BlockGraph::Block* dos_header_block_;
};

}  // namespace testing

#endif  // SYZYGY_INSTRUMENT_TRANSFORMS_UNITTEST_UTIL_H_
