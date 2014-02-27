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
// Implements TestDllTransformTest functions.

#include "syzygy/instrument/transforms/unittest_util.h"

#include "syzygy/pe/coff_decomposer.h"
#include "syzygy/pe/coff_utils.h"
#include "syzygy/pe/decomposer.h"
#include "syzygy/pe/pe_utils.h"

namespace testing {

TestDllTransformTest::TestDllTransformTest()
    : policy_(NULL), header_block_(NULL) {
}

void TestDllTransformTest::DecomposeTestDll() {
  base::FilePath test_dll_path = ::testing::GetOutputRelativePath(
      testing::kTestDllName);

  ASSERT_TRUE(pe_file_.Init(test_dll_path));

  pe::ImageLayout layout(&block_graph_);
  pe::Decomposer decomposer(pe_file_);
  ASSERT_TRUE(decomposer.Decompose(&layout));

  header_block_ = layout.blocks.GetBlockByAddress(
      core::RelativeAddress(0));
  ASSERT_TRUE(header_block_ != NULL);

  policy_ = &pe_policy_;
}

void TestDllTransformTest::DecomposeTestDllObj() {
  base::FilePath test_dll_obj_path = ::testing::GetExeTestDataRelativePath(
      testing::kTestDllCoffObjName);

  ASSERT_TRUE(coff_file_.Init(test_dll_obj_path));

  pe::ImageLayout layout(&block_graph_);
  pe::CoffDecomposer decomposer(coff_file_);
  ASSERT_TRUE(decomposer.Decompose(&layout));

  ASSERT_TRUE(pe::FindCoffSpecialBlocks(
      &block_graph_, &header_block_, NULL, NULL));
  ASSERT_TRUE(header_block_ != NULL);

  policy_ = &coff_policy_;
}

}  // namespace testing
