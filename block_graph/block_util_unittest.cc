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

#include "syzygy/block_graph/block_util.h"

#include "gtest/gtest.h"

namespace block_graph {

namespace {

class BlockUtilTest: public testing::Test {
 public:
  void TestAttributes(BlockGraph::BlockAttributes attributes, bool expected) {
    BlockGraph::Block* code = image_.AddBlock(BlockGraph::CODE_BLOCK, 40, "c");
    code->set_attributes(attributes);
    ASSERT_EQ(expected, CodeBlockAttributesAreBasicBlockSafe(code));
  }

 private:
  BlockGraph image_;
};

}  // namespace

TEST_F(BlockUtilTest, CodeBlockAttributesAreBasicBlockSafeGapBlock) {
  ASSERT_NO_FATAL_FAILURE(TestAttributes(BlockGraph::GAP_BLOCK, false));
}

TEST_F(BlockUtilTest, CodeBlockAttributesAreBasicBlockSafePaddingBlock) {
  ASSERT_NO_FATAL_FAILURE(TestAttributes(BlockGraph::PADDING_BLOCK, false));
}

TEST_F(BlockUtilTest, CodeBlockAttributesAreBasicBlockSafeHasInlineAssembly) {
  ASSERT_NO_FATAL_FAILURE(TestAttributes(BlockGraph::HAS_INLINE_ASSEMBLY,
                                         false));
}

TEST_F(BlockUtilTest, CodeBlockAttributesAreBasicBlockSafeUnsupportedCompiler) {
  ASSERT_NO_FATAL_FAILURE(TestAttributes(
      BlockGraph::BUILT_BY_UNSUPPORTED_COMPILER, false));
}

TEST_F(BlockUtilTest, CodeBlockAttributesAreBasicBlockSafeErroredDisassembly) {
  ASSERT_NO_FATAL_FAILURE(TestAttributes(BlockGraph::ERRORED_DISASSEMBLY,
                                         false));
}

TEST_F(BlockUtilTest, CodeBlockAttributesAreBasicBlockSafeExceptionHandling) {
  ASSERT_NO_FATAL_FAILURE(TestAttributes(BlockGraph::HAS_EXCEPTION_HANDLING,
                                         false));
}

TEST_F(BlockUtilTest, CodeBlockAttributesAreBasicBlockSafeDisassembledPastEnd) {
  ASSERT_NO_FATAL_FAILURE(TestAttributes(BlockGraph::DISASSEMBLED_PAST_END,
                                         false));
}

TEST_F(BlockUtilTest, CodeBlockAttributesAreBasicBlockSafeBuiltBySyzygy) {
  ASSERT_NO_FATAL_FAILURE(TestAttributes(
      BlockGraph::HAS_INLINE_ASSEMBLY | BlockGraph::BUILT_BY_SYZYGY, true));
}

}  // namespace block_graph
