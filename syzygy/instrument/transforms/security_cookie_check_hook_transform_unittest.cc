// Copyright 2017 Google Inc. All Rights Reserved.
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

#include "syzygy/instrument/transforms/security_cookie_check_hook_transform.h"

#include "gtest/gtest.h"
#include "syzygy/block_graph/basic_block.h"
#include "syzygy/block_graph/basic_block_decomposer.h"
#include "syzygy/block_graph/basic_block_subgraph.h"
#include "syzygy/block_graph/block_graph.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/instrument/transforms/unittest_util.h"
#include "syzygy/pe/unittest_util.h"

#include "mnemonics.h"  // NOLINT

namespace instrument {
namespace transforms {
namespace {

using block_graph::BasicBlock;
using block_graph::BasicBlockDecomposer;
using block_graph::BasicBlockSubGraph;
using block_graph::BasicCodeBlock;
using block_graph::BlockGraph;
using block_graph::Instruction;

class SecurityCookieCheckHookTransformTest
    : public testing::TestDllTransformTest {
 protected:
  void CheckBasicBlockInstrumentation();

  SecurityCookieCheckHookTransform security_cookie_check_hook_;
};

void SecurityCookieCheckHookTransformTest::CheckBasicBlockInstrumentation() {
  bool hit = false;

  BlockGraph::BlockMap::const_iterator block_iter =
      block_graph_.blocks().begin();
  for (; block_iter != block_graph_.blocks().end(); ++block_iter) {
    const BlockGraph::Block& block = block_iter->second;

    // Skip everything but __syzygy_report_gsfailure.
    if (block.name() !=
        SecurityCookieCheckHookTransform::kSyzygyReportGsFailure)
      continue;

    hit = true;

    // Decompose the block to basic-blocks.
    BasicBlockSubGraph subgraph;
    BasicBlockDecomposer bb_decomposer(&block, &subgraph);
    ASSERT_TRUE(bb_decomposer.Decompose());

    // Retrieve the first basic block.
    ASSERT_EQ(1, subgraph.block_descriptions().size());
    const BasicBlockSubGraph::BasicBlockOrdering& original_order =
        subgraph.block_descriptions().front().basic_block_order;
    BasicCodeBlock* first_bb = BasicCodeBlock::Cast(*original_order.begin());
    ASSERT_NE(first_bb, nullptr);

    // Check if the stub is a 'mov [deadbeef], eax' instruction.
    BasicBlockSubGraph::BBCollection::const_iterator bb_iter =
        subgraph.basic_blocks().begin();
    for (; bb_iter != subgraph.basic_blocks().end(); ++bb_iter) {
      const BasicCodeBlock* bb = BasicCodeBlock::Cast(*bb_iter);
      if (bb == nullptr || bb->is_padding())
        continue;

      BasicBlock::Instructions::const_iterator inst_iter =
                                                   bb->instructions().begin(),
                                               end_iter =
                                                   bb->instructions().end();
      ASSERT_NE(inst_iter, end_iter);
      // mov [deadbeef], eax
      const Instruction& inst = *inst_iter;
      const _DInst& representation = inst.representation();
      EXPECT_EQ(I_MOV, representation.opcode);
      EXPECT_EQ(representation.ops[0].type, O_DISP);
      EXPECT_EQ(representation.disp,
                SecurityCookieCheckHookTransform::kInvalidUserAddress);
    }
  }

  EXPECT_TRUE(hit);
}

}  // namespace

TEST_F(SecurityCookieCheckHookTransformTest, ApplyTranform) {
  ASSERT_NO_FATAL_FAILURE(DecomposeTestDll());

  ASSERT_TRUE(block_graph::ApplyBlockGraphTransform(
      &security_cookie_check_hook_, policy_, &block_graph_, header_block_));

  ASSERT_NO_FATAL_FAILURE(CheckBasicBlockInstrumentation());
}

}  // namespace transforms
}  // namespace instrument
