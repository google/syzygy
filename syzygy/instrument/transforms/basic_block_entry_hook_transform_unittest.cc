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
//
// Coverage instrumentation transform unittests.

#include "syzygy/instrument/transforms/basic_block_entry_hook_transform.h"

#include "gtest/gtest.h"
#include "syzygy/block_graph/basic_block.h"
#include "syzygy/block_graph/basic_block_decomposer.h"
#include "syzygy/block_graph/basic_block_subgraph.h"
#include "syzygy/block_graph/block_graph.h"
#include "syzygy/block_graph/transform.h"
#include "syzygy/block_graph/typed_block.h"
#include "syzygy/common/coverage.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/block_util.h"
#include "syzygy/pe/decomposer.h"
#include "syzygy/pe/unittest_util.h"

#include "mnemonics.h"  // NOLINT

namespace instrument {
namespace transforms {
namespace {

using block_graph::BasicBlock;
using block_graph::BasicBlockDecomposer;
using block_graph::BasicBlockSubGraph;
using block_graph::BlockGraph;
using block_graph::Instruction;

class BasicBlockEntryHookTransformTest : public testing::PELibUnitTest {
 public:
  BasicBlockEntryHookTransformTest() : dos_header_block_(NULL) { }

  void DecomposeTestDll() {
    // Open the PE file.
    ASSERT_TRUE(pe_file_.Init(::testing::GetOutputRelativePath(kDllName)));

    // Initialize the block-graph.
    pe::ImageLayout layout(&block_graph_);
    pe::Decomposer decomposer(pe_file_);
    ASSERT_TRUE(decomposer.Decompose(&layout));

    // Get the DOS header block.
    dos_header_block_ = layout.blocks.GetBlockByAddress(
        core::RelativeAddress(0));
    ASSERT_TRUE(dos_header_block_ != NULL);
  }

  pe::PEFile pe_file_;
  BlockGraph block_graph_;
  BlockGraph::Block* dos_header_block_;
};

}  // namespace

TEST_F(BasicBlockEntryHookTransformTest, DefaultConstructor) {
  BasicBlockEntryHookTransform tx;

  std::string module_name(BasicBlockEntryHookTransform::kDefaultModuleName);
  std::string function_name(BasicBlockEntryHookTransform::kDefaultFunctionName);
  EXPECT_EQ(module_name, tx.module_name());
  EXPECT_EQ(function_name, tx.function_name());
  EXPECT_EQ(0U, tx.bb_addresses().size());
  EXPECT_FALSE(tx.bb_entry_hook_ref().IsValid());
}

TEST_F(BasicBlockEntryHookTransformTest, NamedConstructor) {
  std::string module_name("foo.dll");
  std::string function_name("bar");

  BasicBlockEntryHookTransform tx(module_name, function_name);
  EXPECT_EQ(module_name, tx.module_name());
  EXPECT_EQ(function_name, tx.function_name());
  EXPECT_EQ(0U, tx.bb_addresses().size());
  EXPECT_FALSE(tx.bb_entry_hook_ref().IsValid());
}

TEST_F(BasicBlockEntryHookTransformTest, SetNames) {
  std::string module_name("foo.dll");
  std::string function_name("bar");

  BasicBlockEntryHookTransform tx;
  tx.set_module_name(module_name);
  tx.set_function_name(function_name);
  EXPECT_EQ(module_name, tx.module_name());
  EXPECT_EQ(function_name, tx.function_name());
}

TEST_F(BasicBlockEntryHookTransformTest, ApplyBasicBlockEntryHookTransform) {
  DecomposeTestDll();
  BasicBlockEntryHookTransform tx;
  ASSERT_TRUE(block_graph::ApplyBlockGraphTransform(&tx, &block_graph_,
                                                    dos_header_block_));

  // Let's examine each eligible block to verify that its BB's have been
  // instrumented.
  size_t num_decomposed_blocks = 0;
  size_t total_basic_blocks = 0;
  BlockGraph::BlockMap::const_iterator block_iter =
      block_graph_.blocks().begin();
  for (; block_iter != block_graph_.blocks().end(); ++block_iter) {
    const BlockGraph::Block& block = block_iter->second;

    // Skip ineligible blocks.
    if (block.type() != BlockGraph::CODE_BLOCK)
      continue;
    if (!pe::CodeBlockIsBasicBlockDecomposable(&block))
      continue;

    // Note that we have attempted to validate a block.
    ++num_decomposed_blocks;

    // Decompose the block to basic-blocks.
    BasicBlockSubGraph subgraph;
    BasicBlockDecomposer bb_decomposer(&block, &subgraph);
    ASSERT_TRUE(bb_decomposer.Decompose());

    // Check if each basic block begins with the instrumentation sequence.
    size_t num_basic_blocks = 0;
    BasicBlockSubGraph::BBCollection::const_iterator bb_iter =
        subgraph.basic_blocks().begin();
    for (; bb_iter != subgraph.basic_blocks().end(); ++bb_iter) {
      const BasicBlock& bb = bb_iter->second;
      if (bb.type() != BasicBlock::BASIC_CODE_BLOCK)
        continue;
      ++num_basic_blocks;
      ASSERT_LE(2U, bb.instructions().size());
      const Instruction& inst1 = *(bb.instructions().begin());
      const Instruction& inst2 = *(++bb.instructions().begin());
      EXPECT_EQ(I_PUSH, inst1.representation().opcode);
      EXPECT_EQ(I_CALL, inst2.representation().opcode);
      EXPECT_EQ(1U, inst2.references().size());
      EXPECT_EQ(tx.bb_entry_hook_ref().referenced(),
                inst2.references().begin()->second.block());
    }
    EXPECT_NE(0U, num_basic_blocks);
    total_basic_blocks += num_basic_blocks;
  }

  EXPECT_NE(0U, num_decomposed_blocks);
  EXPECT_EQ(total_basic_blocks, tx.bb_addresses().size());
}

}  // namespace transforms
}  // namespace instrument
