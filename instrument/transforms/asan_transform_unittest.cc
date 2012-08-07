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
// Unittests for the Asan transform.

#include "syzygy/instrument/transforms/asan_transform.h"

#include <vector>

#include "gtest/gtest.h"
#include "syzygy/block_graph/basic_block_assembler.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/decomposer.h"
#include "syzygy/pe/pe_file.h"
#include "syzygy/pe/pe_utils.h"
#include "syzygy/pe/unittest_util.h"
#include "third_party/distorm/files/include/mnemonics.h"

namespace pe {
namespace transforms {

namespace {

using block_graph::BasicBlock;
using block_graph::BasicBlockSubGraph;
using block_graph::BlockGraph;

// A derived class to expose protected members for unit-testing.
class TestAsanBasicBlockTransform : public AsanBasicBlockTransform {
 public:
  using AsanBasicBlockTransform::InstrumentBasicBlock;

  TestAsanBasicBlockTransform(BlockGraph::Reference* hook_write,
                              BlockGraph::Reference* hook_read) :
      AsanBasicBlockTransform(hook_write, hook_read) {
  }
};

class AsanTransformTest : public testing::PELibUnitTest {
 public:
  AsanTransformTest() : dos_header_block_(NULL) {
  }

  virtual void SetUp() OVERRIDE {
  }

  void DecomposeTestDll() {
    FilePath test_dll_path = ::testing::GetOutputRelativePath(kDllName);

    ASSERT_TRUE(pe_file_.Init(test_dll_path));

    pe::ImageLayout layout(&block_graph_);
    pe::Decomposer decomposer(pe_file_);
    ASSERT_TRUE(decomposer.Decompose(&layout));

    dos_header_block_ = layout.blocks.GetBlockByAddress(
      core::RelativeAddress(0));
    ASSERT_TRUE(dos_header_block_ != NULL);
  }

 protected:
  pe::PEFile pe_file_;
  BlockGraph block_graph_;
  BlockGraph::Block* dos_header_block_;
  AsanTransform asan_transform_;
};

}  // namespace

TEST_F(AsanTransformTest, SetInstrumentDLLName) {
  asan_transform_.set_instrument_dll_name("foo");
  ASSERT_EQ(strcmp(asan_transform_.instrument_dll_name(), "foo"), 0);
}

TEST_F(AsanTransformTest, ApplyAsanTransform) {
  ASSERT_NO_FATAL_FAILURE(DecomposeTestDll());

  ASSERT_TRUE(block_graph::ApplyBlockGraphTransform(
      &asan_transform_, &block_graph_, dos_header_block_));

  // TODO(sebmarchand): Ensure that each memory access is instrumented by
  // decomposing each block of the new block-graph into basic blocks and walk
  // through their instructions. For now it's not possible due to an issue with
  // the labels in the new block-graph.
}

TEST_F(AsanTransformTest, InjectAsanHooks) {
  // Set up the references to the hooks needed by SyzyAsan.
  BlockGraph::Block hook_write_access = BlockGraph::Block(0,
      BlockGraph::CODE_BLOCK, 4, "hook_write_access");
  BlockGraph::Reference hook_write_access_ref(BlockGraph::ABSOLUTE_REF, 4,
      &hook_write_access, 0, 0);
  BlockGraph::Block hook_read_access = BlockGraph::Block(0,
      BlockGraph::CODE_BLOCK, 4, "hook_read_access");
  BlockGraph::Reference hook_read_access_ref(BlockGraph::ABSOLUTE_REF, 4,
      &hook_read_access, 4, 0);

  // Generate a basic block with a read and a write access to the memory.
  const int kDataBlockSize = 32;
  uint8 block_data[kDataBlockSize];
  BasicBlock basic_block(0, "test block", BasicBlock::BASIC_CODE_BLOCK,
      BasicBlock::kNoOffset, kDataBlockSize, block_data);
  block_graph::BasicBlockAssembler bb_asm(basic_block.instructions().begin(),
      &basic_block.instructions());
  // Add a read access to the memory.
  bb_asm.mov(core::eax, block_graph::Operand(core::ebx));
  // Add a write access to the memory.
  bb_asm.mov(block_graph::Operand(core::ecx), core::edx);

  // Instrument this basic block.
  TestAsanBasicBlockTransform bb_transform(&hook_write_access_ref,
                                           &hook_read_access_ref);
  ASSERT_TRUE(bb_transform.InstrumentBasicBlock(&basic_block));

  // Ensure that the basic block is well instrumented.

  // We had 2 instructions initially, and for each of them we add 3 other one to
  // call the asan hooks, so we expect to have 2 + 3*2 = 8 instructions.
  ASSERT_EQ(basic_block.instructions().size(), 8);

  // Walk through the instructions to ensure that the Asan hooks have been
  // injected.
  BasicBlock::Instructions::const_iterator iter_inst =
      basic_block.instructions().begin();

  // First we check if the first memory access is instrumented as a read
  // access.
  ASSERT_TRUE((iter_inst++)->representation().opcode == I_PUSH);
  ASSERT_TRUE((iter_inst++)->representation().opcode == I_LEA);
  ASSERT_EQ(iter_inst->references().size(), 1);
  ASSERT_TRUE(
      iter_inst->references().begin()->second.block() == &hook_read_access);
  ASSERT_TRUE((iter_inst++)->representation().opcode == I_CALL);
  ASSERT_TRUE((iter_inst++)->representation().opcode == I_MOV);

  // Then we check if the second memory access is well instrumented as a write
  // access.
  ASSERT_TRUE((iter_inst++)->representation().opcode == I_PUSH);
  ASSERT_TRUE((iter_inst++)->representation().opcode == I_LEA);
  ASSERT_EQ(iter_inst->references().size(), 1);
  ASSERT_TRUE(
      iter_inst->references().begin()->second.block() == &hook_write_access);
  ASSERT_TRUE((iter_inst++)->representation().opcode == I_CALL);
  ASSERT_TRUE((iter_inst++)->representation().opcode == I_MOV);

  ASSERT_TRUE(iter_inst == basic_block.instructions().end());
}

}  // namespace transforms
}  // namespace instrument
