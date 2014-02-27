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
// Unittests for iteration primitives.

#include "syzygy/instrument/transforms/entry_call_transform.h"

#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/block_graph/basic_block_assembler.h"
#include "syzygy/block_graph/basic_block_test_util.h"
#include "syzygy/block_graph/transform.h"
#include "syzygy/block_graph/unittest_util.h"
#include "syzygy/common/defs.h"
#include "syzygy/instrument/transforms/unittest_util.h"
#include "syzygy/pe/pe_utils.h"

namespace instrument {
namespace transforms {

namespace {

class TestingEntryCallBasicBlockTransform
    : public EntryCallBasicBlockTransform {
 public:
  TestingEntryCallBasicBlockTransform(
    const BlockGraph::Reference& hook_reference, bool debug_friendly) :
        EntryCallBasicBlockTransform(hook_reference, debug_friendly) {
  }

  // Expose for testing.
  using EntryCallBasicBlockTransform::TransformBasicBlockSubGraph;
};


class EntryCallTransformTest : public testing::TestDllTransformTest {
};

class EntryCallBasicBlockTransformTest : public testing::BasicBlockTest {
 public:
  virtual void SetUp() OVERRIDE {
    // Create a dummy IAT block for our reference.
    dummy_iat_ = block_graph_.AddBlock(BlockGraph::DATA_BLOCK, 1024, "IAT");
    import_ref_ =
        BlockGraph::Reference(BlockGraph::ABSOLUTE_REF,
                              sizeof(core::AbsoluteAddress),
                              dummy_iat_,
                              103 * sizeof(core::AbsoluteAddress),
                              0);
  }

  BlockGraph::Block* TransformAssemblyFunc(bool debug_friendly) {
    EntryCallBasicBlockTransform tx(import_ref_, debug_friendly);

    // Apply the transform.
    block_graph::BlockVector created_blocks;
    EXPECT_TRUE(ApplyBasicBlockSubGraphTransform(
        &tx, &policy_, &block_graph_, assembly_func_, &created_blocks));

    if (created_blocks.size() != 1)
      return NULL;

    return created_blocks[0];
  }

 protected:
  BlockGraph::Block* dummy_iat_;
  BlockGraph::Reference import_ref_;
};

}  // namespace

TEST_F(EntryCallBasicBlockTransformTest, AccessorsAndMutators) {
  EntryCallBasicBlockTransform tx(import_ref_, false);

  EXPECT_STREQ("EntryCallBasicBlockTransform", tx.name());
}

TEST_F(EntryCallBasicBlockTransformTest, ApplyTransform) {
  ASSERT_NO_FATAL_FAILURE(InitBlockGraph());
  ASSERT_NO_FATAL_FAILURE(InitBasicBlockSubGraph());

  // Transform and return a function.
  BlockGraph::Block* created_block = TransformAssemblyFunc(false);
  ASSERT_NE(static_cast<BlockGraph::Block*>(NULL), created_block);

  ASSERT_LE(2U, created_block->size());
  // We expect an indirect call instruction at the start of the block.
  // That's opcode FF, followed by a 0x15 modrm byte.
  ASSERT_EQ(0xFF, created_block->data()[0]);
  ASSERT_EQ(0x15, created_block->data()[1]);

  // Retrieve and check the inserted reference.
  BlockGraph::Reference ref;
  ASSERT_TRUE(created_block->GetReference(2, &ref));
  ASSERT_EQ(import_ref_.referenced(), ref.referenced());
  ASSERT_EQ(import_ref_.offset(), ref.offset());

  // Check that there's no source range for the first byte of the new block.
  EXPECT_TRUE(created_block->source_ranges().FindRangePair(0, 1) == NULL);

  // We expect that the data_ block refers to the head of the new block.
  ASSERT_TRUE(data_->GetReference(0, &ref));
  EXPECT_EQ(created_block, ref.referenced());
  EXPECT_EQ(0, ref.offset());
}

TEST_F(EntryCallBasicBlockTransformTest, ApplyTransformDebugFriendly) {
  ASSERT_NO_FATAL_FAILURE(InitBlockGraph());
  ASSERT_NO_FATAL_FAILURE(InitBasicBlockSubGraph());

  // Transform and return a function.
  BlockGraph::Block* created_block = TransformAssemblyFunc(true);
  ASSERT_NE(static_cast<BlockGraph::Block*>(NULL), created_block);

  // Check that there's a source range for the first byte of the new block.
  EXPECT_TRUE(created_block->source_ranges().FindRangePair(0, 1) != NULL);
}

TEST_F(EntryCallBasicBlockTransformTest, CorrectlyInstrumentsSelfRecursion) {
  using block_graph::BasicBlockAssembler;
  using block_graph::BasicBlockReference;
  using block_graph::BasicCodeBlock;
  using block_graph::Instruction;
  using block_graph::Immediate;
  using block_graph::Successor;

  BasicCodeBlock* code_block = subgraph_.AddBasicCodeBlock("Foo()");
  ASSERT_NE(static_cast<BasicCodeBlock*>(NULL), code_block);
  code_block->set_offset(0);

  // Create the minimal self-recursive function, that also loops to itself.
  BasicBlockAssembler assm(code_block->instructions().begin(),
                           &code_block->instructions());
  assm.call(Immediate(code_block));
  code_block->successors().push_back(
      Successor(Successor::kConditionTrue,
                BasicBlockReference(BlockGraph::PC_RELATIVE_REF,
                                    4,
                                    code_block),
                5));

  BasicBlockSubGraph::BlockDescription* desc =
      subgraph_.AddBlockDescription("Foo()", "foo.obj",
                                    BlockGraph::CODE_BLOCK, 1, 1, 0);
  ASSERT_NE(static_cast<BasicBlockSubGraph::BlockDescription*>(NULL), desc);
  desc->basic_block_order.push_back(code_block);

  TestingEntryCallBasicBlockTransform tx(import_ref_, false);

  // Apply the transform.
  ASSERT_TRUE(
      tx.TransformBasicBlockSubGraph(&policy_, &block_graph_, &subgraph_));

  // Get the entry hook block.
  BasicBlock* entry_hook = desc->basic_block_order.front();
  ASSERT_NE(code_block, entry_hook);

  // Now make sure the self-referential call instruction has been redirected,
  // while the self-referential successor has not.
  ASSERT_EQ(1U, code_block->instructions().size());
  const Instruction& call_inst = code_block->instructions().front();
  ASSERT_EQ(1U, call_inst.references().size());
  ASSERT_TRUE(call_inst.references().begin() != call_inst.references().end());
  const BasicBlockReference& call_ref = call_inst.references().begin()->second;
  EXPECT_EQ(entry_hook, call_ref.basic_block());

  ASSERT_EQ(1U, code_block->successors().size());
  Successor& succ = code_block->successors().front();
  EXPECT_EQ(code_block, succ.reference().basic_block());
}

TEST_F(EntryCallTransformTest, AccessorsAndMutators) {
  EntryCallTransform tx(false);

  EXPECT_STREQ("EntryCallTransform", tx.name());
  EXPECT_STREQ("profile_client.dll", tx.instrument_dll_name());
  EXPECT_EQ(false, tx.debug_friendly());

  tx.set_instrument_dll_name("HulaBonga.dll");
  EXPECT_STREQ("HulaBonga.dll", tx.instrument_dll_name());
}

TEST_F(EntryCallTransformTest, TransformCreatesThunkSection) {
  ASSERT_NO_FATAL_FAILURE(DecomposeTestDll());

  using block_graph::BlockGraph;
  ASSERT_EQ(static_cast<BlockGraph::Section*>(NULL),
            block_graph_.FindSection(common::kThunkSectionName));

  EntryCallTransform transform(false);

  // Run the transform.
  ASSERT_TRUE(ApplyBlockGraphTransform(
      &transform, policy_, &block_graph_, header_block_));

  // Check that the thunks section now exists.
  ASSERT_NE(static_cast<BlockGraph::Section*>(NULL),
            block_graph_.FindSection(common::kThunkSectionName));
}

}  // namespace transforms
}  // namespace instrument
