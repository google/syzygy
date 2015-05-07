// Copyright 2015 Google Inc. All Rights Reserved.
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

#include "syzygy/pe/hot_patching_writer.h"

#include <memory>

#include "gtest/gtest.h"
#include "syzygy/block_graph/basic_block_assembler.h"
#include "syzygy/block_graph/basic_block_subgraph.h"
#include "syzygy/block_graph/block_builder.h"
#include "syzygy/pe/hot_patching_decomposer.h"
#include "syzygy/pe/hot_patching_unittest_util.h"

namespace pe {

namespace {

using block_graph::BlockGraph;
using block_graph::BlockBuilder;
using block_graph::BasicCodeBlock;
using block_graph::BasicBlockSubGraph;
using block_graph::BasicBlockAssembler;
using block_graph::Displacement;
using block_graph::Immediate;
using block_graph::Operand;

const size_t kTestMemorySize = 1024U * 1024U;

// TODO(cseri): This is based on EntryThunkTransform::CreateOneThunk, where it
//     has a comment that is should be made reusable. This class should be
//     renamed and moved into a common location.
class TestBlockCreator {
 public:
  // Set up a basic block subgraph containing a single block description, with
  // that block description containing a single empty basic block, and get an
  // assembler writing into that basic block.
  TestBlockCreator() {
    BasicBlockSubGraph::BlockDescription* block_desc =
        bbsg_.AddBlockDescription("foo",
                                  NULL,
                                  BlockGraph::CODE_BLOCK,
                                  1,
                                  1,
                                  0);
    BasicCodeBlock* bb = bbsg_.AddBasicCodeBlock("foo");
    block_desc->basic_block_order.push_back(bb);
    assm_.reset(new BasicBlockAssembler(bb->instructions().begin(),
                                        &bb->instructions()));
  }

  BasicBlockAssembler* assm() {
    return assm_.get();
  }

  // Builds a block from the instructions in the assembler.
  // @param block_graph A block graph in which the new block should be inserted.
  // @param new_block will contain the newly created block.
  void ToBlock(BlockGraph* block_graph, BlockGraph::Block** new_block) {
    BlockBuilder block_builder(block_graph);
    if (!block_builder.Merge(&bbsg_)) {
      LOG(ERROR) << "Failed to build test block.";
      *new_block = nullptr;
    }

    // Exactly one new block should have been created.
    ASSERT_EQ(1U, block_builder.new_blocks().size());
    *new_block = block_builder.new_blocks()[0];
  }

 private:
  BasicBlockSubGraph bbsg_;
  std::unique_ptr<BasicBlockAssembler> assm_;
};

// Creates a simple block with a return instruction.
// @param return_value The return value of the function in the generated block.
// @param block_graph A block graph in which the new block should be inserted.
// @param new_block will contain the newly created block.
void CreateSimpleTestBlock(int return_value,
                           BlockGraph* block_graph,
                           BlockGraph::Block** new_block) {

  TestBlockCreator block_creator;

  // The goal is to test with a function that returns return_value.
  // Set up our function:
  // 1. MOV EAX, [imm32: return_value]
  // 2. RET

  block_creator.assm()->mov(assm::eax, Immediate(return_value));
  block_creator.assm()->ret();

  ASSERT_NO_FATAL_FAILURE(block_creator.ToBlock(block_graph, new_block));
  ASSERT_NE(nullptr, new_block);
}

// Creates a block that, when executed, calls another block using a PC-relative
// reference.
// @param block_to_call The block to be called.
// @param block_graph A block graph in which the new block should be inserted.
// @param new_block will contain the newly created block.
void CreateTestBlockWithPCRelativeReference(BlockGraph::Block* block_to_call,
                                            BlockGraph* block_graph,
                                            BlockGraph::Block** new_block) {

  TestBlockCreator block_creator;

  // The goal is to test with a function that calls |block_to_call| both via
  // PC-relative reference.
  //
  // The assembly code for the block:
  // 1. MOV EAX, 0
  // 2. CALL block_to_call            // PC-relative reference
  // 3. ADD EAX, 1
  // 4. RET

  // Reset EAX to 1.
  block_creator.assm()->mov(assm::eax, Immediate(1));
  // Use a call instruction to get a PC-relative reference.
  block_creator.assm()->call(Immediate(block_to_call, 0));
  block_creator.assm()->add(assm::eax, Immediate(1));
  block_creator.assm()->ret();

  block_creator.ToBlock(block_graph, new_block);
  ASSERT_NE(nullptr, new_block);
}

// Creates a block that, when executed, returns the address of another block
// using an absolute reference.
// @param referenced_block The block that's address should be returned.
// @param block_graph A block graph in which the new block should be inserted.
// @param new_block will contain the newly created block.
void CreateTestBlockWithAbsoluteReference(BlockGraph::Block* referenced_block,
                                          BlockGraph* block_graph,
                                          BlockGraph::Block** new_block) {

  TestBlockCreator block_creator;

  // This test function returns the address of the block in |block_to_call|.
  //
  // The assembly code for the block:
  // 1. MOV EAX, block_to_call        // absolute reference
  // 2. RET

  block_creator.assm()->mov(assm::eax, Immediate(referenced_block, 0));
  block_creator.assm()->ret();

  block_creator.ToBlock(block_graph, new_block);
  ASSERT_NE(nullptr, new_block);
}

// Using this function pointer type we can call our test functions.
typedef int __stdcall TestFunctionType();

class HotPatchingWriterTest : public testing::Test {
 public:
  HotPatchingWriterTest() : simple_block_(nullptr),
                            simple_proc_(nullptr) {}

  // Creates a simple block and writes it using the member writer. Updates the
  // |simple_block_| and |simple_proc_| members.
  // NOTE: |simple_proc_| is nullptr after the call if the write did not
  //     succeed. This allows testing failure scenarios.
  void CreateAndWriteSimpleBlock() {
    // Test simple block.
    CreateSimpleTestBlock(4, &block_graph_, &simple_block_);
    ASSERT_NE(nullptr, simple_block_);

    // Write the block into memory.
    simple_proc_ = reinterpret_cast<TestFunctionType*>(
        writer_.Write(simple_block_));
  }

 protected:
  // The created test blocks will be inserted into this block graph.
  BlockGraph block_graph_;

  // The block for the simple block is saved as a member so that we set
  // up references to it.
  BlockGraph::Block* simple_block_;

  // The pointer for the simple procedure after written by the writer.
  TestFunctionType* simple_proc_;

  // The hot patching writer used by the tests.
  HotPatchingWriter writer_;
};

}  // namespace

TEST_F(HotPatchingWriterTest, SimpleBlock) {
  // Initialize writer with buffer that has a sufficient size.
  ASSERT_TRUE(writer_.Init(kTestMemorySize));

  // Create and write a simple block that we will call.
  ASSERT_NO_FATAL_FAILURE(CreateAndWriteSimpleBlock());
  ASSERT_NE(nullptr, simple_proc_);

  // Call the block and test the result. Zero EAX before calling to be sure
  // it does not contain the right result beforehand.
  __asm xor eax, eax;
  int test1 = simple_proc_();
  ASSERT_EQ(4, test1);
}

// Test writing a block that has a PC-relative reference.
TEST_F(HotPatchingWriterTest, PCRelativeReference) {
  // Initialize writer with buffer that has a sufficient size.
  ASSERT_TRUE(writer_.Init(kTestMemorySize));

  // Create and write a simple block that we can reference.
  ASSERT_NO_FATAL_FAILURE(CreateAndWriteSimpleBlock());
  ASSERT_NE(nullptr, simple_proc_);

  // Create a block with a PC-relative call.
  BlockGraph::Block* block = nullptr;
  ASSERT_NO_FATAL_FAILURE(CreateTestBlockWithPCRelativeReference(
      simple_block_, &block_graph_, &block));
  ASSERT_NE(nullptr, block);

  // Write the block to executable memory.
  TestFunctionType* test_proc =
      reinterpret_cast<TestFunctionType*>(writer_.Write(block));
  ASSERT_NE(nullptr, test_proc);

  // Call the block and test the result.
  int test_result = test_proc();
  ASSERT_EQ(5, test_result);
}

// Test writing a block that has an absolute reference.
TEST_F(HotPatchingWriterTest, AbsoluteReference) {
  // Initialize writer with buffer that has a sufficient size.
  ASSERT_TRUE(writer_.Init(kTestMemorySize));

  // Create and write a simple block that we can reference.
  ASSERT_NO_FATAL_FAILURE(CreateAndWriteSimpleBlock());
  ASSERT_NE(nullptr, simple_proc_);

  // Create a block with an absolute reference.
  BlockGraph::Block* block = nullptr;
  ASSERT_NO_FATAL_FAILURE(CreateTestBlockWithAbsoluteReference(
      simple_block_, &block_graph_, &block));
  ASSERT_NE(nullptr, block);

  // Write the block to executable memory.
  TestFunctionType* test_proc =
      reinterpret_cast<TestFunctionType*>(writer_.Write(block));
  ASSERT_NE(nullptr, test_proc);

  // Call the block and test the result. The expected result is the function
  // pointer of the simple block.
  int test_result = test_proc();
  ASSERT_EQ(reinterpret_cast<int>(simple_proc_), test_result);
}

TEST_F(HotPatchingWriterTest, WriteFailsIfNotEnoughSpace) {
  // Initialize the writer with a buffer that's not big enough to hold the
  // simple test block.
  ASSERT_TRUE(writer_.Init(3U));

  // Writing the block into memory should fail.
  ASSERT_NO_FATAL_FAILURE(CreateAndWriteSimpleBlock());
  ASSERT_EQ(nullptr, simple_proc_);
}

namespace {

// A basic block transform that does not change the basic block subgraph.
class IdentityBasicBlockTransform
    : public block_graph::transforms::NamedBasicBlockSubGraphTransformImpl<
          IdentityBasicBlockTransform> {
 public:
  typedef block_graph::BlockGraph BlockGraph;
  typedef block_graph::BasicBlockSubGraph BasicBlockSubGraph;
  typedef block_graph::TransformPolicyInterface TransformPolicyInterface;

  IdentityBasicBlockTransform() { }

  // @name BasicBlockSubGraphTransformInterface method.
  virtual bool TransformBasicBlockSubGraph(
      const TransformPolicyInterface* policy,
      BlockGraph* block_graph,
      BasicBlockSubGraph* basic_block_subgraph) override {
    return true;
  }

  static const char kTransformName[];
};

const char IdentityBasicBlockTransform::kTransformName[] =
    "IdentityBasicBlockTransform";

class HotPatchingWriterTestDllTest : public testing::HotPatchingTestDllTest {
};

}  // namespace

TEST_F(HotPatchingWriterTestDllTest, Write) {
  ASSERT_NO_FATAL_FAILURE(HotPatchInstrumentTestDll());

  // Load hot patchable library into memory.
  testing::ScopedHMODULE module;
  LoadTestDll(hp_test_dll_path_, &module);

  // Decompose the hot patchable library.
  BlockGraph block_graph;
  pe::ImageLayout layout(&block_graph);
  HotPatchingDecomposer decomposer(module);
  decomposer.Decompose(&layout);

  pe::HotPatchingWriter writer;
  ASSERT_TRUE(writer.Init(kTestMemorySize));

  // The block map changes during the basic block transform, so save the list of
  // blocks to transform first.
  std::vector<BlockGraph::Block*> blocks_to_transform;
  for (auto& entry : block_graph.blocks_mutable()) {
    BlockGraph::Block* block = &entry.second;
    if (block->type() == BlockGraph::CODE_BLOCK &&
        !(block->attributes() & BlockGraph::BUILT_BY_UNSUPPORTED_COMPILER)) {
      blocks_to_transform.push_back(block);
    }
  }

  pe::PETransformPolicy pe_policy;

  bool dllmain_found = false;
  ASSERT_EQ(blocks_to_transform.size(),
            hp_transform_.blocks_prepared().size());

  // NOTE: This test assumes that the blocks IDs are the same order as in the
  //     blocks themselves in the hot patching metadata.
  for (size_t i = 0; i < blocks_to_transform.size(); ++i) {
    BlockGraph::Block* original_block = hp_transform_.blocks_prepared()[i];
    BlockGraph::Block* block = blocks_to_transform[i];
    EXPECT_EQ(block->addr(), original_block->addr());

    // Write the transformed block of DllMain and call the written function.
    // There is no sense testing the other functions as we can't call them
    // without knowing their calling conventions.
    if (original_block->name() == "DllMain") {
      dllmain_found = true;
      std::vector<BlockGraph::Block*> new_blocks;
      IdentityBasicBlockTransform transform;

      const void* old_entry_point = block->data();

      ASSERT_TRUE(pe_policy.BlockIsSafeToBasicBlockDecompose(block));

      // Do a basic block decomposition first, that should ruin the references
      // in the memory.
      ASSERT_TRUE(ApplyBasicBlockSubGraphTransform(&transform,
                                                   &pe_policy,
                                                   &block_graph,
                                                   block,
                                                   &new_blocks));

      ASSERT_EQ(1U, new_blocks.size());
      BlockGraph::Block* transformed_block = new_blocks.front();

      HotPatchingWriter::FunctionPointer new_entry_point =
          writer.Write(transformed_block);
      ASSERT_NE(nullptr, new_entry_point);
      ASSERT_NE(old_entry_point, new_entry_point);

      // Call the DllMain.
      typedef BOOL WINAPI DllMainProc(
        _In_  HINSTANCE hinstDLL,
        _In_  DWORD fdwReason,
        _In_  LPVOID lpvReserved
      );
      reinterpret_cast<DllMainProc*>(new_entry_point)(
          nullptr, DLL_PROCESS_ATTACH, nullptr);
    }
  }
  ASSERT_TRUE(dllmain_found);
}

}  // namespace pe
