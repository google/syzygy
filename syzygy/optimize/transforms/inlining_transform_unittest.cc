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

#include "syzygy/optimize/transforms/inlining_transform.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/block_graph/basic_block.h"
#include "syzygy/block_graph/basic_block_assembler.h"
#include "syzygy/block_graph/basic_block_decomposer.h"
#include "syzygy/block_graph/basic_block_subgraph.h"
#include "syzygy/block_graph/block_builder.h"
#include "syzygy/block_graph/block_graph.h"
#include "syzygy/block_graph/unittest_util.h"
#include "syzygy/optimize/application_profile.h"
#include "syzygy/pe/pe_transform_policy.h"

namespace optimize {
namespace transforms {
namespace {

using block_graph::BasicBlock;
using block_graph::BasicBlockAssembler;
using block_graph::BasicBlockDecomposer;
using block_graph::BasicBlockReference;
using block_graph::BasicBlockSubGraph;
using block_graph::BlockBuilder;
using block_graph::BlockGraph;
using block_graph::Displacement;
using block_graph::Immediate;
using block_graph::Instruction;
using block_graph::Operand;
using block_graph::Successor;
using pe::ImageLayout;
using testing::ElementsAreArray;

typedef block_graph::BasicBlockSubGraph::BasicCodeBlock BasicCodeBlock;

// This enum is used to drive the contents of the callee.
enum CalleeKind {
  // Block DirectTrampoline
  //   dummy: jmp target
  kDirectTrampoline,
  // Block IndirectTrampoline
  //   dummy: jmp [target]
  kIndirectTrampoline,
  // Block RecursiveTrampoline
  //   dummy: jmp dummy
  kRecursiveTrampoline,
};

const uint8 kData[] = { 0x01, 0x02, 0x03, 0x04 };

// _asm ret
const uint8 kCodeRet[] = { 0xC3 };

// _asm push ebp
// _asm mov ebp, esp
// _asm pop ebp
// _asm ret
const uint8 kCodeEmpty[] = { 0x55, 0x8B, 0xEC, 0x5D, 0xC3 };

// _asm ret8
const uint8 kCodeRetWithOffset[] = { 0xC2, 0x08, 0x00 };

// _asm lea esp, [esp + 8]
const uint8 kCodeLeaEsp8[] = { 0x8D, 0x64, 0x24, 0x08, 0xC3 };

// _asm xor eax, eax
const uint8 kCodeRet0[] = { 0x33, 0xC0, 0xC3 };

// _asm xor eax, eax
const uint8 kCodeMov0[] = { 0x33, 0xC0 };

// _asm mov eax, 2Ah
// _asm ret
const uint8 kCodeRet42[] = { 0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3 };

// _asm xor eax, eax
// _asm mov eax, 2Ah
// _asm ret
const uint8 kCodeRetBoth[] = { 0x33, 0xC0, 0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3 };

// _asm mov eax, esp
// _asm ret
const uint8 kCodeMovStack[] = { 0x8B, 0xC4, 0xC3 };

// _asm ret (16x)
const uint8 kCodeBig[] = {
    0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3,
    0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3 };

// _asm je  here
// _asm xor eax, eax
// here:
// _asm ret
const uint8 kCodeJump[] = { 0x74, 0x02, 0x33, 0xC0, 0xC3 };

// here:
// _asm or  eax,eax
// _asm jne here
// _asm ret
const uint8 kCodeSelfJump[] = { 0x0B, 0xC0, 0x75, 0xFC, 0xC3 };

// _asm call  dword ptr [eax]
// _asm ret
const uint8 kCodeIndirectCall[] = { 0xFF, 0x55, 0xF8, 0xC3 };

// _asm push 2
// _asm pop eax
// _asm ret
const uint8 kStackCst[] = { 0x6A, 0x02, 0x58, 0xC3 };

class TestInliningTransform : public InliningTransform {
 public:
  using InliningTransform::subgraph_cache_;
};

class InliningTransformTest : public testing::Test {
 public:
  InliningTransformTest()
      : data_(NULL),
        caller_(NULL),
        callee_(NULL),
        image_(&block_graph_),
        profile_(&image_) {
  }

  virtual void SetUp() {
    caller_ =
        block_graph_.AddBlock(BlockGraph::CODE_BLOCK, sizeof(kCodeRet), "ret");
    DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), caller_);
    caller_->SetData(kCodeRet, sizeof(kCodeRet));
    caller_->SetLabel(0, "code", BlockGraph::CODE_LABEL);

    data_ = block_graph_.AddBlock(BlockGraph::DATA_BLOCK, sizeof(kData), "int");
    DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), data_);
    data_->SetData(kData, sizeof(kData));
  }

 protected:
  void AddBlockFromBuffer(const uint8* data,
                          size_t length,
                          BlockGraph::Block** block);
  void CreateCalleeBlock(CalleeKind kind,
                         BlockGraph::Block* target,
                         BlockGraph::Block** callee);
  void CreateCallSiteToBlock(BlockGraph::Block* callee);
  void ApplyTransformOnCaller();
  void SaveCaller();

  pe::PETransformPolicy policy_;
  BlockGraph block_graph_;
  BlockGraph::Block* data_;
  BlockGraph::Block* caller_;
  BlockGraph::Block* callee_;
  std::vector<uint8> original_;
  BasicBlockSubGraph callee_subgraph_;
  ImageLayout image_;
  ApplicationProfile profile_;
  SubGraphProfile subgraph_profile_;
};

void InliningTransformTest::AddBlockFromBuffer(const uint8* data,
                                               size_t length,
                                               BlockGraph::Block** block) {
  DCHECK_NE(reinterpret_cast<BlockGraph::Block**>(NULL), block);
  *block = block_graph_.AddBlock(BlockGraph::CODE_BLOCK, length, "test");
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), *block);
  (*block)->SetData(data, length);
  (*block)->SetLabel(0, "code", BlockGraph::CODE_LABEL);
}

// Produce a callee block. The content of the body is determined by |kind|.
void InliningTransformTest::CreateCalleeBlock(CalleeKind kind,
                                              BlockGraph::Block* target,
                                              BlockGraph::Block** callee) {
  DCHECK_NE(reinterpret_cast<BlockGraph::Block**>(NULL), callee);
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), *callee);

  // Decompose to subgraph.
  BasicBlockSubGraph subgraph;
  BasicBlockDecomposer decomposer(*callee, &subgraph);
  ASSERT_TRUE(decomposer.Decompose());

  // Retrieve the single basic block.
  ASSERT_EQ(1U, subgraph.basic_blocks().size());
  BasicCodeBlock* code = BasicCodeBlock::Cast(*subgraph.basic_blocks().begin());
  DCHECK_NE(reinterpret_cast<BasicCodeBlock*>(NULL), code);

  // Clear instructions and open an assembler at the start of the basic block.
  BasicBlock::Instructions& instructions = code->instructions();
  instructions.clear();
  BasicBlockAssembler assembler(instructions.begin(), &instructions);

  switch (kind) {
    case kRecursiveTrampoline:
      assembler.jmp(Immediate(code));
      break;
    case kDirectTrampoline: {
      Successor successor(
          Successor::kConditionTrue,
          BasicBlockReference(BlockGraph::PC_RELATIVE_REF, 4, target, 0, 0),
          4);
      code->successors().push_back(successor);
      break;
    }
    case kIndirectTrampoline:
      assembler.jmp(Operand(Displacement(target, 0, 0)));
      break;
    default:
      NOTREACHED() << "Invalid callee kind.";
  }

  // Rebuild block.
  BlockBuilder builder(&block_graph_);
  ASSERT_TRUE(builder.Merge(&subgraph));
  CHECK_EQ(1u, builder.new_blocks().size());
  *callee = *builder.new_blocks().begin();
};

void InliningTransformTest::CreateCallSiteToBlock(BlockGraph::Block* callee) {
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), caller_);
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), callee);

  // Decompose to subgraph.
  BasicBlockSubGraph subgraph;
  BasicBlockDecomposer decomposer(caller_, &subgraph);
  ASSERT_TRUE(decomposer.Decompose());

  // Retrieve the single basic block.
  ASSERT_EQ(1U, subgraph.basic_blocks().size());
  BasicCodeBlock* code = BasicCodeBlock::Cast(*subgraph.basic_blocks().begin());
  DCHECK_NE(reinterpret_cast<BasicCodeBlock*>(NULL), code);

  // Encode a call at the entry of this basic block.
  BasicBlock::Instructions& instructions = code->instructions();
  BasicBlockAssembler assembler(instructions.begin(), &instructions);
  assembler.call(Immediate(callee, 0, 0));

  // Rebuild block.
  BlockBuilder builder(&block_graph_);
  ASSERT_TRUE(builder.Merge(&subgraph));
  CHECK_EQ(1u, builder.new_blocks().size());
  caller_ = *builder.new_blocks().begin();

  // Keep track of the original raw bytes from the caller block.
  SaveCaller();
};

void InliningTransformTest::SaveCaller() {
  // Keep track of the original raw bytes from the caller block.
  ASSERT_LT(0U, caller_->size());
  original_.resize(caller_->size());
  ::memcpy(&original_[0], caller_->data(), caller_->size());
}

void InliningTransformTest::ApplyTransformOnCaller() {
  // Decompose to subgraph.
  BasicBlockSubGraph subgraph;
  BasicBlockDecomposer decomposer(caller_, &subgraph);
  ASSERT_TRUE(decomposer.Decompose());

  // Apply inlining transform.
  InliningTransform tx;
  ASSERT_TRUE(
      tx.TransformBasicBlockSubGraph(&policy_, &block_graph_, &subgraph,
                                     &profile_, &subgraph_profile_));

  // Rebuild block.
  BlockBuilder builder(&block_graph_);
  ASSERT_TRUE(builder.Merge(&subgraph));
  CHECK_EQ(1u, builder.new_blocks().size());
  caller_ = *builder.new_blocks().begin();
}

}  // namespace

TEST_F(InliningTransformTest, SubgraphCache) {
  TestInliningTransform tx;

  // Create a valid inlining candidate.
  ASSERT_NO_FATAL_FAILURE(
      AddBlockFromBuffer(kCodeRet42, sizeof(kCodeRet42), &callee_));
  ASSERT_NO_FATAL_FAILURE(CreateCallSiteToBlock(callee_));

  // The cache must be empty.
  EXPECT_TRUE(tx.subgraph_cache_.empty());

  // Decompose to subgraph.
  BasicBlockSubGraph subgraph;
  BasicBlockDecomposer decomposer(caller_, &subgraph);
  ASSERT_TRUE(decomposer.Decompose());

  // Apply inlining transform.
  ASSERT_TRUE(
      tx.TransformBasicBlockSubGraph(&policy_, &block_graph_, &subgraph,
                                     &profile_, &subgraph_profile_));

  // Expect the subgraph to be cached.
  EXPECT_EQ(1U, tx.subgraph_cache_.size());
}

TEST_F(InliningTransformTest, PreTransformValidation) {
  ASSERT_NO_FATAL_FAILURE(
      AddBlockFromBuffer(kCodeRet, sizeof(kCodeRet), &callee_));
  ASSERT_NO_FATAL_FAILURE(CreateCallSiteToBlock(callee_));

  // Caller and callee aren't modified without applying the transform.
  EXPECT_EQ(6U, caller_->size());
  EXPECT_EQ(1U, callee_->size());
  EXPECT_THAT(kCodeRet, ElementsAreArray(callee_->data(), callee_->size()));
}

TEST_F(InliningTransformTest, InlineTrivialRet) {
  ASSERT_NO_FATAL_FAILURE(
      AddBlockFromBuffer(kCodeRet, sizeof(kCodeRet), &callee_));
  ASSERT_NO_FATAL_FAILURE(CreateCallSiteToBlock(callee_));
  ASSERT_NO_FATAL_FAILURE(ApplyTransformOnCaller());

  // Expect inlining expansion on caller.
  EXPECT_THAT(kCodeRet, ElementsAreArray(caller_->data(), caller_->size()));
  EXPECT_THAT(kCodeRet, ElementsAreArray(callee_->data(), callee_->size()));
}

TEST_F(InliningTransformTest, InlineTrivialRet0) {
  ASSERT_NO_FATAL_FAILURE(
      AddBlockFromBuffer(kCodeRet0, sizeof(kCodeRet0), &callee_));
  ASSERT_NO_FATAL_FAILURE(CreateCallSiteToBlock(callee_));
  ASSERT_NO_FATAL_FAILURE(ApplyTransformOnCaller());

  EXPECT_THAT(kCodeRet0, ElementsAreArray(caller_->data(), caller_->size()));
  EXPECT_THAT(kCodeRet0, ElementsAreArray(callee_->data(), callee_->size()));
}

TEST_F(InliningTransformTest, InlineTrivialRet42) {
  ASSERT_NO_FATAL_FAILURE(
      AddBlockFromBuffer(kCodeRet42, sizeof(kCodeRet42), &callee_));
  ASSERT_NO_FATAL_FAILURE(CreateCallSiteToBlock(callee_));
  ASSERT_NO_FATAL_FAILURE(ApplyTransformOnCaller());

  EXPECT_THAT(kCodeRet42, ElementsAreArray(caller_->data(), caller_->size()));
  EXPECT_THAT(kCodeRet42, ElementsAreArray(callee_->data(), callee_->size()));
}

TEST_F(InliningTransformTest, InlineEmptyBody) {
  ASSERT_NO_FATAL_FAILURE(
      AddBlockFromBuffer(kCodeEmpty, sizeof(kCodeEmpty), &callee_));
  ASSERT_NO_FATAL_FAILURE(CreateCallSiteToBlock(callee_));
  ASSERT_NO_FATAL_FAILURE(ApplyTransformOnCaller());

  EXPECT_THAT(kCodeRet, ElementsAreArray(caller_->data(), caller_->size()));
}

TEST_F(InliningTransformTest, InlineTrivialTwoCalls) {
  BlockGraph::Block* callee1 = NULL;
  BlockGraph::Block* callee2 = NULL;

  ASSERT_NO_FATAL_FAILURE(
      AddBlockFromBuffer(kCodeRet0, sizeof(kCodeRet0), &callee1));
  ASSERT_NO_FATAL_FAILURE(
      AddBlockFromBuffer(kCodeRet42, sizeof(kCodeRet42), &callee2));

  ASSERT_NO_FATAL_FAILURE(CreateCallSiteToBlock(callee2));
  ASSERT_NO_FATAL_FAILURE(CreateCallSiteToBlock(callee1));

  ASSERT_NO_FATAL_FAILURE(ApplyTransformOnCaller());

  // Expect both calls to be inlined and instructions to be in the right order.
  EXPECT_THAT(kCodeRetBoth,
              ElementsAreArray(caller_->data(), caller_->size()));
}

TEST_F(InliningTransformTest, InlineReturnWithOffset) {
  ASSERT_NO_FATAL_FAILURE(
      AddBlockFromBuffer(kCodeRetWithOffset,
                         sizeof(kCodeRetWithOffset),
                         &callee_));
  ASSERT_NO_FATAL_FAILURE(CreateCallSiteToBlock(callee_));
  ASSERT_NO_FATAL_FAILURE(ApplyTransformOnCaller());

  // A return with an offset is inlined.
  EXPECT_THAT(kCodeLeaEsp8, ElementsAreArray(caller_->data(), caller_->size()));
}

TEST_F(InliningTransformTest, DontInlineStackManipulation) {
  ASSERT_NO_FATAL_FAILURE(
      AddBlockFromBuffer(kCodeMovStack, sizeof(kCodeMovStack), &callee_));
  ASSERT_NO_FATAL_FAILURE(CreateCallSiteToBlock(callee_));
  ASSERT_NO_FATAL_FAILURE(ApplyTransformOnCaller());

  // Taking address of the stack cannot be inlined. (i.e. stack manipulation).
  EXPECT_THAT(original_, ElementsAreArray(caller_->data(), caller_->size()));
}

TEST_F(InliningTransformTest, DontInlineIndirectCall) {
  ASSERT_NO_FATAL_FAILURE(
      AddBlockFromBuffer(kCodeRetWithOffset,
                         sizeof(kCodeRetWithOffset),
                         &callee_));
  ASSERT_NO_FATAL_FAILURE(
      AddBlockFromBuffer(kCodeIndirectCall,
                         sizeof(kCodeIndirectCall),
                         &caller_));
  ASSERT_NO_FATAL_FAILURE(SaveCaller());
  ASSERT_NO_FATAL_FAILURE(ApplyTransformOnCaller());

  // Taking address of the stack cannot be inlined. (i.e. stack manipulation).
  EXPECT_THAT(original_, ElementsAreArray(caller_->data(), caller_->size()));
}

TEST_F(InliningTransformTest, DontInlineNoReturn) {
  ASSERT_NO_FATAL_FAILURE(
      AddBlockFromBuffer(kCodeMov0, sizeof(kCodeMov0), &callee_));
  ASSERT_NO_FATAL_FAILURE(CreateCallSiteToBlock(callee_));
  ASSERT_NO_FATAL_FAILURE(ApplyTransformOnCaller());

  // No returns found, could not inlined.
  EXPECT_THAT(original_, ElementsAreArray(caller_->data(), caller_->size()));
}

TEST_F(InliningTransformTest, DontInlineData) {
    BlockGraph::Block* data_ =
        block_graph_.AddBlock(BlockGraph::DATA_BLOCK, sizeof(kCodeRet0), "d1");
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), data_);
  data_->SetData(kCodeRet0, sizeof(kCodeRet0));
  ASSERT_NO_FATAL_FAILURE(CreateCallSiteToBlock(data_));
  ASSERT_NO_FATAL_FAILURE(ApplyTransformOnCaller());

  // Data block cannot be inlined.
  EXPECT_THAT(original_, ElementsAreArray(caller_->data(), caller_->size()));
}

TEST_F(InliningTransformTest, DontInlineForwardControlFlow) {
  ASSERT_NO_FATAL_FAILURE(
      AddBlockFromBuffer(kCodeJump, sizeof(kCodeJump), &callee_));
  ASSERT_NO_FATAL_FAILURE(CreateCallSiteToBlock(callee_));
  ASSERT_NO_FATAL_FAILURE(ApplyTransformOnCaller());

  EXPECT_THAT(original_, ElementsAreArray(caller_->data(), caller_->size()));
}

TEST_F(InliningTransformTest, DontInlineSelfControlFlow) {
  ASSERT_NO_FATAL_FAILURE(
      AddBlockFromBuffer(kCodeSelfJump, sizeof(kCodeSelfJump), &callee_));
  ASSERT_NO_FATAL_FAILURE(CreateCallSiteToBlock(callee_));
  ASSERT_NO_FATAL_FAILURE(ApplyTransformOnCaller());

  EXPECT_THAT(original_, ElementsAreArray(caller_->data(), caller_->size()));
}

TEST_F(InliningTransformTest, DontInlineBigBlock) {
  ASSERT_NO_FATAL_FAILURE(
      AddBlockFromBuffer(kCodeBig, sizeof(kCodeBig), &callee_));
  ASSERT_NO_FATAL_FAILURE(CreateCallSiteToBlock(callee_));
  ASSERT_NO_FATAL_FAILURE(ApplyTransformOnCaller());

  // Big block cannot be inlined.
  EXPECT_THAT(original_, ElementsAreArray(caller_->data(), caller_->size()));
}

TEST_F(InliningTransformTest, DontInlineCallerPolicy) {
  ASSERT_NO_FATAL_FAILURE(
      AddBlockFromBuffer(kCodeRet0, sizeof(kCodeRet0), &callee_));
  ASSERT_NO_FATAL_FAILURE(CreateCallSiteToBlock(callee_));

  caller_->set_attributes(BlockGraph::HAS_EXCEPTION_HANDLING);
  ASSERT_NO_FATAL_FAILURE(ApplyTransformOnCaller());

  // Cannot inline exception handling. (i.e. policy handling).
  EXPECT_THAT(original_, ElementsAreArray(caller_->data(), caller_->size()));
}

TEST_F(InliningTransformTest, DontInlineCalleePolicy) {
  ASSERT_NO_FATAL_FAILURE(
      AddBlockFromBuffer(kCodeRet0, sizeof(kCodeRet0), &callee_));
  ASSERT_NO_FATAL_FAILURE(CreateCallSiteToBlock(callee_));

  callee_->set_attributes(BlockGraph::HAS_EXCEPTION_HANDLING);
  ASSERT_NO_FATAL_FAILURE(ApplyTransformOnCaller());

  // Cannot inline exception handling. (i.e. policy handling).
  EXPECT_THAT(original_, ElementsAreArray(caller_->data(), caller_->size()));
}

TEST_F(InliningTransformTest, DontInfiniteLoopOnSelfTrampoline) {
  ASSERT_NO_FATAL_FAILURE(
      AddBlockFromBuffer(kCodeRet, sizeof(kCodeRet), &callee_));
  ASSERT_NO_FATAL_FAILURE(
      CreateCalleeBlock(kRecursiveTrampoline, callee_, &callee_));
  ASSERT_NO_FATAL_FAILURE(CreateCallSiteToBlock(callee_));
  ASSERT_NO_FATAL_FAILURE(ApplyTransformOnCaller());
}

TEST_F(InliningTransformTest, InlineTrampolineToCode) {
  BlockGraph::Block* dummy = NULL;
  ASSERT_NO_FATAL_FAILURE(
      AddBlockFromBuffer(kCodeRet42, sizeof(kCodeRet42), &dummy));
  ASSERT_NO_FATAL_FAILURE(
      AddBlockFromBuffer(kCodeRet, sizeof(kCodeRet), &callee_));
  ASSERT_NO_FATAL_FAILURE(
      CreateCalleeBlock(kDirectTrampoline, dummy, &callee_));
  ASSERT_NO_FATAL_FAILURE(CreateCallSiteToBlock(callee_));
  ASSERT_NO_FATAL_FAILURE(ApplyTransformOnCaller());

  // Validate that the reference from caller is to dummy.
  ASSERT_EQ(1U, callee_->references().size());
  BlockGraph::Reference reference = callee_->references().begin()->second;
  EXPECT_EQ(dummy, reference.referenced());
}

TEST_F(InliningTransformTest, DontInlineTrampolineToData) {
  BlockGraph::Block* dummy =
        block_graph_.AddBlock(BlockGraph::DATA_BLOCK, sizeof(kCodeRet0), "d1");
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), dummy);
  dummy->SetData(kCodeRet0, sizeof(kCodeRet0));
  ASSERT_NO_FATAL_FAILURE(
      AddBlockFromBuffer(kCodeRet, sizeof(kCodeRet), &callee_));
  ASSERT_NO_FATAL_FAILURE(
      CreateCalleeBlock(kDirectTrampoline, dummy, &callee_));
  ASSERT_NO_FATAL_FAILURE(CreateCallSiteToBlock(callee_));
  ASSERT_NO_FATAL_FAILURE(ApplyTransformOnCaller());

  // Validate that the reference from caller is still to callee.
  ASSERT_EQ(1U, callee_->references().size());
  BlockGraph::Reference reference = callee_->references().begin()->second;
  EXPECT_EQ(dummy, reference.referenced());
}

TEST_F(InliningTransformTest, InlineIndirectTrampoline) {
  ASSERT_NO_FATAL_FAILURE(
      AddBlockFromBuffer(kCodeRet, sizeof(kCodeRet), &callee_));
  ASSERT_NO_FATAL_FAILURE(
      CreateCalleeBlock(kIndirectTrampoline, data_, &callee_));
  ASSERT_NO_FATAL_FAILURE(CreateCallSiteToBlock(callee_));
  ASSERT_NO_FATAL_FAILURE(ApplyTransformOnCaller());

  // Validate that the reference from caller is to |data_|.
  ASSERT_EQ(1U, callee_->references().size());
  BlockGraph::Reference reference = callee_->references().begin()->second;
  EXPECT_EQ(data_, reference.referenced());
}

TEST_F(InliningTransformTest, InlineConstantOnStack) {
  ASSERT_NO_FATAL_FAILURE(
      AddBlockFromBuffer(kStackCst, sizeof(kStackCst), &callee_));
  ASSERT_NO_FATAL_FAILURE(CreateCallSiteToBlock(callee_));
  ASSERT_NO_FATAL_FAILURE(ApplyTransformOnCaller());

  EXPECT_THAT(kStackCst, ElementsAreArray(caller_->data(), caller_->size()));
}

}  // namespace transforms
}  // namespace optimize
