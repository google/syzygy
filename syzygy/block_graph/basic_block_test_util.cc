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

#include "syzygy/block_graph/basic_block_test_util.h"

#include "gtest/gtest.h"
#include "syzygy/block_graph/basic_block_decomposer.h"
#include "syzygy/block_graph/basic_block_subgraph.h"

extern "C" {

// Functions invoked or referred by the .asm test stub.
int func1() {
  return 1;
}

int func2() {
  return 2;
}

}  // extern "C"

namespace testing {

namespace {

using block_graph::BlockGraph;

#define POINTER_DIFF(x, y) \
    (reinterpret_cast<const uint8*>(x) - reinterpret_cast<const uint8*>(y))
const int32 kAssemblyFuncSize = POINTER_DIFF(assembly_func_end, assembly_func);
const int32 kCaseTableOffset = POINTER_DIFF(case_table, assembly_func);
const int32 kJumpTableOffset = POINTER_DIFF(jump_table, assembly_func);
const int32 kCase0Offset = POINTER_DIFF(case_0, assembly_func);
const int32 kCase1Offset = POINTER_DIFF(case_1, assembly_func);
const int32 kCaseDefaultOffset = POINTER_DIFF(case_default, assembly_func);
const int32 kInterruptOffset = POINTER_DIFF(interrupt_label, assembly_func);
const int32 kUnreachableOffset = POINTER_DIFF(unreachable_label,
                                              assembly_func);
#undef POINTER_DIFF

const BlockGraph::LabelAttributes kCaseTableAttributes =
    BlockGraph::DATA_LABEL | BlockGraph::CASE_TABLE_LABEL;

const BlockGraph::LabelAttributes kJumpTableAttributes =
    BlockGraph::DATA_LABEL | BlockGraph::JUMP_TABLE_LABEL;

}  // namespace

BasicBlockTest::BasicBlockTest()
    : text_section_(NULL), data_section_(NULL), assembly_func_(NULL),
      func1_(NULL), func2_(NULL), data_(NULL) {
}

void BasicBlockTest::InitBlockGraph() {
  start_addr_ = RelativeAddress(0xF00D);

  text_section_ = block_graph_.AddSection(
      ".text", IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE);
  ASSERT_TRUE(text_section_ != NULL);

  data_section_ = block_graph_.AddSection(
      ".data",
      IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ |
          IMAGE_SCN_MEM_WRITE);
  ASSERT_TRUE(data_section_ != NULL);

  // Create func1, which will be called from assembly_func.
  func1_ = block_graph_.AddBlock(BlockGraph::CODE_BLOCK, 1, "func1");
  ASSERT_TRUE(func1_ != NULL);
  func1_->set_section(text_section_->id());

  // Create func2, a non-returning function called from assembly_func.
  func2_ = block_graph_.AddBlock(BlockGraph::CODE_BLOCK, 1, "func2");
  ASSERT_TRUE(func2_ != NULL);
  func2_->set_attributes(BlockGraph::NON_RETURN_FUNCTION);
  func2_->set_section(text_section_->id());

  // Create a data block to refer to assembly_func.
  data_ = block_graph_.AddBlock(BlockGraph::DATA_BLOCK, 4, "data");
  ASSERT_TRUE(data_ != NULL);
  data_->set_section(data_section_->id());

  // Create assembly_func, and mark it as BUILT_BY_SYZYGY so the basic-block
  // decomposer is willing to process it.
  assembly_func_ = block_graph_.AddBlock(BlockGraph::CODE_BLOCK,
                                         kAssemblyFuncSize,
                                         "assembly_func_");
  ASSERT_TRUE(assembly_func_ != NULL);
  assembly_func_->SetData(reinterpret_cast<const uint8*>(assembly_func),
                          kAssemblyFuncSize);
  assembly_func_->set_attributes(BlockGraph::BUILT_BY_SYZYGY);
  assembly_func_->set_section(text_section_->id());
  assembly_func_->
      source_ranges().Push(Block::DataRange(0, kAssemblyFuncSize),
                           Block::SourceRange(start_addr_, kAssemblyFuncSize));

  // This block contains aligned case and jump tables, so the decomposer would
  // give it pointer alignment.
  assembly_func_->set_alignment(4);

  // Add the data labels.
  ASSERT_TRUE(assembly_func_->SetLabel(
      kCaseTableOffset, "case_table", kCaseTableAttributes));
  ASSERT_TRUE(assembly_func_->SetLabel(
      kJumpTableOffset, "jump_table", kJumpTableAttributes));

  // Add the instruction references to the jump and case tables. Note that
  // the jump table reference is at the end of the indirect jmp instruction
  // (7-bytes) that immediately precedes the unreachable label and that the
  // case table reference is at the end of the movzx instruction which
  // immediately preceeds the jmp.
  ASSERT_TRUE(assembly_func_->SetReference(
      kUnreachableOffset - (Reference::kMaximumSize + 7),
      Reference(BlockGraph::RELATIVE_REF, Reference::kMaximumSize,
                assembly_func_, kCaseTableOffset, kCaseTableOffset)));
  ASSERT_TRUE(assembly_func_->SetReference(
      kUnreachableOffset - Reference::kMaximumSize,
      Reference(BlockGraph::RELATIVE_REF, Reference::kMaximumSize,
                assembly_func_, kJumpTableOffset, kJumpTableOffset)));
  // Add the jump table references to the cases.
  ASSERT_TRUE(assembly_func_->SetReference(
      kJumpTableOffset + (Reference::kMaximumSize * 0),
      Reference(BlockGraph::RELATIVE_REF, Reference::kMaximumSize,
                assembly_func_, kCase0Offset, kCase0Offset)));
  ASSERT_TRUE(assembly_func_->SetReference(
      kJumpTableOffset + (Reference::kMaximumSize * 1),
      Reference(BlockGraph::RELATIVE_REF, Reference::kMaximumSize,
                assembly_func_, kCase1Offset, kCase1Offset)));
  ASSERT_TRUE(assembly_func_->SetReference(
      kJumpTableOffset + (Reference::kMaximumSize * 2),
      Reference(BlockGraph::RELATIVE_REF, Reference::kMaximumSize,
                assembly_func_, kCaseDefaultOffset, kCaseDefaultOffset)));

  // Add the external outbound references.
  ASSERT_TRUE(assembly_func_->SetReference(
      kCase1Offset + 1,
      Reference(BlockGraph::RELATIVE_REF, Reference::kMaximumSize,
                func1_, 0, 0)));
  ASSERT_TRUE(assembly_func_->SetReference(
      kInterruptOffset - Reference::kMaximumSize,
      Reference(BlockGraph::RELATIVE_REF, Reference::kMaximumSize,
                func2_, 0, 0)));

  // Add an inbound reference to the top of the function.
  ASSERT_TRUE(data_->SetReference(
      0,
      Reference(BlockGraph::RELATIVE_REF, Reference::kMaximumSize,
                assembly_func_, 0, 0)));
}

void BasicBlockTest::InitBasicBlockSubGraph() {
  BasicBlockDecomposer bb_decomposer(assembly_func_, &subgraph_);
  logging::SetMinLogLevel(logging::LOG_ERROR_REPORT);
  ASSERT_TRUE(bb_decomposer.Decompose());
  ASSERT_TRUE(subgraph_.IsValid());

  ASSERT_EQ(1u, subgraph_.block_descriptions().size());
  bds_.reserve(subgraph_.block_descriptions().size());
  BasicBlockSubGraph::BlockDescriptionList::iterator bd_it =
      subgraph_.block_descriptions().begin();
  for (; bd_it != subgraph_.block_descriptions().end(); ++bd_it)
    bds_.push_back(&(*bd_it));
  ASSERT_EQ(subgraph_.block_descriptions().size(), bds_.size());

  ASSERT_EQ(kNumBasicBlocks, bds_[0]->basic_block_order.size());
  bbs_.reserve(bds_[0]->basic_block_order.size());
  bbs_.assign(bds_[0]->basic_block_order.begin(),
              bds_[0]->basic_block_order.end());
  ASSERT_EQ(bds_[0]->basic_block_order.size(), bbs_.size());
}

void BasicBlockTest::InitBasicBlockSubGraphWithLabelPastEnd() {
  // We create a simple block-graph containing two blocks. One of them is a
  // simple function that contains a single int3 instruction. The second block
  // contains a call to the first block. The second block has no epilog (given
  // that it calls a non-returning function) and has a debug-end label past the
  // end of the block.
  ASSERT_TRUE(block_graph_.sections().empty());
  ASSERT_TRUE(block_graph_.blocks().empty());

  text_section_ = block_graph_.AddSection(
      ".text", IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE);
  ASSERT_TRUE(text_section_ != NULL);

  func1_ = block_graph_.AddBlock(BlockGraph::CODE_BLOCK, 1, "noret");
  ASSERT_TRUE(func1_ != NULL);
  func1_->ResizeData(1);
  func1_->GetMutableData()[0] = 0xCC;  // int3.
  func1_->SetLabel(0, "noret", BlockGraph::CODE_LABEL);

  func2_ = block_graph_.AddBlock(BlockGraph::CODE_BLOCK, 6, "no_epilog");
  ASSERT_TRUE(func2_ != NULL);
  func2_->ResizeData(6);
  func2_->GetMutableData()[0] = 0xE8;  // call 0x00000000 (non returning).
  func2_->GetMutableData()[5] = 0xCC;  // int3.

  func2_->SetLabel(0, "no_epilog, debug-start",
               BlockGraph::CODE_LABEL | BlockGraph::DEBUG_START_LABEL);
  func2_->SetLabel(6, "debug-end", BlockGraph::DEBUG_END_LABEL);

  func2_->SetReference(1, BlockGraph::Reference(BlockGraph::ABSOLUTE_REF,
                                                4,
                                                func1_,
                                                0,
                                                0));

  // Decompose the second function.
  BasicBlockDecomposer bb_decomposer(func2_, &subgraph_);

  ASSERT_TRUE(bb_decomposer.Decompose());
  ASSERT_TRUE(subgraph_.IsValid());

  ASSERT_EQ(1u, subgraph_.block_descriptions().size());
  ASSERT_EQ(2u, subgraph_.basic_blocks().size());

  BasicBlockSubGraph::BlockDescriptionList::const_iterator bd_it =
      subgraph_.block_descriptions().begin();
  ASSERT_EQ(2u, bd_it->basic_block_order.size());

  BasicBlockSubGraph::BBCollection::const_iterator bb_it =
      subgraph_.basic_blocks().begin();

  const block_graph::BasicBlock* bb = *bb_it;
  const block_graph::BasicCodeBlock* bcb =
      block_graph::BasicCodeBlock::Cast(bb);
  ASSERT_TRUE(bcb != NULL);

  ASSERT_EQ(2u, bcb->instructions().size());
  ASSERT_EQ(1u, bcb->instructions().begin()->references().size());
  ASSERT_TRUE(bcb->instructions().begin()->has_label());
  ASSERT_EQ(BlockGraph::CODE_LABEL | BlockGraph::DEBUG_START_LABEL,
            bcb->instructions().begin()->label().attributes());

  ++bb_it;
  bb = *bb_it;
  const block_graph::BasicEndBlock* beb =
      block_graph::BasicEndBlock::Cast(bb);
  ASSERT_TRUE(beb != NULL);

  BlockGraph::Label expected_label("debug-end", BlockGraph::DEBUG_END_LABEL);
  ASSERT_TRUE(beb->has_label());
  ASSERT_EQ(expected_label, beb->label());

  ++bb_it;
  ASSERT_TRUE(bb_it == subgraph_.basic_blocks().end());
}

}  // namespace testing
