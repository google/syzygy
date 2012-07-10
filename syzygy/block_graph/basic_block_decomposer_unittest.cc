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
// Tests for basic block disassembler.

#include "syzygy/block_graph/basic_block_decomposer.h"

#include <algorithm>
#include <vector>

#include "base/bind.h"
#include "base/command_line.h"
#include "base/file_util.h"
#include "base/memory/scoped_ptr.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/block_graph/block_graph_serializer.h"
#include "syzygy/block_graph/block_util.h"
#include "syzygy/block_graph/unittest_util.h"
#include "syzygy/core/address.h"
#include "syzygy/core/unittest_util.h"

#include "mnemonics.h"  // NOLINT

namespace block_graph {

namespace {

using block_graph::BasicBlock;
using block_graph::BasicBlockSubGraph;
using block_graph::BlockGraph;
using block_graph::BlockGraphSerializer;
using block_graph::Successor;
using core::AbsoluteAddress;
using core::Disassembler;
using testing::_;
using testing::Return;

typedef BasicBlockSubGraph::BBAddressSpace BBAddressSpace;

const wchar_t kSerializedTestDllBlockGraph[] =
    L"syzygy/block_graph/test_data/test_dll_"
#ifdef NDEBUG
    // Release build.
    L"release"
#else
    // Debug/Coverage build.
    L"debug"
#endif
    L".bg";

class TestBasicBlockDecomposer : public BasicBlockDecomposer {
public:
  using BasicBlockDecomposer::on_instruction_;

  explicit TestBasicBlockDecomposer(const BlockGraph::Block* block,
                                    BasicBlockSubGraph* subgraph)
      : BasicBlockDecomposer(block, subgraph) {
    check_decomposition_results_ = true;
  }

};

class BasicBlockDecomposerTest : public ::testing::Test {
public:
  virtual void SetUp() OVERRIDE {
    ::testing::Test::SetUp();

    BlockGraphSerializer bgs;
    FilePath path = testing::GetSrcRelativePath(kSerializedTestDllBlockGraph);
    file_util::ScopedFILE from_file(file_util::OpenFile(path, "rb"));
    core::FileInStream in_stream(from_file.get());
    core::NativeBinaryInArchive in_archive(&in_stream);
    ASSERT_TRUE(bgs.Load(&block_graph_, &in_archive));
  }

  MOCK_METHOD2(OnInstruction,
               Disassembler::CallbackDirective(const Disassembler&,
                                               const _DInst&));
 protected:
  BlockGraph block_graph_;
};


int TypeCount(const BBAddressSpace& the_map,
              BasicBlock::BasicBlockType the_type) {
  int count = 0;
  BBAddressSpace::RangeMapConstIter iter(the_map.begin());
  for (; iter != the_map.end(); ++iter) {
    if (iter->second->type() == the_type)
      ++count;
  }
  return count;
}

int AttributeCount(const BlockGraph::Block::LabelMap& the_map, uint32 mask) {
  int count = 0;
  BlockGraph::Block::LabelMap::const_iterator iter(the_map.begin());
  for (; iter != the_map.end(); ++iter) {
    if (iter->second.has_attributes(mask))
      ++count;
  }
  return count;
}

const BlockGraph::Block* FindBlockByName(const BlockGraph& block_graph,
                                         const base::StringPiece& name) {
  BlockGraph::BlockMap::const_iterator iter = block_graph.blocks().begin();
  BlockGraph::BlockMap::const_iterator iter_end = block_graph.blocks().end();
  for (; iter != iter_end; ++iter) {
    if (name.compare(iter->second.name()) == 0)
      return &iter->second;
  }
  return NULL;
}

bool HasGapOrIsOutOfOrder(const BasicBlock* lhs, const BasicBlock* rhs) {
  typedef BasicBlock::Size Size;
  return lhs->offset() + lhs->size() != static_cast<Size>(rhs->offset());
}

}  // namespace

TEST_F(BasicBlockDecomposerTest, DecomposeDllMain) {
  // Setup our expected constants.
#ifndef NDEBUG
  static const size_t kNumInstructions = 209;
  static const size_t kNumBasicBlocks = 26;
  static const size_t kNumPaddingBlocks = 2;
#else
  static const size_t kNumInstructions = 183;
  static const size_t kNumBasicBlocks = 24;
  static const size_t kNumPaddingBlocks = 1;
#endif  // NDEBUG

  static const size_t kNumLabels = 19;
  static const size_t kNumDataLabels = 4;
  static const size_t kNumDebugLabels = 2;  // Start and end;
  static const size_t kNumCodeLabels =
      kNumLabels - kNumDataLabels - kNumDebugLabels;
  static const size_t kNumDataBlocks = kNumDataLabels;
  static const size_t kNumCodeBlocks =
      kNumBasicBlocks - kNumDataBlocks - kNumPaddingBlocks;

  const BlockGraph::Block* block = FindBlockByName(block_graph_, "DllMain");
  ASSERT_FALSE(block == NULL);

  const BlockGraph::Block::LabelMap& labels = block->labels();
  EXPECT_FALSE(labels.empty());

  // Inspect the labels.
  BlockGraph::Block::LabelMap::const_iterator label_iter = labels.begin();

  EXPECT_EQ(kNumLabels, labels.size());
  EXPECT_EQ(kNumCodeLabels, AttributeCount(labels, BlockGraph::CODE_LABEL));
  EXPECT_EQ(kNumDataLabels, AttributeCount(labels, BlockGraph::DATA_LABEL));
  EXPECT_EQ(1, AttributeCount(labels, BlockGraph::DEBUG_START_LABEL));
  EXPECT_EQ(1, AttributeCount(labels, BlockGraph::DEBUG_END_LABEL));

  BasicBlockSubGraph subgraph;
  TestBasicBlockDecomposer bb_decomposer(block, &subgraph);
  bb_decomposer.on_instruction_ =
      base::Bind(&BasicBlockDecomposerTest::OnInstruction,
                 base::Unretained(this));

  // We should hit kNumInstructions instructions during decomposition.
  EXPECT_CALL(*this, OnInstruction(_, _)).Times(kNumInstructions).
      WillRepeatedly(Return(Disassembler::kDirectiveContinue));
  ASSERT_TRUE(bb_decomposer.Decompose());
  EXPECT_TRUE(subgraph.IsValid());

  const BasicBlockSubGraph::BBAddressSpace& basic_blocks =
      subgraph.original_address_space();

  // All blocks should have been disassembled.
  EXPECT_EQ(kNumBasicBlocks, basic_blocks.size());
  EXPECT_EQ(kNumCodeBlocks,
            TypeCount(basic_blocks, BasicBlock::BASIC_CODE_BLOCK));
  EXPECT_EQ(kNumDataBlocks,
            TypeCount(basic_blocks, BasicBlock::BASIC_DATA_BLOCK));
  EXPECT_EQ(kNumPaddingBlocks,
            TypeCount(basic_blocks, BasicBlock::BASIC_PADDING_BLOCK));
}

TEST_F(BasicBlockDecomposerTest, DecomposeAllCodeBlocks) {
  BlockGraph::BlockMap::const_iterator it = block_graph_.blocks().begin();
  for (; it != block_graph_.blocks().end(); ++it) {
    const BlockGraph::Block* block = &it->second;
    if (block->type() != BlockGraph::CODE_BLOCK)
      continue;

    if (!CodeBlockAttributesAreBasicBlockSafe(block))
      continue;

    BasicBlockSubGraph subgraph;
    TestBasicBlockDecomposer bb_decomposer(block, &subgraph);
    ASSERT_TRUE(bb_decomposer.Decompose());
    EXPECT_TRUE(subgraph.IsValid());
    EXPECT_EQ(1U, subgraph.block_descriptions().size());

    typedef BasicBlockSubGraph::BlockDescription BlockDescription;
    const BlockDescription& desc = subgraph.block_descriptions().back();
    EXPECT_EQ(block->type(), desc.type);
    EXPECT_EQ(block->alignment(), desc.alignment);
    EXPECT_EQ(block->name(), desc.name);
    EXPECT_EQ(block->section(), desc.section);
    EXPECT_EQ(block->attributes(), desc.attributes);
    EXPECT_TRUE(
        std::adjacent_find(
            desc.basic_block_order.begin(),
            desc.basic_block_order.end(),
            &HasGapOrIsOutOfOrder) == desc.basic_block_order.end());
  }
}

}  // namespace block_graph
