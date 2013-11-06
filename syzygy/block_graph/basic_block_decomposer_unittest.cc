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
#include "syzygy/block_graph/basic_block_test_util.h"
#include "syzygy/block_graph/block_graph_serializer.h"
#include "syzygy/core/address.h"
#include "syzygy/core/serialization.h"
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

typedef BlockGraph::Block Block;
typedef BlockGraph::Offset Offset;
typedef BlockGraph::Reference Reference;
typedef BlockGraph::Size Size;

// A helper to count basic blocks of a given type.
size_t CountBasicBlocks(const BasicBlockSubGraph& subgraph,
                        BasicBlock::BasicBlockType type) {
  size_t counter = 0;
  BasicBlockSubGraph::BBCollection::const_iterator bb_it =
      subgraph.basic_blocks().begin();
  for (; bb_it != subgraph.basic_blocks().end(); ++bb_it) {
    if ((*bb_it)->type() == type)
      ++counter;
  }

  return counter;
}

// A helper to count padding basic blocks of a given type.
size_t CountPaddingBasicBlocks(const BasicBlockSubGraph& subgraph,
                               BasicBlock::BasicBlockType type) {
  size_t counter = 0;
  BasicBlockSubGraph::BBCollection::const_iterator bb_it =
      subgraph.basic_blocks().begin();
  for (; bb_it != subgraph.basic_blocks().end(); ++bb_it) {
    if ((*bb_it)->type() == type && (*bb_it)->is_padding())
      ++counter;
  }

  return counter;
}

// A helper comparator to that returns true if lhs and rhs are not adjacent
// and in order.
bool HasGapOrIsOutOfOrder(const BasicBlock* lhs, const BasicBlock* rhs) {
  typedef BasicBlock::Size Size;

  Offset lhs_end = lhs->offset();

  const BasicCodeBlock* lhs_code = BasicCodeBlock::Cast(lhs);
  if (lhs_code != NULL) {
    lhs_end += lhs_code->GetInstructionSize();

    BasicBlock::Successors::const_iterator it(lhs_code->successors().begin());
    for (; it != lhs_code->successors().end(); ++it) {
      lhs_end += it->instruction_size();
    }
  }
  const BasicDataBlock* lhs_data = BasicDataBlock::Cast(lhs);
  if (lhs_data != NULL)
    lhs_end += lhs_data->size();

  return lhs_end != rhs->offset();
}

// A test fixture which generates a block-graph to use for basic-block
// related testing.
// See: basic_block_assembly_func.asm
class BasicBlockDecomposerTest : public testing::BasicBlockTest {
 public:
  void InitBlockGraphFromSerializedFile(const wchar_t* src_relative_path) {
    base::FilePath path = testing::GetSrcRelativePath(src_relative_path);
    file_util::ScopedFILE file(file_util::OpenFile(path, "rb"));
    ASSERT_TRUE(file.get() != NULL);
    core::FileInStream is(file.get());
    core::InArchive ia(&is);
    BlockGraphSerializer bgs;
    ASSERT_TRUE(bgs.Load(&block_graph_, &ia));
  }
};

// Calculates the net size of all bytes covered by the given basic-block
// decomposition.
size_t GetNetBBSize(const BasicBlockSubGraph& bbsg) {
  // We expect the decomposition to cover the entire block.
  size_t net_bb_size = 0;
  for (BasicBlockSubGraph::BBCollection::const_iterator bb_it =
           bbsg.basic_blocks().begin();
       bb_it != bbsg.basic_blocks().end();
       ++bb_it) {
    switch ((*bb_it)->type()) {
      case BasicBlock::BASIC_CODE_BLOCK: {
        const BasicCodeBlock* bcb = BasicCodeBlock::Cast(*bb_it);
        CHECK_NE(reinterpret_cast<const BasicCodeBlock*>(NULL), bcb);
        net_bb_size += bcb->GetInstructionSize();

        for (BasicCodeBlock::Successors::const_iterator succ_it =
                 bcb->successors().begin();
             succ_it != bcb->successors().end();
             ++succ_it) {
          net_bb_size += succ_it->instruction_size();
        }

        break;
      }

      case BasicBlock::BASIC_DATA_BLOCK: {
        const BasicDataBlock* bdb = BasicDataBlock::Cast(*bb_it);
        CHECK_NE(reinterpret_cast<const BasicDataBlock*>(NULL), bdb);
        net_bb_size += bdb->size();
        break;
      }
    }
  }
  return net_bb_size;
}

struct BasicBlockOffsetComparator {
  bool operator()(const BasicBlock* bb0, const BasicBlock* bb1) {
    DCHECK_NE(reinterpret_cast<const BasicBlock*>(NULL), bb0);
    DCHECK_NE(reinterpret_cast<const BasicBlock*>(NULL), bb1);
    return bb0->offset() < bb1->offset();
  }
};

void ValidateHasInlineAssemblyBlock5677(const BasicBlockSubGraph& bbsg) {
  ASSERT_EQ(3u, bbsg.basic_blocks().size());

  // Get the basic blocks sorted by their original offsets.
  std::vector<const BasicBlock*> bbs(bbsg.basic_blocks().begin(),
                                     bbsg.basic_blocks().end());
  std::sort(bbs.begin(), bbs.end(), BasicBlockOffsetComparator());

  // cachedHasSSE2
  // bb0:
  // 0044DA50  push        ebp
  // 0044DA51  mov         ebp,esp
  // 0044DA53  mov         eax,1
  // 0044DA58  sub         esp,14h
  // 0044DA5B  test        byte ptr ds:[41EA07Ch],al
  // 0044DA61  jne         bb2
  EXPECT_EQ(BasicBlock::BASIC_CODE_BLOCK, bbs[0]->type());
  const BasicCodeBlock* bcb0 = BasicCodeBlock::Cast(bbs[0]);
  ASSERT_NE(reinterpret_cast<const BasicCodeBlock*>(NULL), bcb0);
  EXPECT_EQ(0, bcb0->offset());
  EXPECT_EQ(5u, bcb0->instructions().size());
  EXPECT_EQ(17u, bcb0->GetInstructionSize());
  EXPECT_EQ(2u, bcb0->successors().size());

  // bb1:
  // 0044DA63  or          dword ptr ds:[41EA07Ch],eax
  // 0044DA69  xor         eax,eax
  // 0044DA6B  mov         dword ptr [ebp-14h],eax
  // 0044DA6E  mov         dword ptr [ebp-10h],eax
  // 0044DA71  mov         dword ptr [ebp-0Ch],eax
  // 0044DA74  mov         dword ptr [ebp-8],eax
  // 0044DA77  push        ebx
  // 0044DA78  lea         eax,[ebp-14h]
  // 0044DA7B  push        edi
  // 0044DA7C  mov         dword ptr [ebp-4],eax
  // 0044DA7F  mov         eax,1
  // 0044DA84  cpuid
  // 0044DA86  mov         edi,dword ptr [ebp-4]
  // 0044DA89  mov         dword ptr [edi],eax
  // 0044DA8B  mov         dword ptr [edi+4],ebx
  // 0044DA8E  mov         dword ptr [edi+8],ecx
  // 0044DA91  mov         dword ptr [edi+0Ch],edx
  // 0044DA94  mov         eax,dword ptr [ebp-8]
  // 0044DA97  shr         eax,1Ah
  // 0044DA9A  and         al,1
  // 0044DA9C  pop         edi
  // 0044DA9D  mov         byte ptr ds:[041EA078h],al
  // 0044DAA2  pop         ebx
  // 0044DAA3  mov         esp,ebp
  // 0044DAA5  pop         ebp
  // 0044DAA6  ret
  EXPECT_EQ(BasicBlock::BASIC_CODE_BLOCK, bbs[1]->type());
  const BasicCodeBlock* bcb1 = BasicCodeBlock::Cast(bbs[1]);
  ASSERT_NE(reinterpret_cast<const BasicCodeBlock*>(NULL), bcb1);
  EXPECT_EQ(19, bcb1->offset());
  EXPECT_EQ(26u, bcb1->instructions().size());
  EXPECT_EQ(68u, bcb1->GetInstructionSize());
  EXPECT_EQ(0u, bcb1->successors().size());

  // bb2:
  // 0044DAA7  mov         al,byte ptr ds:[041EA078h]
  // 0044DAAC  mov         esp,ebp
  // 0044DAAE  pop         ebp
  // 0044DAAF  ret
  // 0044DAB0
  EXPECT_EQ(BasicBlock::BASIC_CODE_BLOCK, bbs[2]->type());
  const BasicCodeBlock* bcb2 = BasicCodeBlock::Cast(bbs[2]);
  ASSERT_NE(reinterpret_cast<const BasicCodeBlock*>(NULL), bcb2);
  EXPECT_EQ(87, bcb2->offset());
  EXPECT_EQ(4u, bcb2->instructions().size());
  EXPECT_EQ(9u, bcb2->GetInstructionSize());
  EXPECT_EQ(0u, bcb2->successors().size());
}

}  // namespace

TEST_F(BasicBlockDecomposerTest, DecomposeNoSubGraph) {
  ASSERT_NO_FATAL_FAILURE(InitBlockGraph());
  BasicBlockDecomposer bbd(assembly_func_, NULL);
  EXPECT_TRUE(bbd.Decompose());
}

TEST_F(BasicBlockDecomposerTest, DecomposeFailsInvalidCodeDataLayout) {
  // RET, 0x00, INT3.
  static const uint8 kData[] = { 0xC3, 0x00, 0xCC };
  BlockGraph::Block* b = block_graph_.AddBlock(BlockGraph::CODE_BLOCK,
                                               3, "BadCodeDataLayout");
  b->SetData(kData, arraysize(kData));
  b->SetLabel(0, "Code", BlockGraph::CODE_LABEL);
  b->SetLabel(1, "Data", BlockGraph::DATA_LABEL);
  b->SetLabel(2, "Code", BlockGraph::CODE_LABEL);
  BasicBlockDecomposer bbd(b, NULL);
  EXPECT_FALSE(bbd.Decompose());
}

TEST_F(BasicBlockDecomposerTest, Decompose) {
  ASSERT_NO_FATAL_FAILURE(InitBlockGraph());
  ASSERT_NO_FATAL_FAILURE(InitBasicBlockSubGraph());

  // Ensure we have the expected number and types of blocks.
  ASSERT_EQ(kNumBasicBlocks, subgraph_.basic_blocks().size());
  ASSERT_EQ(kNumCodeBasicBlocks,
            CountBasicBlocks(subgraph_, BasicBlock::BASIC_CODE_BLOCK));
  ASSERT_EQ(kNumDataBasicBlocks,
            CountBasicBlocks(subgraph_, BasicBlock::BASIC_DATA_BLOCK));
  ASSERT_EQ(kNumCodePaddingBasicBlocks,
            CountPaddingBasicBlocks(subgraph_, BasicBlock::BASIC_CODE_BLOCK));
  ASSERT_EQ(kNumDataPaddingBasicBlocks,
            CountPaddingBasicBlocks(subgraph_, BasicBlock::BASIC_DATA_BLOCK));

  // There should be no gaps and all of the blocks should be used.
  ASSERT_EQ(1U, subgraph_.block_descriptions().size());
  const BasicBlockSubGraph::BlockDescription& desc =
      subgraph_.block_descriptions().back();
  EXPECT_EQ(kNumBasicBlocks, desc.basic_block_order.size());
  EXPECT_TRUE(
      std::adjacent_find(
          desc.basic_block_order.begin(),
          desc.basic_block_order.end(),
          &HasGapOrIsOutOfOrder) == desc.basic_block_order.end());

  BasicBlockSubGraph::ReachabilityMap rm;
  subgraph_.GetReachabilityMap(&rm);

  // Basic-block 0 - assembly_func.
  ASSERT_TRUE(BasicBlockSubGraph::IsReachable(rm, bbs_[0]));
  ASSERT_FALSE(bbs_[0]->is_padding());
  ASSERT_EQ(BasicBlock::BASIC_CODE_BLOCK, bbs_[0]->type());
  BasicCodeBlock* bb0 = BasicCodeBlock::Cast(bbs_[0]);
  ASSERT_TRUE(bb0 != NULL);
  ASSERT_EQ(4u, bb0->instructions().size());
  ASSERT_EQ(0u, bb0->successors().size());
  BasicBlock::Instructions::const_iterator inst_iter =
      bb0->instructions().begin();
  std::advance(inst_iter, 2);
  ASSERT_EQ(1u, inst_iter->references().size());
  ASSERT_EQ(bbs_[9], inst_iter->references().begin()->second.basic_block());
  std::advance(inst_iter, 1);
  ASSERT_EQ(1u, inst_iter->references().size());
  ASSERT_EQ(bbs_[8], inst_iter->references().begin()->second.basic_block());
  ASSERT_EQ(1u, bbs_[0]->alignment());

  // Basic-block 1 - unreachable-label.
  ASSERT_FALSE(BasicBlockSubGraph::IsReachable(rm, bbs_[1]));
  ASSERT_TRUE(bbs_[1]->is_padding());
  ASSERT_EQ(BasicBlock::BASIC_CODE_BLOCK, bbs_[1]->type());
  BasicCodeBlock* bb1 = BasicCodeBlock::Cast(bbs_[1]);
  ASSERT_EQ(1u, bb1->instructions().size());
  ASSERT_EQ(1u, bb1->successors().size());
  ASSERT_EQ(bbs_[2],
            bb1->successors().front().reference().basic_block());
  ASSERT_EQ(1u, bb1->alignment());

  // Basic-block 2 - case_0.
  ASSERT_TRUE(BasicBlockSubGraph::IsReachable(rm, bbs_[2]));
  ASSERT_FALSE(bbs_[2]->is_padding());
  ASSERT_EQ(BasicBlock::BASIC_CODE_BLOCK, bbs_[2]->type());
  BasicCodeBlock* bb2 = BasicCodeBlock::Cast(bbs_[2]);
  ASSERT_TRUE(bb2 != NULL);
  ASSERT_EQ(2u, bb2->instructions().size());
  ASSERT_EQ(1u, bb2->successors().size());
  ASSERT_EQ(bbs_[3], bb2->successors().front().reference().basic_block());
  ASSERT_EQ(1u, bbs_[2]->alignment());

  // Basic-block 3 - sub eax to jnz.
  ASSERT_TRUE(BasicBlockSubGraph::IsReachable(rm, bbs_[3]));
  ASSERT_FALSE(bbs_[3]->is_padding());
  ASSERT_EQ(BasicBlock::BASIC_CODE_BLOCK, bbs_[3]->type());
  BasicCodeBlock* bb3 = BasicCodeBlock::Cast(bbs_[3]);
  ASSERT_TRUE(bb3 != NULL);
  ASSERT_EQ(1u, bb3->instructions().size());
  ASSERT_EQ(2u, bb3->successors().size());
  ASSERT_EQ(bb3, bb3->successors().front().reference().basic_block());
  ASSERT_EQ(bbs_[4], bb3->successors().back().reference().basic_block());
  ASSERT_EQ(1u, bbs_[3]->alignment());

  // Basic-block 4 - ret.
  ASSERT_TRUE(BasicBlockSubGraph::IsReachable(rm, bbs_[4]));
  ASSERT_FALSE(bbs_[4]->is_padding());
  ASSERT_EQ(BasicBlock::BASIC_CODE_BLOCK, bbs_[4]->type());
  BasicCodeBlock* bb4 = BasicCodeBlock::Cast(bbs_[4]);
  ASSERT_TRUE(bb4 != NULL);
  ASSERT_EQ(1u, bb4->instructions().size());
  ASSERT_EQ(0u, bb4->successors().size());
  ASSERT_EQ(1u, bbs_[4]->alignment());

  // Basic-block 5 - case_1.
  ASSERT_TRUE(BasicBlockSubGraph::IsReachable(rm, bbs_[5]));
  ASSERT_FALSE(bbs_[5]->is_padding());
  ASSERT_EQ(BasicBlock::BASIC_CODE_BLOCK, bbs_[5]->type());
  BasicCodeBlock* bb5 = BasicCodeBlock::Cast(bbs_[5]);
  ASSERT_TRUE(bb5 != NULL);
  ASSERT_EQ(1u, bb5->instructions().size());
  ASSERT_EQ(
      func1_,
      bb5->instructions().front().references().begin()->second.block());
  ASSERT_EQ(1u, bb5->successors().size());
  ASSERT_EQ(bbs_[6], bb5->successors().front().reference().basic_block());
  ASSERT_EQ(1u, bbs_[5]->alignment());

  // Basic-block 6 - case_default.
  ASSERT_TRUE(BasicBlockSubGraph::IsReachable(rm, bbs_[6]));
  ASSERT_FALSE(bbs_[6]->is_padding());
  ASSERT_EQ(BasicBlock::BASIC_CODE_BLOCK, bbs_[6]->type());
  BasicCodeBlock* bb6 = BasicCodeBlock::Cast(bbs_[6]);
  ASSERT_TRUE(bb6 != NULL);
  ASSERT_EQ(2u, bb6->instructions().size());
  ASSERT_EQ(
      func2_,
      bb6->instructions().back().references().begin()->second.block());
  ASSERT_EQ(0u, bb6->successors().size());
  ASSERT_EQ(1u, bbs_[6]->alignment());

  // Basic-block 7 - interrupt_label.
  ASSERT_FALSE(BasicBlockSubGraph::IsReachable(rm, bbs_[7]));
  ASSERT_TRUE(bbs_[7]->is_padding());
  ASSERT_EQ(BasicBlock::BASIC_CODE_BLOCK, bbs_[7]->type());
  BasicCodeBlock* bb7 = BasicCodeBlock::Cast(bbs_[7]);
  ASSERT_TRUE(bb7 != NULL);
  ASSERT_EQ(3u, bb7->instructions().size());
  ASSERT_EQ(0u, bb7->successors().size());
  ASSERT_EQ(1u, bbs_[7]->alignment());

  // Basic-block 8 - jump_table.
  ASSERT_TRUE(BasicBlockSubGraph::IsReachable(rm, bbs_[8]));
  ASSERT_FALSE(bbs_[8]->is_padding());
  ASSERT_EQ(BasicBlock::BASIC_DATA_BLOCK, bbs_[8]->type());
  BasicDataBlock* bb8 = BasicDataBlock::Cast(bbs_[8]);
  ASSERT_TRUE(bb8 != NULL);
  ASSERT_EQ(3 * Reference::kMaximumSize, bb8->size());
  ASSERT_EQ(3u, bb8->references().size());
  ASSERT_EQ(4u, bbs_[8]->alignment());

  // Basic-block 9 - case_table.
  ASSERT_TRUE(BasicBlockSubGraph::IsReachable(rm, bbs_[9]));
  ASSERT_FALSE(bbs_[9]->is_padding());
  ASSERT_EQ(BasicBlock::BASIC_DATA_BLOCK, bbs_[9]->type());
  BasicDataBlock* bb9 = BasicDataBlock::Cast(bbs_[9]);
  ASSERT_TRUE(bb9 != NULL);
  ASSERT_EQ(256, bb9->size());
  ASSERT_EQ(0u, bb9->references().size());
  ASSERT_EQ(4u, bbs_[9]->alignment());

  // Validate all source ranges.
  core::RelativeAddress next_addr(start_addr_);
  for (size_t i = 0; i < bbs_.size(); ++i) {
    const BasicCodeBlock* code_block = BasicCodeBlock::Cast(bbs_[i]);
    const BasicDataBlock* data_block = BasicDataBlock::Cast(bbs_[i]);

    if (code_block != NULL) {
      ASSERT_TRUE(data_block == NULL);

      BasicBlock::Instructions::const_iterator instr_it =
          code_block->instructions().begin();
      for (; instr_it != code_block->instructions().end(); ++instr_it) {
        const Instruction& instr = *instr_it;
        ASSERT_EQ(next_addr, instr.source_range().start());
        ASSERT_EQ(instr.size(), instr.source_range().size());

        next_addr += instr.size();
      }

      BasicBlock::Successors::const_iterator succ_it =
          code_block->successors().begin();
      for (; succ_it != code_block->successors().end(); ++succ_it) {
        const Successor& succ = *succ_it;
        if (succ.source_range().size() != 0) {
          ASSERT_EQ(next_addr, succ.source_range().start());
          ASSERT_EQ(succ.instruction_size(), succ.source_range().size());
        } else {
          ASSERT_EQ(0, succ.instruction_size());
        }

        next_addr += succ.instruction_size();
      }
    }

    if (data_block != NULL) {
      ASSERT_TRUE(code_block == NULL);
      ASSERT_TRUE(data_block->type() == BasicBlock::BASIC_DATA_BLOCK);
      ASSERT_EQ(next_addr, data_block->source_range().start());
      ASSERT_EQ(data_block->size(), data_block->source_range().size());

      next_addr += data_block->size();
    }
  }
}

TEST_F(BasicBlockDecomposerTest, DecomposeBlockWithLabelPastData) {
  ASSERT_NO_FATAL_FAILURE(InitBasicBlockSubGraphWithLabelPastEnd());
}

TEST_F(BasicBlockDecomposerTest, HasInlineAssembly) {
  ASSERT_NO_FATAL_FAILURE(InitBlockGraphFromSerializedFile(
      L"syzygy/block_graph/test_data/has_inline_assembly.bg"));

  BlockGraph::BlockMap::const_iterator block_it = block_graph_.blocks().begin();
  for (; block_it != block_graph_.blocks().end(); ++block_it) {
    const BlockGraph::Block* block = &(block_it->second);

    // We skip the 'master' blocks. These are simply dummy blocks that act as
    // sources and destinations for references, to keep the remaining blocks
    // intact.
    if (block->name() == "CodeMaster" || block->name() == "DataMaster")
      continue;

    BasicBlockSubGraph bbsg;
    BasicBlockDecomposer bbd(block, &bbsg);
    ASSERT_TRUE(bbd.Decompose());
    EXPECT_EQ(block->size(), GetNetBBSize(bbsg));

    // Validate a block in detail.
    if (block->id() == 5677)
      ASSERT_NO_FATAL_FAILURE(ValidateHasInlineAssemblyBlock5677(bbsg));
  }
}

}  // namespace block_graph
