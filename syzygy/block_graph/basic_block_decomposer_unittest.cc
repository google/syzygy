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
#include <memory>
#include <vector>

#include "base/bind.h"
#include "base/command_line.h"
#include "base/files/file_util.h"
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
    base::ScopedFILE file(base::OpenFile(path, "rb"));
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
  ASSERT_EQ(4u, bbsg.basic_blocks().size());

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

  EXPECT_EQ(BasicBlock::BASIC_END_BLOCK, bbs[3]->type());
}

}  // namespace

TEST_F(BasicBlockDecomposerTest, DecomposeNoSubGraph) {
  ASSERT_NO_FATAL_FAILURE(InitBlockGraph());
  BasicBlockDecomposer bbd(assembly_func_, NULL);
  EXPECT_TRUE(bbd.Decompose());
  EXPECT_FALSE(bbd.contains_unsupported_instructions());
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
  ASSERT_EQ(kNumEndBasicBlocks,
            CountBasicBlocks(subgraph_, BasicBlock::BASIC_END_BLOCK));
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

  ASSERT_EQ(BasicBlock::BASIC_END_BLOCK, bbs_[10]->type());

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

  BlockGraph::BlockMap::iterator block_it =
      block_graph_.blocks_mutable().begin();
  for (; block_it != block_graph_.blocks().end(); ++block_it) {
    BlockGraph::Block* block = &(block_it->second);

    // We skip the 'master' blocks. These are simply dummy blocks that act as
    // sources and destinations for references, to keep the remaining blocks
    // intact.
    if (block->name() == "CodeMaster" || block->name() == "DataMaster")
      continue;

    BasicBlockSubGraph bbsg;
    BasicBlockDecomposer bbd(block, &bbsg);
    ASSERT_TRUE(bbd.Decompose());
    EXPECT_FALSE(bbd.contains_unsupported_instructions());
    EXPECT_EQ(block->size(), GetNetBBSize(bbsg));

    // Validate a block in detail.
    if (block->id() == 5677)
      ASSERT_NO_FATAL_FAILURE(ValidateHasInlineAssemblyBlock5677(bbsg));
  }
}

TEST_F(BasicBlockDecomposerTest, FailsForBrokenInlineAssembly) {
  static const uint8_t kInvalidInstruction[] = { 0xF0, 0x0F };
  auto block = block_graph_.AddBlock(
      BlockGraph::CODE_BLOCK, sizeof(kInvalidInstruction), "foo");
  block->SetData(kInvalidInstruction, sizeof(kInvalidInstruction));
  block->set_attribute(BlockGraph::HAS_INLINE_ASSEMBLY);

  BasicBlockSubGraph bbsg;
  BasicBlockDecomposer bbd(block, &bbsg);
  ASSERT_FALSE(bbd.Decompose());
  EXPECT_FALSE(bbd.contains_unsupported_instructions());
}

TEST_F(BasicBlockDecomposerTest, ContainsJECXZ) {
  ASSERT_NO_FATAL_FAILURE(InitBlockGraph());
  BlockGraph::Block* jecxz = block_graph_.AddBlock(
      BlockGraph::CODE_BLOCK, 4, "jecxz");
  ASSERT_TRUE(jecxz != NULL);
  jecxz->set_section(text_section_->id());

  // The following bytes are the assembly of the following code:
  //   JECXZ done
  //   DEC ecx
  //   done:
  //   RET
  // The JECXZ instruction has a PC-relative reference at byte 1 to
  // byte 3.
  const uint8_t kAssembly[] = {0xE3, 0x01, 0x49, 0xC3};
  jecxz->CopyData(arraysize(kAssembly), kAssembly);
  jecxz->SetReference(1,
      BlockGraph::Reference(BlockGraph::PC_RELATIVE_REF, 1, jecxz, 3, 3));

  BasicBlockSubGraph bbsg;
  BasicBlockDecomposer bbd(jecxz, &bbsg);
  EXPECT_FALSE(bbd.Decompose());
  EXPECT_TRUE(bbd.contains_unsupported_instructions());
}

TEST_F(BasicBlockDecomposerTest, ContainsCRC32) {
  const uint8_t kAssembly[] = {
      /*
      This is a problem function from Chrome, where distorm has trouble
      decoding the 16-bit form of the CRC32 instruction.

      chrome!sse42::hash_fn [skchecksum_opts.h @ 87]:
         87 0f322673 55              push    ebp
         87 0f322674 8bec            mov     ebp,esp
         90 0f322676 8b550c          mov     edx,dword ptr [ebp+0Ch]
         90 0f322679 56              push    esi
         90 0f32267a 8b7508          mov     esi,dword ptr [ebp+8]
         90 0f32267d 6a0c            push    0Ch
         90 0f32267f 58              pop     eax
         90 0f322680 894508          mov     dword ptr [ebp+8],eax
         90 0f322683 3bd0            cmp     edx,eax
         90 0f322685 7235            jb      chrome!sse42::hash_fn+0x49
      (0f3226bc)

      chrome!sse42::hash_fn+0x14 [skchecksum_opts.h @ 97]:
         97 0f322687 8bc2            mov     eax,edx
         97 0f322689 33d2            xor     edx,edx
         97 0f32268b f77508          div     eax,dword ptr [ebp+8]
         97 0f32268e 53              push    ebx
         97 0f32268f 57              push    edi
         97 0f322690 8b7d10          mov     edi,dword ptr [ebp+10h]
         97 0f322693 8bdf            mov     ebx,edi
         97 0f322695 8bcf            mov     ecx,edi
         98 0f322697 85c0            test    eax,eax
         98 0f322699 7419            je      chrome!sse42::hash_fn+0x41
      (0f3226b4)

      chrome!sse42::hash_fn+0x28 [skchecksum_opts.h @ 99]:
         99 0f32269b f20f38f13e      crc32   edi,dword ptr [esi]
        100 0f3226a0 f20f38f15e04    crc32   ebx,dword ptr [esi+4]
        101 0f3226a6 f20f38f14e08    crc32   ecx,dword ptr [esi+8]
        102 0f3226ac 83c60c          add     esi,0Ch
        102 0f3226af 83e801          sub     eax,1
        102 0f3226b2 75e7            jne     chrome!sse42::hash_fn+0x28
      (0f32269b)

      chrome!sse42::hash_fn+0x41 [skchecksum_opts.h @ 105]:
        105 0f3226b4 33cb            xor     ecx,ebx
        105 0f3226b6 33cf            xor     ecx,edi
        105 0f3226b8 5f              pop     edi
        105 0f3226b9 5b              pop     ebx
        105 0f3226ba eb05            jmp     chrome!sse42::hash_fn+0x4e
      (0f3226c1)

      chrome!sse42::hash_fn+0x49 [skchecksum_opts.h @ 125]:
        125 0f3226bc 33c9            xor     ecx,ecx
        125 0f3226be 8b4d10          mov     ecx,dword ptr [ebp+10h]

      chrome!sse42::hash_fn+0x4e [skchecksum_opts.h @ 109]:
        109 0f3226c1 83fa08          cmp     edx,8
        109 0f3226c4 720b            jb      chrome!sse42::hash_fn+0x5e
      (0f3226d1)

      chrome!sse42::hash_fn+0x53 [skchecksum_opts.h @ 110]:
        110 0f3226c6 f20f38f10e      crc32   ecx,dword ptr [esi]
        111 0f3226cb 83ea04          sub     edx,4
        112 0f3226ce 83c604          add     esi,4

      chrome!sse42::hash_fn+0x5e [skchecksum_opts.h @ 116]:
        116 0f3226d1 f6c204          test    dl,4
        116 0f3226d4 7408            je      chrome!sse42::hash_fn+0x6b
      (0f3226de)

      chrome!sse42::hash_fn+0x63 [skchecksum_opts.h @ 117]:
        117 0f3226d6 f20f38f10e      crc32   ecx,dword ptr [esi]
        118 0f3226db 83c604          add     esi,4

      chrome!sse42::hash_fn+0x6b [skchecksum_opts.h @ 120]:
        120 0f3226de f6c202          test    dl,2
        120 0f3226e1 7409            je      chrome!sse42::hash_fn+0x79
      (0f3226ec)

      chrome!sse42::hash_fn+0x70 [skchecksum_opts.h @ 121]:
        121 0f3226e3 66f20f38f10e    crc32   cx,word ptr [esi]
        122 0f3226e9 83c602          add     esi,2

      chrome!sse42::hash_fn+0x79 [skchecksum_opts.h @ 124]:
        124 0f3226ec f6c201          test    dl,1
        124 0f3226ef 7405            je      chrome!sse42::hash_fn+0x83
      (0f3226f6)

      chrome!sse42::hash_fn+0x7e [skchecksum_opts.h @ 125]:
        125 0f3226f1 f20f38f00e      crc32   ecx,byte ptr [esi]

      chrome!sse42::hash_fn+0x83 [skchecksum_opts.h @ 127]:
        127 0f3226f6 8bc1            mov     eax,ecx
        127 0f3226f8 5e              pop     esi
        128 0f3226f9 5d              pop     ebp
        128 0f3226fa c3              ret
      */
      0x55, 0x8b, 0xec, 0x8b, 0x55, 0x0c, 0x56, 0x8b, 0x75, 0x08, 0x6a, 0x0c,
      0x58, 0x89, 0x45, 0x08, 0x3b, 0xd0, 0x72, 0x35, 0x8b, 0xc2, 0x33, 0xd2,
      0xf7, 0x75, 0x08, 0x53, 0x57, 0x8b, 0x7d, 0x10, 0x8b, 0xdf, 0x8b, 0xcf,
      0x85, 0xc0, 0x74, 0x19, 0xf2, 0x0f, 0x38, 0xf1, 0x3e, 0xf2, 0x0f, 0x38,
      0xf1, 0x5e, 0x04, 0xf2, 0x0f, 0x38, 0xf1, 0x4e, 0x08, 0x83, 0xc6, 0x0c,
      0x83, 0xe8, 0x01, 0x75, 0xe7, 0x33, 0xcb, 0x33, 0xcf, 0x5f, 0x5b, 0xeb,
      0x05, 0x33, 0xc9, 0x8b, 0x4d, 0x10, 0x83, 0xfa, 0x08, 0x72, 0x0b, 0xf2,
      0x0f, 0x38, 0xf1, 0x0e, 0x83, 0xea, 0x04, 0x83, 0xc6, 0x04, 0xf6, 0xc2,
      0x04, 0x74, 0x08, 0xf2, 0x0f, 0x38, 0xf1, 0x0e, 0x83, 0xc6, 0x04, 0xf6,
      0xc2, 0x02, 0x74, 0x09, 0x66, 0xf2, 0x0f, 0x38, 0xf1, 0x0e, 0x83, 0xc6,
      0x02, 0xf6, 0xc2, 0x01, 0x74, 0x05, 0xf2, 0x0f, 0x38, 0xf0, 0x0e, 0x8b,
      0xc1, 0x5e, 0x5d, 0xc3,
  };
  ASSERT_NO_FATAL_FAILURE(InitBlockGraph());
  BlockGraph::Block* crc32 = block_graph_.AddBlock(
      BlockGraph::CODE_BLOCK, arraysize(kAssembly), "crc32");
  ASSERT_TRUE(crc32 != NULL);
  crc32->set_section(text_section_->id());

  crc32->CopyData(arraysize(kAssembly), kAssembly);

  BasicBlockSubGraph bbsg;
  BasicBlockDecomposer bbd(crc32, &bbsg);
  EXPECT_TRUE(bbd.Decompose());
  EXPECT_EQ(15, bbsg.basic_blocks().size());

  /*
  Look for this basic block, which is at offset 0x70 from the start of the
  function.

  chrome!sse42::hash_fn+0x70 [skchecksum_opts.h @ 121]:
    121 0f3226e3 66f20f38f10e    crc32   cx,word ptr [esi]
    122 0f3226e9 83c602          add     esi,2
  */
  BasicCodeBlock* bb70 = nullptr;
  for (auto bb : bbsg.basic_blocks()) {
    if (bb->offset() == 0x70) {
      bb70 = BasicCodeBlock::Cast(bb);
      break;
    }
  }

  ASSERT_TRUE(bb70 != nullptr);

  // Check that the problem instruction has been decoded correctly as to
  // length, register names and operand (access) sizes.
  EXPECT_EQ(2, bb70->instructions().size());
  Instruction inst = bb70->instructions().front();
  EXPECT_EQ(6, inst.size());
  const _DInst& repr = inst.representation();
  EXPECT_EQ(I_CRC32, repr.opcode);

  EXPECT_EQ(O_REG, repr.ops[0].type);
  EXPECT_EQ(R_CX, repr.ops[0].index);
  EXPECT_EQ(16, repr.ops[0].size);

  EXPECT_EQ(16, repr.ops[1].size);
}

}  // namespace block_graph
