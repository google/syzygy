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

#include "syzygy/block_graph/basic_block_disassembler.h"

#include <vector>

#include "base/bind.h"
#include "base/memory/scoped_ptr.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/core/address.h"

#include "mnemonics.h"  // NOLINT

extern "C" {
// functions and labels exposed from our .asm test stub.
extern int bb_assembly_func();
extern int bb_internal_label();
extern int bb_external_label();
extern int bb_assembly_func_end();

// Functions invoked or referred by the .asm test stub.
int bb_ext_func1() {
  return 1;
}

int bb_ext_func2() {
  return 2;
}

}  // extern "C"

namespace block_graph {

using core::AbsoluteAddress;
using core::Disassembler;
using testing::_;
using testing::ElementsAre;

namespace {

// This class provides a DSL for describing a basic block.
//
// It can be used to test whether a parsed block gets broken down into the
// expected basic blocks. For example:
//
//   EXPECT_THAT(
//       basic_block,
//       DescribedBy(
//           BasicBlockDesk(0x11223344)
//               .AddInst(I_MOV)
//               .AddInst(I_SUB)
//               .AddInst(I_MUL)
//               .AddInst(I_CMP)
//               .AddSucc(I_JNE, 0xAABBCCDD)
//               .AddSucc(I_JMP, 0x99887766)));
//
// Or...
//
//   EXPECT_THAT(
//       basic_block_collection,
//       testing::ElementsAre(
//           DescribedBy(
//               BasicBlockDesk(BlockGraph::BASIC_CODE_BLOCK, 0x11223344)
//                   .AddInst(I_MOV)
//                   .AddSucc(I_JMP, 0x99887766)),
//           DescribedBy(
//               BasicBlockDesk(BlockGraph::BASIC_CODE_BLOCK, 0x11223344)
//                   .AddInst(I_MOV)
//                   .AddSucc(I_JMP, 0x99887766)),
//           ...);
//
// where AddInst() and AddSucc() add instructions and successors to the
// basic block, respectively.
struct BasicBlockDesc {
  struct Instruction {
    uint16 opcode;
    AbsoluteAddress target_addr;
    Instruction(uint16 o, AbsoluteAddress t)
        : opcode(o),
          target_addr(t) {
    }
  };

  typedef std::vector<Instruction> Instructions;
  typedef BasicBlock::Successors Successors;
  typedef BasicBlock::BlockType BlockType;

  explicit BasicBlockDesc(AbsoluteAddress start)
      : block_type(BlockGraph::BASIC_CODE_BLOCK),
        start_addr(start) {
  }

  // Mutate the expected block type.
  BasicBlockDesc& SetType(BlockType& type) {
    block_type = type;
    return *this;
  }

  // Append an instruction to the basic block.
  BasicBlockDesc& AddInst(uint16 opcode) {
    instructions.push_back(Instruction(opcode, AbsoluteAddress(0)));
    return *this;
  }

  // Append an successor (branching) instruction to the basic block.
  BasicBlockDesc& AddSucc(uint16 opcode, AbsoluteAddress target) {
    successors.push_back(
        Successor(Successor::OpCodeToCondition(opcode),
                  target,
                  Successor::SourceRange()));
    EXPECT_TRUE(successors.size() <= 2);
    return *this;
  }

  BlockType block_type;
  AbsoluteAddress start_addr;
  Instructions instructions;
  Successors successors;
};

// Helper function to compare a set of instructions to an expected set.
// @param bb_inst the actual basic block instructions.
// @param exp_inst the expected instructions.
// @returns true if the instruction sequences are the same.
bool SameInstructions(const BasicBlock::Instructions& bb_inst,
                      const BasicBlockDesc::Instructions& exp_inst) {
  BasicBlock::Instructions::const_iterator bb_iter = bb_inst.begin();
  BasicBlockDesc::Instructions::const_iterator exp_iter = exp_inst.begin();

  while (bb_iter != bb_inst.end() && exp_iter != exp_inst.end()) {
    if (bb_iter->representation().opcode != exp_iter->opcode)
      return false;
    ++bb_iter;
    ++exp_iter;
  }

  return bb_iter == bb_inst.end() && exp_iter == exp_inst.end();
}

// Helper function to compare a set of successors to an expected set.
// @param bb_succ the actual basic block successors.
// @param exp_succ the expected successors.
// @returns true if the succcessors are the same.
bool SameSuccessors(const BasicBlock::Successors& bb_succ,
                    const BasicBlockDesc::Successors& exp_succ) {
  BasicBlock::Successors::const_iterator bb_iter = bb_succ.begin();
  BasicBlockDesc::Successors::const_iterator exp_iter = exp_succ.begin();

  while (bb_iter != bb_succ.end() && exp_iter != exp_succ.end()) {
    if (bb_iter->condition() != exp_iter->condition() ||
        bb_iter->original_target_address() !=
            exp_iter->original_target_address()) {
      return false;
    }
    ++bb_iter;
    ++exp_iter;
  }

  return bb_iter == bb_succ.end() && exp_iter == exp_succ.end();
}

// Helper funciton to determine if an given start address and basic block
// is described by a BasicBlockDesc.
// @param expected the description of the expected basic block.
// @param start_addr the actual start address.
// @param bb the actual basic block.
// @returns true if the expected block describes the actual block.
bool DescribesBlock(const BasicBlockDesc& expected,
                    AbsoluteAddress start_addr,
                    const BasicBlock& bb ) {
  if (bb.type() != expected.block_type)
    return false;

  if (start_addr != expected.start_addr)
    return false;

  if (!SameInstructions(bb.instructions(), expected.instructions))
    return false;

  if (!SameSuccessors(bb.successors(), expected.successors))
    return false;

  return true;
}

// A wrapper to integrate the DescribesBlock utility function into the GMock
// framework.
MATCHER_P(DescribedBy, expected, "") {
  return DescribesBlock(expected, arg.first.start(), arg.second);
}

}  // namespace

class BasicBlockDisassemblerTest : public testing::Test {
 public:
  virtual void SetUp() {
    on_instruction_ =
        base::Bind(&BasicBlockDisassemblerTest::OnInstruction,
                   base::Unretained(this));
  }

  MOCK_METHOD3(OnInstruction, void(const Disassembler&, const _DInst&,
                                   Disassembler::CallbackDirective*));

  static AbsoluteAddress AddressOf(const void* ptr) {
    return AbsoluteAddress(reinterpret_cast<size_t>(ptr));
  }

  static const uint8* PointerTo(const void* ptr) {
    return reinterpret_cast<const uint8*>(ptr);
  }

  static int BlockCount(const BasicBlockDisassembler::BBAddressSpace& range_map,
                        BlockGraph::BlockType type) {
    int block_count = 0;
    BasicBlockDisassembler::RangeMapConstIter iter(range_map.begin());
    for (; iter != range_map.end(); ++iter) {
      if (iter->second.type() == type) {
        ++block_count;
      }
    }
    return block_count;
  }

 protected:
  Disassembler::InstructionCallback on_instruction_;
};

TEST_F(BasicBlockDisassemblerTest, BasicCoverage) {
  Disassembler::AddressSet labels;
  labels.insert(AddressOf(&bb_assembly_func));

  EXPECT_CALL(*this, OnInstruction(_, _, _)).Times(9);

  BasicBlockDisassembler disasm(
      PointerTo(&bb_assembly_func),
      PointerTo(&bb_assembly_func_end) - PointerTo(&bb_assembly_func),
      AddressOf(&bb_assembly_func),
      labels,
      "test",
      on_instruction_);
  Disassembler::WalkResult result = disasm.Walk();
  EXPECT_EQ(Disassembler::kWalkSuccess, result);

  const BasicBlockDisassembler::BBAddressSpace& basic_blocks(
      disasm.GetBasicBlockRanges());
  EXPECT_EQ(5, basic_blocks.size());

  // We should have one block that was not disassembled since it was reachable
  // only via a non-referenced internal label and was consequently marked as
  // data.
  EXPECT_EQ(4, BlockCount(basic_blocks, BlockGraph::BASIC_CODE_BLOCK));
  EXPECT_EQ(1, BlockCount(basic_blocks, BlockGraph::BASIC_DATA_BLOCK));
}

TEST_F(BasicBlockDisassemblerTest, BasicCoverageWithLabels) {
  Disassembler::AddressSet labels;
  labels.insert(AddressOf(&bb_assembly_func));

  // This should cause the block that was previously marked as data to be
  // disassembled and marked as code.
  labels.insert(AddressOf(&bb_internal_label));

  // This should cause the basic block containing this label to be broken up.
  labels.insert(AddressOf(&bb_external_label));

  // We should hit 10 instructions.
  EXPECT_CALL(*this, OnInstruction(_, _, _)).Times(10);

  BasicBlockDisassembler disasm(
      PointerTo(&bb_assembly_func),
      PointerTo(&bb_assembly_func_end) - PointerTo(&bb_assembly_func),
      AddressOf(&bb_assembly_func),
      labels,
      "test",
      on_instruction_);
  Disassembler::WalkResult result = disasm.Walk();
  EXPECT_EQ(Disassembler::kWalkSuccess, result);

  const BasicBlockDisassembler::BBAddressSpace& basic_blocks(
      disasm.GetBasicBlockRanges());
  EXPECT_EQ(6, basic_blocks.size());

  // All blocks should have been disassembled and marked as code.
  EXPECT_EQ(6, BlockCount(basic_blocks, BlockGraph::BASIC_CODE_BLOCK));
  EXPECT_EQ(0, BlockCount(basic_blocks, BlockGraph::BASIC_DATA_BLOCK));

  // Check that we have blocks starting at both the internally-referenced label
  // and the external label.
  bool block_starts_at_internal_label = false;
  bool block_starts_at_external_label = false;
  BasicBlockDisassembler::RangeMapConstIter iter(basic_blocks.begin());
  for (; iter != basic_blocks.end(); ++iter) {
    if (iter->first.start() == AddressOf(&bb_internal_label)) {
      block_starts_at_internal_label = true;
    } else if (iter->first.start() == AddressOf(&bb_external_label)) {
      block_starts_at_external_label = true;
    }
  }
  EXPECT_TRUE(block_starts_at_internal_label);
  EXPECT_TRUE(block_starts_at_external_label);
}

TEST_F(BasicBlockDisassemblerTest, Instructions) {
  // Setup all of the label.
  Disassembler::AddressSet labels;
  labels.insert(AddressOf(&bb_assembly_func));
  labels.insert(AddressOf(&bb_internal_label));
  labels.insert(AddressOf(&bb_external_label));

  // Disassemble to basic blocks.
  BasicBlockDisassembler disasm(
      PointerTo(&bb_assembly_func),
      PointerTo(&bb_assembly_func_end) - PointerTo(&bb_assembly_func),
      AddressOf(&bb_assembly_func),
      labels,
      "test",
      Disassembler::InstructionCallback());
  Disassembler::WalkResult result = disasm.Walk();
  EXPECT_EQ(Disassembler::kWalkSuccess, result);

  // Validate that we have the expected number and types of blocks
  const BasicBlockDisassembler::BBAddressSpace& basic_blocks(
      disasm.GetBasicBlockRanges());
  EXPECT_EQ(6, basic_blocks.size());
  EXPECT_EQ(6, BlockCount(basic_blocks, BlockGraph::BASIC_CODE_BLOCK));
  EXPECT_EQ(0, BlockCount(basic_blocks, BlockGraph::BASIC_DATA_BLOCK));

  // The JNZ instruction is 7 bytes after the beginning of bb_assembly func.
  const AbsoluteAddress kAddrJnzTarget = AddressOf(&bb_assembly_func) + 7;

  // The immediate value for the JNZ instruction is to jump -3 instructions
  // from the current instruction pointer. This requires backing up an extra
  // two bytes for the JNZ instruction itself.
  const AbsoluteAddress kJnzImmOffset(-5);

  // The fall-through of the JNZ instrucion is 3 bytes before bb_external_label.
  const AbsoluteAddress kAddrJnzSuccessor = AddressOf(&bb_external_label) - 3;

  // The address of lbl2 is offset from the start of bb_internal_label by one
  // call instruction (1 byte plus a 4-byte address)
  const AbsoluteAddress kAddrLbl2 = AddressOf(&bb_internal_label) + 5;

  // Validate that we have the right instructions.
  EXPECT_THAT(
      basic_blocks,
      ElementsAre(
          DescribedBy(
              BasicBlockDesc(AddressOf(&bb_assembly_func))
                  .AddInst(I_MOV)
                  .AddInst(I_MOV)
                  .AddSucc(I_JMP, kAddrJnzTarget)),
          DescribedBy(
              BasicBlockDesc(kAddrJnzTarget)
                  .AddInst(I_SUB)
                  .AddSucc(I_JNZ, kAddrJnzTarget)
                  .AddSucc(I_JZ, kAddrJnzSuccessor)),
          DescribedBy(
              BasicBlockDesc(kAddrJnzSuccessor)
                  .AddInst(I_MOV)
                  .AddInst(I_NOP)
                  .AddSucc(I_JMP, AddressOf(&bb_external_label))),
          DescribedBy(
              BasicBlockDesc(AddressOf(&bb_external_label))
                  .AddSucc(I_JMP, kAddrLbl2)),
          DescribedBy(
              BasicBlockDesc(AddressOf(&bb_internal_label))
                  .AddInst(I_CALL)
                  .AddSucc(I_JMP, kAddrLbl2)),
          DescribedBy(
              BasicBlockDesc(kAddrLbl2)
                  .AddInst(I_CALL)
                  .AddInst(I_RET))));
}

}  // namespace block_graph
