// Copyright 2011 Google Inc.
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

#include "base/scoped_ptr.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/core/address.h"

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

class BasicBlockDisassemblerTest : public testing::Test {
 public:
  virtual void SetUp() {
    on_instruction_.reset(
        NewCallback(this, &BasicBlockDisassemblerTest::OnInstruction));
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
  scoped_ptr<Disassembler::InstructionCallback> on_instruction_;
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
      on_instruction_.get());
  Disassembler::WalkResult result = disasm.Walk();
  EXPECT_EQ(Disassembler::kWalkSuccess, result);

  BasicBlockDisassembler::BBAddressSpace basic_blocks(
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
      on_instruction_.get());
  Disassembler::WalkResult result = disasm.Walk();
  EXPECT_EQ(Disassembler::kWalkSuccess, result);

  BasicBlockDisassembler::BBAddressSpace basic_blocks(
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

}  // namespace block_graph
