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
#include "syzygy/block_graph/basic_block_assembler.h"
#include "syzygy/protect/protect_lib/code_randomizer.h"

#include <algorithm>
#include <vector>
#include "base/strings/utf_string_conversions.h"
#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "syzygy/block_graph/basic_block_subgraph.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/unittest_util.h"
#include "syzygy/application/application.h"

namespace protect {

namespace {

class CodeRandomizerTest : public testing::Test, public CodeRandomizer {
public:
  typedef block_graph::BlockGraph BlockGraph;
  typedef block_graph::BasicBlockSubGraph BasicBlockSubGraph;
  typedef block_graph::BasicCodeBlock BasicCodeBlock;
  typedef block_graph::BasicBlock BasicBlock;
  typedef block_graph::BasicBlockAssembler BasicBlockAssembler;
  typedef BlockGraph::RelativeAddress RelativeAddress;
  typedef BlockGraph::Block::SourceRange SourceRange;

  CodeRandomizerTest();

  void SetUp() override {}

  void TearDown() override {}

protected:
  struct Ref {
    size_t offset;
    block_graph::BasicBlockReference::ReferredType type;
    const void* reference;
  };

  BlockGraph block_graph_;
  BlockGraph::Block* test_block_;
  block_graph::BasicBlockSubGraph subgraph_;
  BasicCodeBlock* test_bb_;
  BasicBlock::Instructions instructions_;
  BasicBlockAssembler asm_;
};

}
CodeRandomizerTest::CodeRandomizerTest()
  : test_block_(NULL),
  test_bb_(NULL),
  asm_(instructions_.end(), &instructions_) {
  std::srand(std::time(0));
  test_block_ = block_graph_.AddBlock(BlockGraph::CODE_BLOCK, 10, "test block");
  test_bb_ = subgraph_.AddBasicCodeBlock("foo");
}

TEST_F(CodeRandomizerTest, FindSafeRegister) {
  RegState test_state;
  std::vector<const assm::Register32> possible_regs;
  possible_regs.push_back(assm::eax);
  possible_regs.push_back(assm::ebx);
  possible_regs.push_back(assm::ecx);
  possible_regs.push_back(assm::edx);
  possible_regs.push_back(assm::esi);
  possible_regs.push_back(assm::edi);

  std::random_shuffle(possible_regs.begin(), possible_regs.end());

  // Empty state
  bool save_reg = true;
  assm::Register32 reg = CodeRandomizerTest::FindSafeRegister(asm_, test_state, save_reg);

  EXPECT_TRUE(possible_regs.end() != find(possible_regs.begin(), possible_regs.end(), reg));
  EXPECT_FALSE(save_reg);

  while (possible_regs.size() > 1) {
    test_state.Add(possible_regs[0].id());
    possible_regs.erase(possible_regs.begin());
    save_reg = true;

    reg = CodeRandomizerTest::FindSafeRegister(asm_, test_state, save_reg);

    EXPECT_TRUE(possible_regs.end() != find(possible_regs.begin(), possible_regs.end(), reg));
    EXPECT_FALSE(save_reg);
  }

  // Full State, save_reg should be true
  save_reg = false;
  test_state.Add(possible_regs[0].id());
  reg = CodeRandomizerTest::FindSafeRegister(asm_, test_state, save_reg);
  EXPECT_TRUE(save_reg);
}

TEST_F(CodeRandomizerTest, RandModifyEsp) {
  BasicBlock::Instructions instructions;
  BasicBlockAssembler assm(instructions.end(), &instructions);
  Instruction instr;
  RegState state;

  int repeat_times = 10;
  int prev_size = 0;

  while (repeat_times) {
    state.extra_stack = 0;
    state.instruction_count = 0;

    RandModifyESP(assm, state);

    if (instructions.size() == prev_size) {
      EXPECT_EQ(0, state.extra_stack);
      EXPECT_EQ(0, state.instruction_count);

    } else {
      EXPECT_EQ(1, instructions.size() - prev_size);
      EXPECT_EQ(1, state.instruction_count);

      instr = instructions.back();
      //std::cout << instr.representation().ops[0]. << "\n";
      //instr.
    }
  }

}
*/
}