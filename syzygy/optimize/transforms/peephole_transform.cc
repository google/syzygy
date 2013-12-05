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

#include "syzygy/optimize/transforms/peephole_transform.h"

#include "syzygy/block_graph/block_graph.h"

namespace optimize {
namespace transforms {

namespace {

using block_graph::BasicBlock;
using block_graph::BasicBlockSubGraph;
using block_graph::BasicCodeBlock;
using block_graph::Instruction;
typedef BasicBlockSubGraph::BBCollection BBCollection;
typedef BasicBlock::Instructions Instructions;

// Match a sequence of three instructions and return them into |instr1|,
// |instr2| and |instr3|.
bool MatchThreeInstructions(const Instructions& instructions,
                            Instructions::iterator where,
                            Instruction** instr1,
                            Instruction** instr2,
                            Instruction** instr3) {
  if (where == instructions.end())
    return false;
  *instr1 = &*where;
  where++;

  if (where == instructions.end())
    return false;
  *instr2 = &*where;
  where++;

  if (where == instructions.end())
    return false;
  *instr3 = &*where;

  return true;
}

// Validate that a given instruction has opcode |opcode| and |reg| as its
// register operand.
bool MatchInstruction1(const Instruction& instr,
                       _InstructionType opcode,
                       _RegisterType reg) {
  const _DInst& repr = instr.representation();
  if (repr.opcode == opcode &&
      repr.ops[0].type == O_REG &&
      repr.ops[0].index == reg) {
    return true;
  }

  return false;
}

// Validate that a given instruction has opcode |opcode| and both |reg1| and
// |reg2| as its register operands.
bool MatchInstruction2(const Instruction& instr,
                       _InstructionType opcode,
                       _RegisterType reg1,
                       _RegisterType reg2) {
  const _DInst& repr = instr.representation();
  if (repr.opcode == opcode &&
      repr.ops[0].type == O_REG &&
      repr.ops[0].index == reg1 &&
      repr.ops[1].type == O_REG &&
      repr.ops[1].index == reg2) {
    return true;
  }

  return false;
}

bool SimplifyEmptyPrologEpilog(Instructions* instructions,
                               Instructions::iterator* where) {
  DCHECK_NE(reinterpret_cast<Instructions*>(NULL), instructions);
  DCHECK_NE(reinterpret_cast<Instructions::iterator*>(NULL), where);

  Instruction* instr1 = NULL;
  Instruction* instr2 = NULL;
  Instruction* instr3 = NULL;
  if (MatchThreeInstructions(*instructions, *where, &instr1,
          &instr2, &instr3) &&
      MatchInstruction1(*instr1, I_PUSH, R_EBP) &&
      MatchInstruction2(*instr2, I_MOV, R_EBP, R_ESP) &&
      MatchInstruction1(*instr3, I_POP, R_EBP)) {
    // Remove the three matched instructions.
    for (int i = 0; i < 3; ++i)
      *where = instructions->erase(*where);
    return true;
  }

  return false;
}

// Simplify a given basic block.
bool SimplifyBasicBlock(BasicBlock* basic_block) {
  DCHECK_NE(reinterpret_cast<BasicBlock*>(NULL), basic_block);

  BasicCodeBlock* bb = BasicCodeBlock::Cast(basic_block);
  if (bb == NULL)
    return false;

  bool changed = false;

  // Match and rewrite based on patterns.
  BasicBlock::Instructions::iterator inst_iter = bb->instructions().begin();
  while (inst_iter != bb->instructions().end()) {
    if (SimplifyEmptyPrologEpilog(&bb->instructions(), &inst_iter)) {
      changed = true;
      continue;
    }

    // Move to the next instruction.
    ++inst_iter;
  }

  return changed;
}

}  // namespace

// Simplify a given subgraph.
bool PeepholeTransform::SimplifySubgraph(BasicBlockSubGraph* subgraph) {
  DCHECK_NE(reinterpret_cast<BasicBlockSubGraph*>(NULL), subgraph);

  bool changed = false;
  BBCollection& basic_blocks = subgraph->basic_blocks();
  BBCollection::iterator it = basic_blocks.begin();
  for (; it != basic_blocks.end(); ++it) {
    if (SimplifyBasicBlock(*it))
      changed = true;
  }

  return changed;
}

bool PeepholeTransform::TransformBasicBlockSubGraph(
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BasicBlockSubGraph* subgraph,
    ApplicationProfile* profile,
    SubGraphProfile* subgraph_profile) {
  DCHECK_NE(reinterpret_cast<TransformPolicyInterface*>(NULL), policy);
  DCHECK_NE(reinterpret_cast<BlockGraph*>(NULL), block_graph);
  DCHECK_NE(reinterpret_cast<BasicBlockSubGraph*>(NULL), subgraph);
  DCHECK_NE(reinterpret_cast<ApplicationProfile*>(NULL), profile);
  DCHECK_NE(reinterpret_cast<SubGraphProfile*>(NULL), subgraph_profile);

  bool changed = false;
  do {
    changed = SimplifySubgraph(subgraph);
    // TODO(etienneb): Add more peephole passes.
  } while (changed);

  return true;
}

}  // namespace transforms
}  // namespace optimize
