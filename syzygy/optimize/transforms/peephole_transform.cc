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
#include "syzygy/block_graph/analysis/liveness_analysis.h"
#include "syzygy/block_graph/analysis/liveness_analysis_internal.h"

namespace optimize {
namespace transforms {

namespace {

using block_graph::BasicBlock;
using block_graph::BasicBlockSubGraph;
using block_graph::BasicCodeBlock;
using block_graph::Instruction;
using block_graph::analysis::LivenessAnalysis;

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
bool MatchInstructionReg(const Instruction& instr,
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
bool MatchInstructionRegReg(const Instruction& instr,
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

// Validate that a given instruction has opcode |opcode| and both |reg1| and
// |reg2| are register operands.
// @param instr the instruction to match.
// @param opcode the expected opcode.
// @param reg1 receives the first register.
// @param reg2 receives the second register.
// @returns true on a successful match, false otherwise.
bool MatchInstructionRegReg(const Instruction& instr,
                            _InstructionType opcode,
                            _RegisterType* reg1,
                            _RegisterType* reg2) {
  const _DInst& repr = instr.representation();
  if (repr.opcode == opcode &&
      repr.ops[0].type == O_REG &&
      repr.ops[1].type == O_REG) {
    *reg1 = static_cast<_RegisterType>(repr.ops[0].index);
    *reg2 = static_cast<_RegisterType>(repr.ops[1].index);
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
      MatchInstructionReg(*instr1, I_PUSH, R_EBP) &&
      MatchInstructionRegReg(*instr2, I_MOV, R_EBP, R_ESP) &&
      MatchInstructionReg(*instr3, I_POP, R_EBP)) {
    // Remove the three matched instructions.
    for (int i = 0; i < 3; ++i)
      *where = instructions->erase(*where);
    return true;
  }

  return false;
}

// Remove identity pattern like: mov eax, eax.
bool SimplifyIdentityMov(Instructions* instructions,
                         Instructions::iterator* where) {
  DCHECK_NE(reinterpret_cast<Instructions*>(NULL), instructions);
  DCHECK_NE(reinterpret_cast<Instructions::iterator*>(NULL), where);

  const Instruction& instr = **where;
  _RegisterType reg1 = _RegisterType();
  _RegisterType reg2 = _RegisterType();
  if (MatchInstructionRegReg(instr, I_MOV, &reg1, &reg2) &&
      reg1 == reg2) {
    // Remove the matched instruction.
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
    if (SimplifyEmptyPrologEpilog(&bb->instructions(), &inst_iter) ||
        SimplifyIdentityMov(&bb->instructions(), &inst_iter)) {
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

bool PeepholeTransform::RemoveDeadCodeSubgraph(BasicBlockSubGraph* subgraph) {
  DCHECK_NE(reinterpret_cast<BasicBlockSubGraph*>(NULL), subgraph);

  bool changed = false;
  BBCollection& basic_blocks = subgraph->basic_blocks();
  BBCollection::iterator it = basic_blocks.begin();

  // Perform a global liveness analysis.
  LivenessAnalysis liveness;
  liveness.Analyze(subgraph);

  // For each basic block, remove dead instructions.
  for (; it != basic_blocks.end(); ++it) {
    BasicCodeBlock* basic_block = BasicCodeBlock::Cast(*it);
    if (basic_block == NULL)
      continue;

    // Get the liveness state information at the end of this basic block.
    LivenessAnalysis::State state;
    liveness.GetStateAtExitOf(basic_block, &state);

    // Perform a backward traversal to cleanup the code.
    Instructions::reverse_iterator rev_iter_inst =
        basic_block->instructions().rbegin();
    while (rev_iter_inst != basic_block->instructions().rend()) {
      const Instruction& instr = *rev_iter_inst;

      // Move to the previous instruction for next iteration.
      ++rev_iter_inst;

      // Determine whether this instruction has side-effects.
      bool has_side_effects = false;

      LivenessAnalysis::State defs;
      if (!LivenessAnalysis::StateHelper::GetDefsOf(instr, &defs))
        has_side_effects = true;

      LivenessAnalysis::State uses;
      if (!LivenessAnalysis::StateHelper::GetUsesOf(instr, &uses))
        has_side_effects = true;

      // Determine whether this instruction may modify a register used later.
      uint32 id = core::kRegisterMin;
      for (; id < core::kRegisterMax; ++id) {
        core::RegisterId reg_id = static_cast<core::RegisterId>(id);
        const core::Register& reg = core::Register::Get(reg_id);
        if (defs.IsLive(reg) && state.IsLive(reg)) {
          has_side_effects = true;
          break;
        }
      }

      if (defs.AreArithmeticFlagsLive() && state.AreArithmeticFlagsLive())
        has_side_effects = true;

      // Avoid stack manipulation.
      if (defs.IsLive(core::ebp) ||
          defs.IsLive(core::esp) ||
          uses.IsLive(core::ebp) ||
          defs.IsLive(core::esp)) {
        has_side_effects = true;
      }

      // Assume control-flow instructions have side-effects.
      if (instr.IsCall() || instr.IsReturn() || instr.IsControlFlow())
        has_side_effects = true;

      // Only consider general purpose registers.
      const _DInst& repr = instr.representation();
      const _Operand& op = repr.ops[0];
      if (op.type != O_REG ||
          op.index < R_EAX ||
          op.index > R_EDI) {
        has_side_effects = true;
      }

      // Only consider these instructions as valid candidate.
      if (!has_side_effects) {
        switch (repr.opcode) {
          case I_ADD:
          case I_CMP:
          case I_SUB:
          case I_AND:
          case I_OR:
          case I_XOR:
          case I_INC:
          case I_DEC:
          case I_SAR:
          case I_SHR:
          case I_SHL:
          case I_LEA:
          case I_MOV:
            break;
          default:
            has_side_effects = true;
            break;
        }
      }

      // If this instruction does not have side effects, remove it.
      if (!has_side_effects) {
        Instructions::const_iterator it = rev_iter_inst.base();
        rev_iter_inst = Instructions::reverse_iterator(
            basic_block->instructions().erase(it));
        changed = true;

        // Do not propagate liveness backward.
        continue;
      }

      // Propagate the liveness information for the next instruction.
      liveness.PropagateBackward(instr, &state);
    }
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
    changed = false;

    if (SimplifySubgraph(subgraph))
      changed = true;
    if (RemoveDeadCodeSubgraph(subgraph))
      changed = true;
  } while (changed);

  return true;
}

}  // namespace transforms
}  // namespace optimize
