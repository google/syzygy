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

#include "syzygy/block_graph/analysis/memory_access_analysis.h"

#include <queue>
#include <set>
#include <vector>

// TODO(etienneb): liveness analysis internal should be hoisted to an
//     instructions helper namespace, and shared between analysis. It is quite
//     common to get the information on registers defined or used by an
//     instruction, or the memory operand read and written.
#include "syzygy/assm/assembler.h"
#include "syzygy/block_graph/analysis/liveness_analysis_internal.h"

#include "mnemonics.h"  // NOLINT

namespace block_graph {
namespace analysis {

namespace {

using block_graph::Operand;
typedef assm::RegisterId RegisterId;
typedef block_graph::BasicBlockSubGraph::BasicBlock BasicBlock;
typedef block_graph::BasicBlockSubGraph::BasicBlock::Instructions Instructions;

}  // namespace

MemoryAccessAnalysis::MemoryAccessAnalysis() {
}

void MemoryAccessAnalysis::GetStateAtEntryOf(const BasicBlock* bb,
                                             State* state) const {
  // This function accepts a NULL basic block and returns a safe state.
  DCHECK(state != NULL);

  state->Clear();

  if (bb == NULL)
    return;

  // Skip unknown basic block.
  StateMap::const_iterator bbentry_state = states_.find(bb);
  if (bbentry_state == states_.end())
    return;

  // Copy basic block memory information to state.
  *state = bbentry_state->second;
}

void MemoryAccessAnalysis::PropagateForward(const Instruction& instr,
                                            State* state) {
  DCHECK(state != NULL);

  state->Execute(instr);

  if (instr.IsCall() || instr.IsControlFlow()) {
    state->Clear();
    return;
  }

  // TODO(etienneb): Find a way to expose the defs concept.
  LivenessAnalysis::State defs;
  LivenessAnalysis::StateHelper::Clear(&defs);
  if (!LivenessAnalysis::StateHelper::GetDefsOf(instr, &defs)) {
    state->Clear();
    return;
  }

  for (size_t r = 0; r < assm::kRegister32Count; ++r) {
    if (defs.IsLive(assm::kRegisters32[r])) {
      // This register is modified, clear all memory accesses with this base.
      state->active_memory_accesses_[r].clear();
    }
  }
}

bool MemoryAccessAnalysis::Intersect(const block_graph::BasicBlock* bb,
                                     const State& state) {
  StateMap::iterator bbentry_state = states_.find(bb);
  if (bbentry_state == states_.end()) {
    // First intersection, create a set. This set will never grow again.
    states_[bb] = state;
    return true;
  }

  bool changed = false;
  // Subtract non redundant memory accesses.
  for (size_t r = 0; r < assm::kRegister32Count; ++r) {
    const std::set<int32_t>& from = state.active_memory_accesses_[r];
    std::set<int32_t>& to = bbentry_state->second.active_memory_accesses_[r];

    // In-place intersection. Remove unknown accesses of the destination set.
    std::set<int32_t>::iterator it1 = to.begin();
    std::set<int32_t>::const_iterator it2 = from.begin();
    while (it1 != to.end()) {
      if (it2 == from.end() || *it1 < *it2) {
        std::set<int32_t>::iterator old = it1;
        ++it1;
        to.erase(old);
        changed = true;
      } else if (*it2 < *it1) {
        ++it2;
      } else {  // *it1 == *it2
        ++it1;
        ++it2;
      }
    }
  }

  return changed;
}

// This function performs a global redundant memory access analysis.
// It is a fix-point algorithm that produce the minimal set of memory locations,
// at the entry of each basic block. The algorithm uses a work-list to follow
// the control flow and re-insert each modified basic block into the work-list.
// When the end of a basic block is reached, the algorithm performs the
// intersection of the current state with all its successors.
void MemoryAccessAnalysis::Analyze(const BasicBlockSubGraph* subgraph) {
  DCHECK(subgraph != NULL);

  std::queue<const BasicBlock*> working;
  std::set<const BasicBlock*> marked;

  states_.clear();

  // Find initial basic blocks (entry-points), add them to working queue.
  const BasicBlockSubGraph::BlockDescriptionList& descriptions =
      subgraph->block_descriptions();
  BasicBlockSubGraph::BlockDescriptionList::const_iterator descr_iter =
      descriptions.begin();
  for (; descr_iter != descriptions.end(); ++descr_iter) {
    const BasicBlockSubGraph::BasicBlockOrdering& original_order =
        descr_iter->basic_block_order;
    if (original_order.empty())
      continue;
    const BasicBlock* head = original_order.front();
    if (marked.insert(head).second) {
      working.push(original_order.front());
      State empty;
      Intersect(head, empty);
    }
  }

  DCHECK(!working.empty());

  // Working set algorithm until fixed point.
  while (!working.empty()) {
    const BasicBlock* bb = working.front();
    working.pop();
    marked.erase(bb);

    const BasicCodeBlock* bb_code = BasicCodeBlock::Cast(bb);
    if (bb_code == NULL) {
      // Invalidate all.
      states_.clear();
      return;
    }

    State state;
    GetStateAtEntryOf(bb, &state);

    // Walk through this basic block to obtain an updated state.
    const Instructions& instructions = bb_code->instructions();
    Instructions::const_iterator inst_iter = instructions.begin();
    for ( ; inst_iter != instructions.end(); ++inst_iter) {
      const Instruction& inst = *inst_iter;
      PropagateForward(inst, &state);
    }

    // Commit updated state to successors, and re-insert modified basic blocks
    // to the working queue to be processed again.
    const BasicBlock::Successors& successors = bb_code->successors();
    BasicBlock::Successors::const_iterator succ = successors.begin();
    for (; succ != successors.end(); ++succ) {
      BasicBlock* basic_block = succ->reference().basic_block();
      if (basic_block == NULL) {
        // Invalidate all.
        states_.clear();
        return;
      }

      // Intersect current state with successor 'basic_block'.
      bool changed = Intersect(basic_block, state);
      if (changed) {
        // When not already in working queue, mark and add it.
        if (marked.insert(basic_block).second)
          working.push(basic_block);
      }
    }
  }
}

MemoryAccessAnalysis::State::State() {
}

MemoryAccessAnalysis::State::State(const State& state) {
  for (size_t r = 0; r < assm::kRegister32Count; ++r) {
    active_memory_accesses_[r] = state.active_memory_accesses_[r];
  }
}

bool MemoryAccessAnalysis::State::HasNonRedundantAccess(
    const Instruction& instr) const {
  const _DInst& repr = instr.representation();

  // Load effective address instruction do not perform a memory access.
  if (repr.opcode == I_LEA)
    return false;

  // Skip string instructions.
  if ((FLAG_GET_PREFIX(repr.flags) & (FLAG_REPNZ | FLAG_REP)) != 0)
    return true;

  // Check each operand to find non redundant access.
  for (size_t op_id = 0; op_id < OPERANDS_NO; ++op_id) {
    const _Operand& op = repr.ops[op_id];

    // Filter unrecognized addressing mode.
    switch (op.type) {
      case O_DISP:
      case O_MEM:
        return true;
      case O_SMEM: {
        if (op.index < R_EAX || op.index > R_EDI)
          return true;

        // Simple memory dereference with optional displacement.
        RegisterId base_reg_id = core::GetRegisterId(op.index);
        DCHECK_LE(assm::kRegister32Min, base_reg_id);
        DCHECK_LT(base_reg_id, assm::kRegister32Max);
        size_t base_reg = base_reg_id - assm::kRegister32Min;

        BasicBlockReference reference;
        if (instr.FindOperandReference(op_id, &reference))
          return true;

        const std::set<int32_t>& accesses = active_memory_accesses_[base_reg];
        if (accesses.find(repr.disp) == accesses.end())
          return true;
      }
      break;
    }
  }

  return false;
}

void MemoryAccessAnalysis::State::Execute(const Instruction& instr) {
  const _DInst& repr = instr.representation();

  // Skip strings instructions.
  if ((FLAG_GET_PREFIX(repr.flags) & (FLAG_REPNZ | FLAG_REP)) != 0)
    return;

  // Load effective address instruction do not perform a memory access.
  if (repr.opcode == I_LEA)
    return;

  // For each operand, insert them as a redundant access.
  for (size_t op_id = 0; op_id < OPERANDS_NO; ++op_id) {
    const _Operand& op = repr.ops[op_id];

    if (op.type != O_SMEM)
      continue;

    if (op.index < R_EAX || op.index > R_EDI)
      continue;

    // Simple memory dereference with optional displacement.
    RegisterId base_reg_id = core::GetRegisterId(op.index);
    DCHECK_LE(assm::kRegister32Min, base_reg_id);
    DCHECK_LT(base_reg_id, assm::kRegister32Max);
    size_t base_reg = base_reg_id - assm::kRegister32Min;

    BasicBlockReference reference;
    if (instr.FindOperandReference(op_id, &reference))
      continue;

    active_memory_accesses_[base_reg].insert(repr.disp);
  }
}

void MemoryAccessAnalysis::State::Clear() {
  for (size_t r = 0; r < assm::kRegister32Count; ++r) {
    active_memory_accesses_[r].clear();
  }
}

}  // namespace analysis
}  // namespace block_graph
