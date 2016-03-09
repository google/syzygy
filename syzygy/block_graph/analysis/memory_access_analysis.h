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
//
// A class that performs an analysis to detect redundant memory accesses over
// a control flow graph.
//
// The redundant memory accesses is a forward analysis which tries to determine
// which memory locations are already accessed, on every possible path, at a
// giving program point.
//
// A global analysis computes information for a whole function by keeping
// internally a state at each basic block entry.
// A local analysis computes information for a single basic block, and does not
// keep any state.
//
// See: http://en.wikipedia.org/wiki/Data-flow_analysis
//      http://en.wikipedia.org/wiki/Available_expression

#ifndef SYZYGY_BLOCK_GRAPH_ANALYSIS_MEMORY_ACCESS_ANALYSIS_H_
#define SYZYGY_BLOCK_GRAPH_ANALYSIS_MEMORY_ACCESS_ANALYSIS_H_

#include "syzygy/block_graph/basic_block.h"
#include "syzygy/block_graph/basic_block_assembler.h"
#include "syzygy/block_graph/basic_block_subgraph.h"

namespace block_graph {
namespace analysis {

// This class implements a local and a global redundant memory access analysis
// on a subgraph.
//
// The redundant memory access analysis is a conservative analysis which tries
// to prove that a memory location was previously used by the execution of a
// instruction for every possible path that may reach the current memory access.
// On failure, the analysis assume the memory access as non redundant.
//
// An instance of 'MemoryAccessAnalysis' keeps track of memory accesses done
// inside the 'State' data structure. To use the information provided
// by this analysis, the instructions in the basic block must be visited in
// order and a call to 'PropagateForward' must be performed on each one. After
// the call, the 'State' contains the set of redundant memory accesses after the
// instruction execution.
//
// Example:
//
//  MemoryAccessAnalysis memory_access;
//  MemoryAccessAnalysis::State state;
//
//  if (state.HasNonRedundantAccess(inst)) {
//    // Do something with a non redundant memory access.
//  }
//  // Move state after the current instruction.
//  memory_access.PropagateForward(&inst, &state);
//
// Local analysis
// --------------
//
// The local analysis does not need any computation before use.
// The analysis assumes an empty state at the beginning of each basic block.
//
// Example:
//
//  MemoryAccessAnalysis memory_access;
//  MemoryAccessAnalysis::State state;
//
//  BasicBlock::Instructions::iterator iter = instructions.begin();
//  memory_access.GetStateAtEntryOf(bb, &state);
//  for (; iter != instructions.end(); ++iter) {
//    const Instruction& instr = *iter;
//    [do something with redundancy information in state...]
//    memory_access.PropagateForward(&instr, &state);
//  }
//
// Global analysis
// ---------------
//
// The global analysis needs a pre-computation pass before any use.
// The analysis internally keeps track of a state at the beginning
// of each basic block.
//
// Example:
//
//  MemoryAccessAnalysis memory_access;
//  MemoryAccessAnalysis::State state;
//
//  // Perform the global analysis.
//  memory_access.Analyze(subgraph);
//
//  BasicBlock::Instructions::iterator iter = instructions.begin();
//  for (; iter != instructions.end(); ++iter) {
//    const Instruction& instr = *iter;
//    [do something with redundancy information in state...]
//    liveness.PropagateForward(&instr, &state);
//  }

class MemoryAccessAnalysis {
 public:
  typedef block_graph::BasicBlockSubGraph BasicBlockSubGraph;

  // Forward declarations.
  class State;

  MemoryAccessAnalysis();

  // Gets the memory accesses already done at the entry of a basic block.
  // When running in local mode, no memory accesses are assumed.
  // @param bb Basic block to analyze.
  // @param state Receives the set of memory location accessed.
  void GetStateAtEntryOf(const BasicBlock* bb, State* state) const;

  // Simulates the forward execution of an instruction and update the memory
  // access information in @p state to reflect side effects of @p instr.
  // @param instr Instruction to analyze.
  // @param state State to update.
  static void PropagateForward(const Instruction& instr, State* state);

  // Performs a global analysis.
  // @param subgraph Subgraph to analyze.
  void Analyze(const BasicBlockSubGraph* subgraph);

 protected:
  // Perform the intersection of the set of memory accesses in @p state with the
  // the set kept by the analysis for the basic block @p bb. On the first
  // intersection of a basic block, @p state is considered the first set for
  // @p bb and is fully copied.
  bool Intersect(const block_graph::BasicBlock* bb, const State& state);

  // Data structure to keep a set of memory locations for each basic block.
  typedef std::map<const block_graph::BasicBlock*, State> StateMap;
  StateMap states_;

 private:
  DISALLOW_COPY_AND_ASSIGN(MemoryAccessAnalysis);
};

// This class contains the memory access information at a given program point.
// The implementation only supports memory access through a single base register
// (e.g. [eax] or [esi+12]). For each general purpose register (eax, ebx, ecx,
// edx, esi, edi, esp, ebp) we keep a set of offsets accessed via the base.
class MemoryAccessAnalysis::State {
 public:
  // On creation, a state is assumed to be empty.
  State();

  // Copy the state @p state.
  // @param state State to copy.
  State(const State& state);

  // Check whether @p instr has a non redundant memory access.
  // @param instr The instruction on which we need to check each memory operand.
  // @returns true if memory accesses are redundant, false otherwise.
  bool HasNonRedundantAccess(const Instruction& instr) const;

 protected:
  // Remove all accessed memory locations from state.
  void Clear();

  // Simulate the execution of @intr and keep track of memory locations
  // accessed.
  // @param instr Instruction to analyze.
  void State::Execute(const Instruction& instr);

  // Contains active memory accesses. For each 32-bit base register, we keep a
  // set of distances (displacements) done via the base register.
  std::set<int32_t> active_memory_accesses_[assm::kRegister32Count];

  friend class MemoryAccessAnalysis;
};

}  // namespace analysis
}  // namespace block_graph

#endif  // SYZYGY_BLOCK_GRAPH_ANALYSIS_MEMORY_ACCESS_ANALYSIS_H_
