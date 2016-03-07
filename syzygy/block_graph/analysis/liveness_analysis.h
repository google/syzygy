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
// A class that performs a liveness analysis of a subgraph for x86 general
// purpose registers and flags.
//
// The liveness analysis is a backward analysis which tries to determine which
// registers are potentially alive (may be in use) and which registers are
// absolutely dead (cannot be used on any path).
//
// A global analysis computes liveness information for a whole function.
// A local analysis computes liveness information for a single basic block.
//
// See: http://en.wikipedia.org/wiki/Live_variable_analysis

#ifndef SYZYGY_BLOCK_GRAPH_ANALYSIS_LIVENESS_ANALYSIS_H_
#define SYZYGY_BLOCK_GRAPH_ANALYSIS_LIVENESS_ANALYSIS_H_

#include <map>

#include "syzygy/block_graph/basic_block.h"
#include "syzygy/block_graph/basic_block_subgraph.h"

namespace block_graph {
namespace analysis {

// This class implements a local and a global liveness analysis on a subgraph.
//
// The liveness analysis is a conservative analysis which tries to prove that
// some registers are unused and the others may be used. When the analysis is
// unable to manage a concept (jump-table, indirect call, calling-convention,
// ...), it simply assumes every register is in use (the most conservative
// decision).
//
// An instance of 'LivenessAnalysis' keeps track of live registers inside the
// 'State' data structure (bitset of registers). To use the information provided
// by this analysis, the instructions in the basic block must be visited in
// reverse order and a call to 'PropagateBackward' performed on each one. After
// the call, the 'State' contains the live registers and flags before
// instruction execution.
//
// Example:
//
//  LivenessAnalysis liveness;
//  LivenessAnalysis::State state;
//
//  liveness.PropagateBackward(&inst, &state);
//  if (!state.IsLive(core::eax)) {
//    // Register eax is not used, and may be overwritten.
//  }
//
//    or
//
//  liveness.GetStateAtEntryOf(bb, &state);
//  if (!state.IsLive(core::eax)) {
//    // Register eax is not used, and may be overwritten.
//  }
//
// Local analysis
// --------------
//
// The local liveness analysis does not need any computation before use.
// The analysis assumes all live registers at the end of a basic block.
//
// Example:
//
//  LivenessAnalysis liveness;
//  LivenessAnalysis::State state;
//
//  BasicBlock::Instructions::reverse_iterator iter = instructions.rbegin();
//  for (; iter != instructions.rend(); ++iter) {
//    const Instruction& instr = *iter;
//    liveness.PropagateBackward(&instr, &state);
//    [do something with liveness information in state...]
//  }
//
//
// Global analysis
// ---------------
//
// The global liveness analysis needs a pre-computation pass before any use.
// The analysis internally keeps track of all alive registers at the beginning
// of each basic block.
//
// Local modifications inside a basic block do not invalidate the global
// analysis except if a new live range escapes the scope of the basic block. In
// that case, the whole analysis is invalid and must be recomputed.
//
// Example:
//
//  LivenessAnalysis liveness;
//  LivenessAnalysis::State state;
//
//  // Perform the global analysis.
//  liveness.Analyze(subgraph);
//
//  // Load the state at the end of the basic block.
//  liveness.GetStateAtExitOf(bb, &state);
//  BasicBlock::Instructions::reverse_iterator iter = instructions.rbegin();
//  for (; iter != instructions.rend(); ++iter) {
//    const Instruction& instr = *iter;
//    liveness.PropagateBackward(&instr, &state);
//    [do something with liveness information in state...]
//  }

class LivenessAnalysis {
 public:
  typedef block_graph::BasicBlockSubGraph BasicBlockSubGraph;

  class State;
  class StateHelper;

  LivenessAnalysis();

  // Get the registers alive at the entry of a basic block.
  // When running in local mode, all registers are assumed alive.
  // @param bb Basic block to analyze.
  // @param state Receives registers alive at entry of basic block.
  void GetStateAtEntryOf(const BasicBlock* bb, State* state) const;

  // Get the registers alive at the exit of a basic block, before running
  // any successors. When running in local mode, all registers are assumed
  // alive.
  // @param bb Basic block to analyze.
  // @param state Receives registers alive at basic block exit.
  void GetStateAtExitOf(const BasicBlock* bb, State* state) const;

  // Simulate the backward execution of an instruction and update the liveness
  // information in @p state to reflect side effects of @p instr.
  // @param instr Instruction to analyze.
  // @param state Receives the updated state (defs and uses).
  static void PropagateBackward(const Instruction& instr, State* state);

  // Perform a global analysis and keep track of liveness information for each
  // basic block.
  // @param subgraph Subgraph to apply the analysis.
  void Analyze(const BasicBlockSubGraph* subgraph);

 private:
  // Contains the registers alive at entry of each basic block.
  typedef std::map<const BasicBlock*, State> LiveMap;
  LiveMap live_in_;

  DISALLOW_COPY_AND_ASSIGN(LivenessAnalysis);
};

// This class contains the liveness information at a given program point.
class LivenessAnalysis::State {
 public:
  typedef uint32_t RegisterMask;
  typedef uint32_t FlagsMask;

  // On creation, a state assumes all registers alive.
  State();

  // Copy the state @p state.
  // @param state State to copy.
  State(const State& state);

  // Check if a register has not been proven unused.
  // @param reg Register to check liveness information.
  // @returns true if the register may be alive, false otherwise.
  bool IsLive(const core::Register& reg) const;

  // Check if the arithmetic flags has not been proved unused.
  // @returns true if the flags may be used, false otherwise.
  bool AreArithmeticFlagsLive() const;

 private:
  friend class LivenessAnalysis::StateHelper;

  // Contains liveness of general purpose registers (eax, ebx, ... esp, ebp).
  RegisterMask registers_;
  // Contains liveness of arithmetic flags (eflags).
  FlagsMask flags_;
};

}  // namespace analysis
}  // namespace block_graph

#endif  // SYZYGY_BLOCK_GRAPH_ANALYSIS_LIVENESS_ANALYSIS_H_
