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
// Provide internal basic operations on liveness states.

#ifndef SYZYGY_BLOCK_GRAPH_ANALYSIS_LIVENESS_ANALYSIS_INTERNAL_H_
#define SYZYGY_BLOCK_GRAPH_ANALYSIS_LIVENESS_ANALYSIS_INTERNAL_H_

#include "syzygy/block_graph/analysis/liveness_analysis.h"

namespace block_graph {
namespace analysis {

// This class provide basic operations on liveness states. This is the internal
// implementation and should not be used by the user. For unit testing purposes
// only. Do not use outside of tests.
class LivenessAnalysis::StateHelper {
 public:
  // A Liveness::State contains 2 bitsets to represent live registers/flags.
  // On x86, general purpose registers may be accessed partially, thus we
  // represent a full register as a 4-bit mask. Thus a register may be
  // partially alive.
  //
  //   register   mask   hex
  //        al    0001   0x1
  //        ah    0010   0x2
  //        ax    0011   0x3
  //       eax    0111   0x7
  //       rax    1111   0xF
  //
  // Flags bitset is represented the same way as DiStorm.
  // [D_IF D_DF D_AF D_PF D_OF D_CF D_SF D_ZF] (see distorm.h).

  typedef State::RegisterMask RegisterMask;
  typedef State::FlagsMask FlagsMask;

  enum RegisterBits {
    REGBITS_NONE = 0x00000000,
    REGBITS_AL = 0x00000001,
    REGBITS_AH = 0x00000002,
    REGBITS_AX = 0x00000003,
    REGBITS_EAX = 0x00000007,
    REGBITS_RAX = 0x0000000F,
    REGBITS_BL = 0x00000010,
    REGBITS_BH = 0x00000020,
    REGBITS_BX = 0x00000030,
    REGBITS_EBX = 0x00000070,
    REGBITS_RBX = 0x000000F0,
    REGBITS_CL = 0x00000100,
    REGBITS_CH = 0x00000200,
    REGBITS_CX = 0x00000300,
    REGBITS_ECX = 0x00000700,
    REGBITS_RCX = 0x00000F00,
    REGBITS_DL = 0x00001000,
    REGBITS_DH = 0x00002000,
    REGBITS_DX = 0x00003000,
    REGBITS_EDX = 0x00007000,
    REGBITS_RDX = 0x0000F000,
    REGBITS_SI = 0x00030000,
    REGBITS_ESI = 0x00070000,
    REGBITS_RSI = 0x000F0000,
    REGBITS_DI = 0x00300000,
    REGBITS_EDI = 0x00700000,
    REGBITS_RDI = 0x00F00000,
    REGBITS_SP = 0x03000000,
    REGBITS_ESP = 0x07000000,
    REGBITS_RSP = 0x0F000000,
    REGBITS_BP = 0x30000000,
    REGBITS_EBP = 0x70000000,
    REGBITS_RBP = 0xF0000000,
    REGBITS_ALL = 0xFFFFFFFF
  };

  // For a given distorm register, returns the corresponding registers mask.
  // @param reg A distorm register to convert to a registers mask.
  // @returns The resulting registers mask.
  static RegisterMask RegisterToRegisterMask(uint8_t reg);

  // Reset the liveness information to assume no registers are live.
  // @param state State to clear.
  static void Clear(State* state);

  // Set the liveness information to assume all registers are live.
  // @param state to set all registers.
  static void SetAll(State* state);

  // Check if the arithmetic flags have not been proved unused.
  // @param state State to check into.
  // @returns true if the flags may be used, false otherwise.
  static bool AreArithmeticFlagsLive(const State& state);

  // Check whether the registers in @p mask are 'fully' set in @p state.
  // @param state State to inspect.
  // @param mask Registers bitset to check.
  // @returns true if the registers may be used, false otherwise.
  static bool IsSet(const State& state, RegisterMask mask);

  // Check whether the registers in @p mask mask are 'partially' set.
  // @param state State to inspect.
  // @param mask Registers bitset to check.
  // @returns true if the registers may be used, false otherwise.
  static bool IsPartiallySet(const State& state, RegisterMask mask);

  // Mark the registers in @p mask as live in @p state.
  // @param mask Registers bitset to mark as live.
  // @param state State to apply modifications.
  static void Set(RegisterMask mask, State* state);

  // Mark the flag in @p mask as live in @p state.
  // @param mask Flags bitset to mark as live.
  // @param state State to apply modifications.
  static void SetFlags(FlagsMask mask, State* state);

  // Overwrite @p state with the state of @p src.
  // @param src State to copy.
  // @param state State to receive the copy.
  static void Copy(const State& src, State* state);

  // Merge the state @p src into @p state.
  // @param src State to merge with.
  // @param state State to apply modifications.
  // @returns true if the output state is modified, false otherwise.
  static bool Union(const State& src, State* state);

  // Subtract defined registers in @p src from @p state.
  // @param src State to subtract.
  // @param state State to apply modifications.
  static void Subtract(const State& src, State* state);

  // Find the registers defined by an operand.
  // @param operand Operand to analyze.
  // @param state Receives defined registers.
  static void StateDefOperand(const _Operand& operand, State* state);

  // Find the registers used by an operand.
  // @param instr Instruction to which belong the operand.
  // @param operand Operand to analyze.
  // @param state Receives used registers.
  static void StateUseOperand(const Instruction& instr,
                              const _Operand& operand,
                              State* state);

  // Find the registers used by an operand on left-hand side.
  // @param instr Instruction to which belong the operand.
  // @param operand Operand to analyze.
  // @param state Receives used registers.
  static void StateUseOperandLHS(const Instruction& instr,
                                 const _Operand& operand,
                                 State* state);

  // Get the registers defined by the execution of the instruction.
  // @param instr Instruction to analyze.
  // @param state On success, receives the registers defined by the instruction.
  // @returns true if we are able to analyze this instruction, false otherwise.
  static bool GetDefsOf(const Instruction& instr, State* state);

  // Get the registers used by the execution of the instruction.
  // @param instr Instruction to analyze.
  // @param state On success, receives registers used by the instruction.
  // @returns true if we are able to analyze this instruction, false otherwise.
  static bool GetUsesOf(const Instruction& instr, State* state);

  // Get the registers used by the execution of the successor (instruction).
  // @param successor Successor to analyze.
  // @param state On success, receives registers used by the instruction.
  // @returns true if we are able to analyze this successor, false otherwise.
  static bool GetUsesOf(const Successor& successor, State* state);
};

}  // namespace analysis
}  // namespace block_graph

#endif  // SYZYGY_BLOCK_GRAPH_ANALYSIS_LIVENESS_ANALYSIS_INTERNAL_H_
