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

#include "syzygy/block_graph/analysis/liveness_analysis.h"

#include <set>
#include <stack>
#include <vector>

#include "syzygy/block_graph/analysis/control_flow_analysis.h"
#include "syzygy/block_graph/analysis/liveness_analysis_internal.h"
#include "syzygy/core/assembler.h"
#include "syzygy/core/disassembler_util.h"

#include "mnemonics.h"  // NOLINT

namespace block_graph {
namespace analysis {
namespace {

using core::Register;
typedef BasicBlockSubGraph::BBCollection BBCollection;
typedef BasicBlock::Instructions Instructions;
typedef BasicBlock::Successors Successors;
typedef Instruction::Representation Representation;
typedef ControlFlowAnalysis::BasicBlockOrdering BasicBlockOrdering;
typedef LivenessAnalysis::State State;
typedef LivenessAnalysis::State::RegisterMask RegisterMask;
typedef LivenessAnalysis::State::FlagsMask FlagsMask;

}  // namespace

State::State()
    : flags_(StateHelper::REGBITS_ALL), registers_(StateHelper::REGBITS_ALL) {
}

State::State(const State& state) {
  StateHelper::Copy(state, this);
}

bool State::IsLive(const Register& reg) const {
  // Convert from core::Register representation of registers to the bits
  // representation we use internally, by way of the Distorm _RegisterType.
  RegisterMask mask = StateHelper::RegisterToRegisterMask(
      core::GetRegisterType(reg));
  return StateHelper::IsPartiallySet(*this, mask);
}

bool State::AreArithmeticFlagsLive() const {
  return StateHelper::AreArithmeticFlagsLive(*this);
}

LivenessAnalysis::LivenessAnalysis() : live_in_() {
}

void LivenessAnalysis::GetStateAtEntryOf(const BasicBlock* bb,
                                         State* state) const {
  // This function accepts a NULL basic block and returns a safe state with all
  // registers alive.
  DCHECK(state != NULL);

  if (bb != NULL) {
    LiveMap::const_iterator look = live_in_.find(bb);
    if (look != live_in_.end()) {
      StateHelper::Copy(look->second, state);
      return;
    }
  }

  StateHelper::SetAll(state);
}

void LivenessAnalysis::GetStateAtExitOf(const BasicBlock* bb,
                                        State* state) const {
  // This function accepts a NULL basic block and returns a safe state with all
  // registers alive.
  DCHECK(state != NULL);

  // Initialize liveness information assuming all registers are alive.
  StateHelper::SetAll(state);

  const BasicCodeBlock* code = BasicCodeBlock::Cast(bb);
  if (code == NULL)
    return;

  const BasicBlock::Successors& successors = code->successors();
  if (successors.empty())
    return;

  // Merge current liveness information with every successor information.
  StateHelper::Clear(state);
  Successors::const_iterator succ_end = successors.end();
  for (Successors::const_iterator succ = successors.begin();
       succ != succ_end; ++succ) {
    BasicBlock* successor_basic_block = succ->reference().basic_block();
    if (successor_basic_block == NULL) {
      // Successor is not a BasicBlock. Assume all registers are alive.
      StateHelper::SetAll(state);
      return;
    }

    // Merge successor state into current state.
    State successor_state;
    GetStateAtEntryOf(successor_basic_block, &successor_state);
    StateHelper::Union(successor_state, state);

    // Merge liveness information from the implicit instruction in successor.
    if (StateHelper::GetUsesOf(*succ, &successor_state)) {
      StateHelper::Union(successor_state, state);
    } else {
      StateHelper::SetAll(state);
    }
  }
}

void LivenessAnalysis::PropagateBackward(const Instruction& instr,
                                         State* state) {
  DCHECK(state != NULL);

  // Skip 'nop' instructions. It's better to skip them (i.e. mov %eax, %eax).
  if (instr.IsNop())
    return;

  // Remove 'defs' from current state.
  State defs;
  if (StateHelper::GetDefsOf(instr, &defs))
    StateHelper::Subtract(defs, state);

  if (instr.IsCall() || instr.IsReturn()) {
    // TODO(etienneb): Can we verify the calling convention? If so we can do
    // better than SetAll here.
    StateHelper::SetAll(state);
  } else if (instr.IsBranch() ||
             instr.IsInterrupt() ||
             instr.IsControlFlow()) {
    // Don't mess with these instructions.
    StateHelper::SetAll(state);
  }

  // Add 'uses' of instruction to current state, or assume all alive when 'uses'
  // information is not available.
  State uses;
  if (StateHelper::GetUsesOf(instr, &uses)) {
    StateHelper::Union(uses, state);
  } else {
    StateHelper::SetAll(state);
  }
}

void LivenessAnalysis::Analyze(const BasicBlockSubGraph* subgraph) {
  DCHECK(subgraph != NULL);
  DCHECK(live_in_.empty());

  // Produce a post-order basic blocks ordering.
  const BBCollection& basic_blocks = subgraph->basic_blocks();
  std::vector<const BasicCodeBlock*> order;
  ControlFlowAnalysis::FlattenBasicBlocksInPostOrder(basic_blocks, &order);

  // Initialize liveness information of each basic block (empty set).
  BasicBlockOrdering::const_iterator fw_iter = order.begin();
  for (; fw_iter != order.end(); ++fw_iter)
    StateHelper::Clear(&live_in_[*fw_iter]);

  // Propagate liveness information until stable (fix-point). Each set may only
  // grow, thus we have a halting condition.
  bool changed = true;
  while (changed) {
    changed = false;

    BasicBlockOrdering::const_iterator  bb_iter = order.begin();
    for (; bb_iter != order.end(); ++bb_iter) {
      const BasicCodeBlock* bb = *bb_iter;

      // Merge current liveness information with every successor information.
      State state;
      GetStateAtExitOf(bb, &state);

      // Propagate liveness information backward until the basic block entry.
      const Instructions& instructions = bb->instructions();
      Instructions::const_reverse_iterator instr_iter = instructions.rbegin();
      for (; instr_iter != instructions.rend(); ++instr_iter)
        PropagateBackward(*instr_iter, &state);

      // Commit liveness information to the global state.
      if (StateHelper::Union(state, &live_in_[bb]))
        changed = true;
    }
  }
}

RegisterMask LivenessAnalysis::StateHelper::RegisterToRegisterMask(uint8 reg) {
  switch (reg) {
    case R_AL:
      return LivenessAnalysis::StateHelper::REGBITS_AL;
    case R_AH:
      return LivenessAnalysis::StateHelper::REGBITS_AH;
    case R_AX:
      return LivenessAnalysis::StateHelper::REGBITS_AX;
    case R_EAX:
      return LivenessAnalysis::StateHelper::REGBITS_EAX;
    case R_RAX:
      return LivenessAnalysis::StateHelper::REGBITS_RAX;
    case R_BL:
      return LivenessAnalysis::StateHelper::REGBITS_BL;
    case R_BH:
      return LivenessAnalysis::StateHelper::REGBITS_BH;
    case R_BX:
      return LivenessAnalysis::StateHelper::REGBITS_BX;
    case R_EBX:
      return LivenessAnalysis::StateHelper::REGBITS_EBX;
    case R_RBX:
      return LivenessAnalysis::StateHelper::REGBITS_RBX;
    case R_CL:
      return LivenessAnalysis::StateHelper::REGBITS_CL;
    case R_CH:
      return LivenessAnalysis::StateHelper::REGBITS_CH;
    case R_CX:
      return LivenessAnalysis::StateHelper::REGBITS_CX;
    case R_ECX:
      return LivenessAnalysis::StateHelper::REGBITS_ECX;
    case R_RCX:
      return LivenessAnalysis::StateHelper::REGBITS_RCX;
    case R_DL:
      return LivenessAnalysis::StateHelper::REGBITS_DL;
    case R_DH:
      return LivenessAnalysis::StateHelper::REGBITS_DH;
    case R_DX:
      return LivenessAnalysis::StateHelper::REGBITS_DX;
    case R_EDX:
      return LivenessAnalysis::StateHelper::REGBITS_EDX;
    case R_RDX:
      return LivenessAnalysis::StateHelper::REGBITS_RDX;
    case R_SI:
      return LivenessAnalysis::StateHelper::REGBITS_SI;
    case R_ESI:
      return LivenessAnalysis::StateHelper::REGBITS_ESI;
    case R_RSI:
      return LivenessAnalysis::StateHelper::REGBITS_RSI;
    case R_DI:
      return LivenessAnalysis::StateHelper::REGBITS_DI;
    case R_EDI:
      return LivenessAnalysis::StateHelper::REGBITS_EDI;
    case R_RDI:
      return LivenessAnalysis::StateHelper::REGBITS_RDI;
    case R_SP:
      return LivenessAnalysis::StateHelper::REGBITS_SP;
    case R_ESP:
      return LivenessAnalysis::StateHelper::REGBITS_ESP;
    case R_RSP:
      return LivenessAnalysis::StateHelper::REGBITS_RSP;
    case R_BP:
      return LivenessAnalysis::StateHelper::REGBITS_BP;
    case R_EBP:
      return LivenessAnalysis::StateHelper::REGBITS_EBP;
    case R_RBP:
      return LivenessAnalysis::StateHelper::REGBITS_RBP;
    default:
      // Unhandled registers are ignored.
      return 0;
  }

  NOTREACHED();
}

void LivenessAnalysis::StateHelper::Clear(State* state) {
  DCHECK(state != NULL);
  state->flags_ = 0;
  state->registers_ = 0;
}

void LivenessAnalysis::StateHelper::SetAll(State* state) {
  DCHECK(state != NULL);
  state->flags_ = StateHelper::REGBITS_ALL;
  state->registers_ = REGBITS_ALL;
}

bool LivenessAnalysis::StateHelper::AreArithmeticFlagsLive(
    const State& state) {
  return (state.flags_ & (D_ZF | D_SF | D_CF | D_OF | D_PF | D_AF)) != 0;
}

bool LivenessAnalysis::StateHelper::IsSet(
    const State& state, RegisterMask mask) {
  return (state.registers_ & mask) == mask;
}

bool LivenessAnalysis::StateHelper::IsPartiallySet(
    const State& state, RegisterMask mask) {
  return (state.registers_ & mask) != 0;
}

void LivenessAnalysis::StateHelper::Set(RegisterMask mask, State* state) {
  DCHECK(state != NULL);
  state->registers_ |= mask;
}

void LivenessAnalysis::StateHelper::SetFlags(FlagsMask mask, State* state) {
  DCHECK(state != NULL);
  state->flags_ |= mask;
}

void LivenessAnalysis::StateHelper::Copy(const State& src, State* state) {
  DCHECK(state != NULL);
  state->flags_ = src.flags_;
  state->registers_ = src.registers_;
}

bool LivenessAnalysis::StateHelper::Union(const State& src, State* state) {
  DCHECK(state != NULL);

  bool changed = ((state->flags_ | src.flags_) != state->flags_) ||
                 ((state->registers_ | src.registers_) != state->registers_);
  state->flags_ |= src.flags_;
  state->registers_ |= src.registers_;
  return changed;
}

void LivenessAnalysis::StateHelper::Subtract(const State& src, State* state) {
  DCHECK(state != NULL);
  state->flags_ &= ~(src.flags_);
  state->registers_ &= ~(src.registers_);
}

void LivenessAnalysis::StateHelper::StateDefOperand(
    const _Operand& operand, State* state) {
  DCHECK(state != NULL);
  if (operand.type == O_REG)
    Set(RegisterToRegisterMask(operand.index), state);
}

void LivenessAnalysis::StateHelper::StateUseOperand(
    const Instruction& instr,
    const _Operand& operand,
    State* state) {
  DCHECK(state != NULL);

  const Representation& repr = instr.representation();

  switch (operand.type) {
    case O_REG:
    case O_SMEM:
      Set(RegisterToRegisterMask(operand.index), state);
      break;
    case O_MEM:
      Set(RegisterToRegisterMask(operand.index), state);
      Set(RegisterToRegisterMask(repr.base), state);
      break;
  }
}

void LivenessAnalysis::StateHelper::StateUseOperandLHS(
     const Instruction& instr,
     const _Operand& operand,
     State* state) {
  DCHECK(state != NULL);

  if (operand.type == O_REG)
    return;
  StateUseOperand(instr, operand, state);
}

bool LivenessAnalysis::StateHelper::GetDefsOf(
    const Instruction& instr, State* state) {
  DCHECK(state != NULL);

  Clear(state);

  const Representation& repr = instr.representation();

  // Get information on flags (eflags register).
  SetFlags(repr.modifiedFlagsMask | repr.undefinedFlagsMask, state);

  // Handle instructions with 'REP' prefix.
  if ((FLAG_GET_PREFIX(repr.flags) & (FLAG_REPNZ | FLAG_REP)) != 0) {
    switch (repr.opcode) {
      case I_MOVS:
        Set(RegisterToRegisterMask(R_ECX), state);
        Set(RegisterToRegisterMask(R_ESI), state);
        Set(RegisterToRegisterMask(R_EDI), state);
        return true;
      case I_STOS:
        Set(RegisterToRegisterMask(R_ECX), state);
        Set(RegisterToRegisterMask(R_EDI), state);
        return true;
      default: return false;
    }
  }

  // Get information on operand (general purpose registers).
  switch (repr.opcode) {
    case I_CMP:
    case I_FCOM:
    case I_FCOMP:
    case I_FCOMPP:
    case I_FCOMI:
    case I_FCOMIP:
    case I_FIST:
    case I_FISTP:
    case I_FST:
    case I_FSTP:
    case I_TEST:
      return true;
    case I_ADD:
    case I_ADC:
    case I_AND:
    case I_DEC:
    case I_INC:
    case I_FADD:
    case I_FADDP:
    case I_FILD:
    case I_FLD:
    case I_FLD1:
    case I_FLDZ:
    case I_FMUL:
    case I_FMULP:
    case I_FSUB:
    case I_FSUBP:
    case I_LEA:
    case I_MOV:
    case I_MOVZX:
    case I_MOVSX:
    case I_NEG:
    case I_NOT:
    case I_OR:
    case I_ROL:
    case I_ROR:
    case I_SAR:
    case I_SBB:
    case I_SETA:
    case I_SETAE:
    case I_SETB:
    case I_SETBE:
    case I_SETG:
    case I_SETGE:
    case I_SETL:
    case I_SETLE:
    case I_SETNO:
    case I_SETNP:
    case I_SETNS:
    case I_SETNZ:
    case I_SETO:
    case I_SETP:
    case I_SETS:
    case I_SETZ:
    case I_SHL:
    case I_SHR:
    case I_SUB:
    case I_XOR:
      StateDefOperand(repr.ops[0], state);
      return true;
    case I_POP:
    case I_POPF:
      StateDefOperand(repr.ops[0], state);
      Set(RegisterToRegisterMask(R_ESP), state);
      return true;
    case I_CALL:
    case I_PUSH:
    case I_PUSHF:
    case I_RET:
      Set(RegisterToRegisterMask(R_ESP), state);
      return true;
    case I_LEAVE:
      Set(RegisterToRegisterMask(R_EBP), state);
      Set(RegisterToRegisterMask(R_ESP), state);
      return true;
    case I_LAHF:
      Set(REGBITS_AH, state);
      return true;
    case I_SAHF:
      // Store register ah into flags (fix a DiStorm bug).
      SetFlags(D_AF | D_CF | D_PF | D_SF| D_ZF, state);
      return true;
    case I_MOVS:
      Set(RegisterToRegisterMask(R_ESI), state);
      Set(RegisterToRegisterMask(R_EDI), state);
      return true;
    case I_STOS:
      Set(RegisterToRegisterMask(R_EDI), state);
      return true;
    case I_CWD:
      Set(RegisterToRegisterMask(R_EAX), state);
      return true;
    case I_CDQ:
      Set(RegisterToRegisterMask(R_EAX), state);
      Set(RegisterToRegisterMask(R_EDX), state);
      return true;
    case I_MUL:
    case I_IMUL:
      if (repr.ops[1].type == O_NONE) {
        // Destination is implicit.
        switch (repr.ops[0].size) {
        case 8:
          Set(RegisterToRegisterMask(R_AX), state);
          return true;
        case 16:
          Set(RegisterToRegisterMask(R_AX), state);
          Set(RegisterToRegisterMask(R_DX), state);
          return true;
        case 32:
          Set(RegisterToRegisterMask(R_EAX), state);
          Set(RegisterToRegisterMask(R_EDX), state);
          return true;
        }
      } else {
        // Destination is explicit.
        DCHECK_EQ(repr.opcode, I_IMUL);
        StateDefOperand(repr.ops[0], state);
      }
      return false;
    default:
      return false;
  }

  NOTREACHED();
}

bool LivenessAnalysis::StateHelper::GetUsesOf(
    const Instruction& instr, State* state) {
  DCHECK(state != NULL);

  Clear(state);

  const Representation& repr = instr.representation();

  // Get information on flags (eflags register).
  SetFlags(repr.testedFlagsMask, state);

  // Handle a special case: xor-initialization (i.e. xor eax, eax).
  if (repr.opcode == I_XOR &&
      repr.ops[0].type == O_REG &&
      repr.ops[1].type == O_REG &&
      repr.ops[0].index == repr.ops[1].index) {
    // We can assume no uses.
    return true;
  }

  // Handle instructions with 'REP' prefix.
  if ((FLAG_GET_PREFIX(repr.flags) & (FLAG_REPNZ | FLAG_REP)) != 0) {
    switch (repr.opcode) {
      case I_MOVS:
        Set(RegisterToRegisterMask(R_ECX), state);
        Set(RegisterToRegisterMask(R_ESI), state);
        Set(RegisterToRegisterMask(R_EDI), state);
        return true;
      case I_STOS:
        Set(RegisterToRegisterMask(R_EAX), state);
        Set(RegisterToRegisterMask(R_ECX), state);
        Set(RegisterToRegisterMask(R_EDI), state);
        return true;
      default: return false;
    }
  }

  // Get information on operand (general purpose registers).
  switch (repr.opcode) {
    case I_ADD:
    case I_ADC:
    case I_AND:
    case I_CMP:
    case I_FADD:
    case I_FADDP:
    case I_FCOM:
    case I_FCOMP:
    case I_FCOMPP:
    case I_FCOMI:
    case I_FCOMIP:
    case I_FICOM:
    case I_FICOMP:
    case I_FILD:
    case I_FIST:
    case I_FISTP:
    case I_FLD:
    case I_FLD1:
    case I_FLDZ:
    case I_FMUL:
    case I_FMULP:
    case I_FST:
    case I_FSTP:
    case I_FSUB:
    case I_FSUBP:
    case I_DEC:
    case I_INC:
    case I_NEG:
    case I_NOT:
    case I_ROL:
    case I_ROR:
    case I_OR:
    case I_SBB:
    case I_SAR:
    case I_SHL:
    case I_SHR:
    case I_SUB:
    case I_TEST:
    case I_XOR:
      StateUseOperand(instr, repr.ops[0], state);
      StateUseOperand(instr, repr.ops[1], state);
      return true;
    case I_SETA:
    case I_SETAE:
    case I_SETB:
    case I_SETBE:
    case I_SETG:
    case I_SETGE:
    case I_SETL:
    case I_SETLE:
    case I_SETNO:
    case I_SETNP:
    case I_SETNS:
    case I_SETNZ:
    case I_SETO:
    case I_SETP:
    case I_SETS:
    case I_SETZ:
      return true;
    case I_LEA:
    case I_MOV:
    case I_MOVZX:
    case I_MOVSX:
      StateUseOperandLHS(instr, repr.ops[0], state);
      StateUseOperand(instr, repr.ops[1], state);
      return true;
    case I_PUSHF:
      SetFlags(REGBITS_ALL, state);
      Set(RegisterToRegisterMask(R_ESP), state);
      return true;
    case I_LAHF:
      SetFlags(D_AF | D_CF | D_PF | D_SF| D_ZF, state);
      return true;
    case I_SAHF:
      Set(REGBITS_AH, state);
      return true;
    case I_POP:
    case I_POPF:
      StateUseOperandLHS(instr, repr.ops[0], state);
      Set(RegisterToRegisterMask(R_ESP), state);
      return true;
    case I_CALL:
    case I_PUSH:
    case I_RET:
      StateUseOperand(instr, repr.ops[0], state);
      Set(RegisterToRegisterMask(R_ESP), state);
      return true;
    case I_LEAVE:
      Set(RegisterToRegisterMask(R_EBP), state);
      Set(RegisterToRegisterMask(R_ESP), state);
      return true;
    case I_MOVS:
      Set(RegisterToRegisterMask(R_ESI), state);
      Set(RegisterToRegisterMask(R_EDI), state);
      return true;
    case I_STOS:
      Set(RegisterToRegisterMask(R_EAX), state);
      Set(RegisterToRegisterMask(R_EDI), state);
      return true;
    case I_CWD:
      Set(RegisterToRegisterMask(R_AX), state);
      return true;
    case I_CDQ:
      Set(RegisterToRegisterMask(R_EAX), state);
      return true;
    case I_MUL:
    case I_IMUL:
      StateUseOperand(instr, repr.ops[0], state);
      StateUseOperand(instr, repr.ops[1], state);
      StateUseOperand(instr, repr.ops[2], state);

      if (repr.ops[1].type == O_NONE) {
        // The second operand is implicit.
        switch (repr.ops[0].size) {
          case 8:
            Set(RegisterToRegisterMask(R_AL), state);
            break;
          case 16:
            Set(RegisterToRegisterMask(R_AX), state);
            break;
          case 32:
            Set(RegisterToRegisterMask(R_EAX), state);
            break;
          default:
            return false;
        }
      }
      return true;
    default:
      return false;
  }

  NOTREACHED();
}

bool LivenessAnalysis::StateHelper::GetUsesOf(
    const Successor& successor, State* state) {
  DCHECK(state != NULL);
  switch (successor.condition()) {
    case Successor::kConditionAbove:
    case Successor::kConditionBelowOrEqual:
      SetFlags(D_CF | D_ZF, state);
      return true;
    case Successor::kConditionBelow:
    case Successor::kConditionAboveOrEqual:
      SetFlags(D_CF, state);
      return true;
    case Successor::kConditionEqual:
    case Successor::kConditionNotEqual:
      SetFlags(D_ZF, state);
      return true;
    case Successor::kConditionGreater:
    case Successor::kConditionLessOrEqual:
      SetFlags(D_ZF | D_SF | D_OF, state);
      return true;
    case Successor::kConditionLess:
    case Successor::kConditionGreaterOrEqual:
      SetFlags(D_SF | D_OF, state);
      return true;
    case Successor::kConditionOverflow:
    case Successor::kConditionNotOverflow:
      SetFlags(D_OF, state);
      return true;
    case Successor::kConditionParity:
    case Successor::kConditionNotParity:
      SetFlags(D_PF, state);
      return true;
    case Successor::kConditionSigned:
    case Successor::kConditionNotSigned:
      SetFlags(D_SF, state);
      return true;
    case Successor::kConditionTrue:
      return true;
    default:
      return false;
  }

  NOTREACHED();
}

}  // namespace analysis
}  // namespace block_graph
