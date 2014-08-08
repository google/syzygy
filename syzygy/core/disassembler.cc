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
// Implementation of disassembler.
#include "syzygy/core/disassembler.h"

#include "base/logging.h"
#include "base/strings/stringprintf.h"
#include "syzygy/core/disassembler_util.h"

namespace core {

Disassembler::Disassembler(const uint8* code,
                           size_t code_size,
                           AbsoluteAddress code_addr,
                           const InstructionCallback& on_instruction)
    : code_(code),
      code_size_(code_size),
      code_addr_(code_addr),
      on_instruction_(on_instruction),
      disassembled_bytes_(0) {
}

Disassembler::Disassembler(const uint8* code,
                           size_t code_size,
                           AbsoluteAddress code_addr,
                           const AddressSet& entry_points,
                           const InstructionCallback& on_instruction)
    : code_(code),
      code_size_(code_size),
      code_addr_(code_addr),
      on_instruction_(on_instruction),
      disassembled_bytes_(0) {

  AddressSet::const_iterator it = entry_points.begin();
  for (; it != entry_points.end(); ++it)
    Unvisited(*it);
}

Disassembler::~Disassembler() {
}

Disassembler::CallbackDirective Disassembler::OnInstruction(
    AbsoluteAddress addr, const _DInst& inst) {
  return kDirectiveContinue;
}

Disassembler::CallbackDirective Disassembler::OnBranchInstruction(
    AbsoluteAddress addr, const _DInst& inst, AbsoluteAddress dest) {
  return kDirectiveContinue;
}

Disassembler::CallbackDirective Disassembler::OnStartInstructionRun(
    AbsoluteAddress start_address) {
  return kDirectiveContinue;
}

Disassembler::CallbackDirective Disassembler::OnEndInstructionRun(
    AbsoluteAddress addr, const _DInst& inst, ControlFlowFlag control_flow) {
  return kDirectiveContinue;
}

Disassembler::CallbackDirective Disassembler::OnDisassemblyComplete() {
  return kDirectiveContinue;
}

Disassembler::WalkResult Disassembler::Walk() {
  // Initialize our disassembly state.
  _CodeInfo code = {};
  code.dt = Decode32Bits;
  code.features = DF_NONE;

  // This is to keep track of whether we cover the entire function.
  bool incomplete_branches = false;

  while (!unvisited_.empty()) {
    AddressSet::iterator it = unvisited_.begin();
    AbsoluteAddress addr(*it);
    unvisited_.erase(it);

    // Unvisited addresses must be within the code block we're currently
    // disassembling.
    DCHECK_LE(code_addr_, addr);
    DCHECK_GT(code_addr_ + code_size_, addr);

    // Notify of the beginning of a new instruction run.
    if (OnStartInstructionRun(addr) == kDirectiveAbort)
      return kWalkError;

    // This continues disassembly along a contiguous instruction run until we
    // run out of code, jump somewhere else, or are requested to terminate the
    // path by the OnInstruction callback. We call notification methods to
    // notify of the start of a run, the end of a run and when branch
    // instructions with computable destination addresses are hit.
    bool terminate = false;
    ControlFlowFlag control_flow = kControlFlowTerminates;
    _DInst inst = {};
    for (; addr != AbsoluteAddress(0) && !terminate; addr += inst.size) {
      code.codeOffset = addr.value();
      code.codeLen = code_size_ - (addr - code_addr_);
      code.code = code_ + (addr - code_addr_);
      if (code.codeLen == 0)
        break;

      bool conditional_branch_handled = false;

      unsigned int decoded = 0;
      _DecodeResult result = DistormDecompose(&code, &inst, 1, &decoded);

      if (decoded == 0) {
        LOG(ERROR) << "Unable to decode instruction at " << addr << ".";

        // Dump the next few bytes. The longest X86 instruction possible is 15
        // bytes according to distorm.
        int max_bytes = code.codeLen;
        if (max_bytes > 15)
          max_bytes = 15;
        std::string dump;
        for (int i = 0; i < max_bytes; ++i) {
          dump += base::StringPrintf(" 0x%02X", code.code[i]);
        }
        LOG(ERROR) << ".text =" << dump
                   << (max_bytes < code.codeLen ? " ..." : ".");
        return kWalkError;
      }

      CHECK_EQ(1U, decoded);
      CHECK(result == DECRES_MEMORYERR || result == DECRES_SUCCESS);

      // Try to visit this instruction.
      VisitedSpace::Range range(addr, inst.size);
      if (!visited_.Insert(range, 0)) {
        // If the collision is a repeat of a previously disassembled
        // instruction at a different offset then something went wrong.
        if (!visited_.ContainsExactly(range)) {
          LOG(ERROR) << "Two disassembled instructions overlap.";
          return kWalkError;
        }
        break;
      }

      // Tally the code bytes we just disassembled.
      disassembled_bytes_ += inst.size;

      // Invoke the callback and terminate if need be.
      switch (NotifyOnInstruction(addr, inst)) {
        case kDirectiveTerminateWalk:
          return kWalkTerminated;

        case kDirectiveAbort:
          return kWalkError;

        case kDirectiveTerminatePath:
          terminate = true;
          break;
      }

      uint8 fc = META_GET_FC(inst.meta);
      switch (fc) {
        case FC_NONE:
        case FC_CALL:
        case FC_CMOV:
          // Do nothing with these flow control types.
          break;

        case FC_RET:
          // It's a RET instruction, we're done with this branch.
          terminate = true;
          break;

        case FC_SYS:
          incomplete_branches = true;
          terminate = true;
          NOTREACHED() << "Unexpected SYS* instruction encountered";
          break;

        case FC_CND_BRANCH:
          // Conditional branch, schedule a visit to the branch-not-taken
          // basic block.
          Unvisited(addr + inst.size);
          // And fall through to visit branch target.

        case FC_UNC_BRANCH: {
            terminate = true;  // The basic block ends here.
            AbsoluteAddress dest;
            switch (inst.ops[0].type) {
              case O_REG:
              case O_MEM:
                // Computed branch, we can't chase this.
                break;

              case O_SMEM:
                // Branch to a register, can't chase this.
                break;

              case O_DISP:
                // Indirect address, this may be e.g. a jump to an import.
                // TODO(siggi): validate that this is so.
                DCHECK_EQ(32, inst.ops[0].size);
                break;

              case O_PC:
                // PC relative address.
                dest = addr + static_cast<size_t>(inst.size + inst.imm.addr);
                conditional_branch_handled = true;
                break;

              default:
                NOTREACHED() << "Unexpected branch destination type";
                break;
            }

            // Make sure to visit the branch destination.
            if (dest != AbsoluteAddress(0)) {
              if (IsInBlock(dest))
                Unvisited(dest);
            }

            // Notify of a newly-discovered branch destination.
            if (OnBranchInstruction(addr, inst, dest) == kDirectiveAbort)
              return kWalkError;

            if (dest == AbsoluteAddress(0)) {
              // We couldn't compute the destination, if not handled,
              // we may have incomplete coverage for the function.
              incomplete_branches =
                  incomplete_branches || !conditional_branch_handled;
            }
          }
          break;

        case FC_INT:
          // We encounter int3 inline in functions sometimes.
          break;

        default:
          NOTREACHED() << "Unexpected instruction type encountered";
          terminate = true;
          break;
      }

      // If the next instruction is flagged as a disassembly start point, we
      // should end this run of instructions (basic-block) and let it be picked
      // up on the next iteration.
      if (unvisited_.count(addr + inst.size) != 0 && !terminate) {
        control_flow = kControlFlowContinues;
        terminate = true;
      }
    }

    // Notify that we are terminating an instruction run. Note that we have to
    // back up the address by the last instruction size.
    if (OnEndInstructionRun(addr - inst.size,
                            inst,
                            control_flow) == kDirectiveAbort)
      return kWalkError;
  }

  // Notify when we've completed disassembly.
  if (OnDisassemblyComplete() == kDirectiveAbort)
    return kWalkError;

  // If we covered every byte in the function, we don't
  // care that we didn't chase all computed branches.
  if (incomplete_branches && disassembled_bytes_ == code_size_)
    return kWalkSuccess;

  // Otherwise we return success only in case of no computed branches.
  return incomplete_branches ? kWalkIncomplete : kWalkSuccess;
}

bool Disassembler::Unvisited(AbsoluteAddress addr) {
  DCHECK(IsInBlock(addr));

  if (visited_.Intersects(addr))
    return false;

  return unvisited_.insert(addr).second;
}

Disassembler::CallbackDirective Disassembler::NotifyOnInstruction(
    AbsoluteAddress addr, const _DInst& inst) {
  // Invoke our local callback.
  CallbackDirective directive = OnInstruction(addr, inst);

  // Invoke the external callback if we're not already aborted.
  if (directive == kDirectiveContinue && !on_instruction_.is_null())
    directive = on_instruction_.Run(*this, inst);

  return directive;
}

bool Disassembler::IsInBlock(AbsoluteAddress addr) const {
  return addr >= code_addr_ &&
      static_cast<size_t>(addr - code_addr_) + 1 <= code_size_;
}

}  // namespace core
