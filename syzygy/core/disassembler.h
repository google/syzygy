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
// A class that attempts to disassemble a function.
#ifndef SYZYGY_CORE_DISASSEMBLER_H_
#define SYZYGY_CORE_DISASSEMBLER_H_

#include <set>
#include "base/basictypes.h"
#include "base/callback.h"
#include "syzygy/core/address.h"
#include "syzygy/core/address_space.h"
#include "distorm.h"  // NOLINT

namespace core {

class Disassembler {
 public:
  typedef std::set<AbsoluteAddress> AddressSet;
  typedef core::AddressSpace<AbsoluteAddress, size_t, uint8> VisitedSpace;

  enum CallbackDirective {
    // Indicates that the disassembler should continue.
    kDirectiveContinue,

    // Indicates that the disassembler should terminate its current
    // path in the walk, and continue at the next unvisited location.
    kDirectiveTerminatePath,

    // Indicates that the disassembler should halt all disassembly.
    kDirectiveTerminateWalk,

    // Indicate that the disassembler should terminate with an error.
    kDirectiveAbort
  };

  // The instruction callback is invoked for each instruction the disassembler
  // encounters. The callback receives three parameters:
  //   1. const Disassembler& disasm the disassembler.
  //   2. const _DInst& inst the current instruction.
  // Returns a CallbackDirective telling the disassembler how to proceed.
  typedef base::Callback<CallbackDirective(const Disassembler&,
                                           const _DInst&)>
      InstructionCallback;

  enum WalkResult {
    // Error during walk - e.g. function is not in our PEImageFile
    // or the section is not code, or the OnInstruction callback indicated an
    // error status.
    kWalkError,

    // Walk was successful and complete.
    kWalkSuccess,

    // Walk was incomplete, e.g. it encountered a computed branch or
    // similar, so may not have traversed every branch of the function.
    kWalkIncomplete,

    // Walk was terminated.
    kWalkTerminated,
  };

  // These flag values are passed to OnEndInstructionRun.
  enum ControlFlowFlag {
    // The instruction run ends with an explicit termination of control flow.
    kControlFlowTerminates,

    // The instruction implicitly flows into the next instruction run.
    kControlFlowContinues,
  };

  Disassembler(const uint8* code,
               size_t code_size,
               AbsoluteAddress code_addr,
               const InstructionCallback& on_instruction);

  Disassembler(const uint8* code,
               size_t code_size,
               AbsoluteAddress code_addr,
               const AddressSet& entry_points,
               const InstructionCallback& on_instruction);

  virtual ~Disassembler();

  // Add addr to unvisited set.
  // @returns true iff addr is unvisited.
  // @pre IsInCode(addr, 1).
  bool Unvisited(AbsoluteAddress addr);

  // Attempts to walk function from known entry points.
  // Invokes callback for every instruction as it's encountered.
  // @returns the results of the walk.
  // @note the instructions may be encountered in any order, as the
  //    disassembler follows the code's control flow.
  virtual WalkResult Walk();

  // @name Accessors.
  // @{
  const uint8* code() const { return code_; }
  size_t code_size() const { return code_size_; }
  const AbsoluteAddress code_addr() const { return code_addr_; }
  const AddressSet& unvisited() const { return unvisited_; }
  const VisitedSpace& visited() const { return visited_; }
  size_t disassembled_bytes() const { return disassembled_bytes_; }
  // @}

 protected:
  // Called every time a basic instruction is hit.
  // @param addr is the address of the branch instruction itself.
  // @param inst is the disassembled instruction data.
  // @returns kWalkContinue on success or kWalkError on failure.
  virtual CallbackDirective OnInstruction(AbsoluteAddress addr,
                                          const _DInst& inst);

  // Called every time a branch instruction is hit.
  // @param addr is the address of the branch instruction itself.
  // @param inst is the disassembled instruction data.
  // @param dest is the destination address of the branch instruction.
  // @returns kWalkContinue on success or kWalkError on failure.
  virtual CallbackDirective OnBranchInstruction(AbsoluteAddress addr,
                                                const _DInst& inst,
                                                AbsoluteAddress dest);

  // Called every time disassembly is started from a new address. Will be
  // called at least once if unvisited_ is non-empty.
  // @param start_address denotes the beginning of the instruction run.
  // @returns kWalkContinue on success or kWalkError on failure.
  virtual CallbackDirective OnStartInstructionRun(
      AbsoluteAddress start_address);

  // Called on every disassembled instruction.
  // @param addr is the address of the instruction that terminates the run.
  // @param inst is the terminating instruction.
  // @param control_flow a flag denoting whether control flow terminates
  //     for this instruction run, or flows into the next instruction run.
  // @returns kWalkContinue on success or kWalkError on failure.
  virtual CallbackDirective OnEndInstructionRun(AbsoluteAddress addr,
                                                const _DInst& inst,
                                                ControlFlowFlag control_flow);

  // Called when disassembly is complete and no further entry points remain
  // to disassemble from.
  // @returns kWalkContinue on success or kWalkError on failure.
  virtual CallbackDirective OnDisassemblyComplete();

  // Wrapper function to handle invoking both the internal and external
  // OnInstruction() callbacks.
  // @param addr is the address of the current instruction.
  // @param inst is the instruction.
  CallbackDirective NotifyOnInstruction(AbsoluteAddress addr,
                                        const _DInst& inst);

  // @returns true iff the range [addr ... addr + len) is in the function.
  bool IsInBlock(AbsoluteAddress addr) const;

  // The code we refer to.
  const uint8* code_;
  const size_t code_size_;

  // The original address of the first byte of code_.
  const AbsoluteAddress code_addr_;

  // Invoke this callback on every instruction.
  InstructionCallback on_instruction_;

  // Unvisited instruction locations before and during a walk.
  // This is seeded by the code entry point(s), and will also contain
  // branch targets during disassembly.
  AddressSet unvisited_;
  // Each visited instruction is stored as a range in this space.
  VisitedSpace visited_;

  // Number of bytes disassembled to this point during walk.
  size_t disassembled_bytes_;
};

}  // namespace core

#endif  // SYZYGY_CORE_DISASSEMBLER_H_
