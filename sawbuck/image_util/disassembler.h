// Copyright 2011 Google Inc.
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
#ifndef SAWBUCK_IMAGE_UTIL_DISASSEMBLER_H_
#define SAWBUCK_IMAGE_UTIL_DISASSEMBLER_H_

#include "base/basictypes.h"
#include "base/callback.h"
#include "sawbuck/image_util/address.h"
#include "distorm.h"  // NOLINT
#include <set>

namespace image_util {

class Disassembler {
 public:
  typedef std::set<AbsoluteAddress> AddressSet;

  // The instruction callback is invoked for each instruction the disassembler
  // encounters. The callback receives three parameters:
  // 1. const Disassembler& disasm the disassembler.
  // 2. const _DInst& inst the current instruction.
  // 3. bool* continue_walk if set to false, terminates the current disassembly.
  typedef Callback3<const Disassembler&, const _DInst&, bool*>::Type
      InstructionCallback;

  enum WalkResult {
    // Error during walk - e.g. function is not in our PEImageFile
    // or the segment is not code.
    kWalkError,

    // Walk was successful and complete.
    kWalkSuccess,

    // Walk was incomplete, e.g. it encountered a computed branch or
    // similar, so may not have traversed every branch of the function.
    kWalkIncomplete,

    // Walk was terminated.
    kWalkTerminated,
  };

  Disassembler(const uint8* code,
               size_t code_size,
               AbsoluteAddress code_addr,
               InstructionCallback* on_instruction);

  // Attempts to walk function from unvisted addresses.
  // Invokes callback for every instruction as it's encountered.
  // @returns the results of the walk.
  // @note the instructions may be encountered in any order, as the
  //    disassembler follows the code's control flow.
  WalkResult Walk();

  // Add addr to unvisited set.
  // @returns true iff addr is unvisited.
  // @pre IsInCode(addr, 1).
  bool Unvisited(AbsoluteAddress addr);

  // @return true iff the range [addr ... addr + len) is in the function.
  bool IsInCode(AbsoluteAddress addr, size_t len) const;

  // Accessors.
  const AddressSet& unvisited() const { return unvisited_; }
  const AddressSet& visited() const { return visited_; }
  const AddressSet& data_locations() const { return data_locations_; }
  size_t disassembled_bytes() const { return disassembled_bytes_; }

 private:
   bool OnInstruction(const _DInst& inst);

  // The code we refer to.
  const uint8* code_;
  size_t code_size_;

  // The original address of the first byte of code_.
  AbsoluteAddress code_addr_;

  // Invoke this callback on every instruction.
  InstructionCallback* on_instruction_;

  // Unvisited instruction locations before and during a walk.
  // This is seeded by the code entry point(s), and will also contain
  // branch targets during disassembly.
  AddressSet unvisited_;
  // Each instruction location we've visited during walk.
  AddressSet visited_;

  // Contains the locations of data within the function. We can identify
  // portions of a function as data when e.g. the function contains a
  // switch statement implemented as a jump table. Each time we encounter
  // a loads or computed branches that refer to an absolute location within
  // the function, we assume that location is data, and take care to avoid
  // disassembling the data.
  // There seem to be cases where we would otherwise chase control flow into
  // data, such as e.g. when the compiler generates a call to a non-returning
  // function as last instruction in the function prior to a jump table.
  AddressSet data_locations_;

  // Number of bytes disassembled to this point during walk.
  size_t disassembled_bytes_;
};

}  // namespace image_util

#endif  // SAWBUCK_IMAGE_UTIL_DISASSEMBLER_H_
