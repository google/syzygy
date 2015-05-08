// Copyright 2015 Google Inc. All Rights Reserved.
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
// This class hot patches a function in memory: all calls to a function will
// redirected to a new function using JMP instructions.
//
// The function must have been prepared for hot patching: it must start with an
// instruction that is at least two bytes long and must have at least 5-byte
// padding before it and must have at least 2-byte alignment. The alignment
// precondition is checked using the CHECK macro. The rest of the preconditions
// are not checked.
//
// The hot patching does the following:
// - Removes write protection from the pages where it needs to write.
// - Writes the a PC-relative JMP instruction to the 5-byte padding before
//   the function. (Opcode: 0xE9 [32-bit PC-relative address])
// - Overwrites the first two bytes of the function with a JMP -5 short jump
//   instruction. (Opcode: 0xEB 0xF9)
// - Restores the old protection.
//
// We also DCHECK that the bytes in the padding that we overwrite are all 0xCC
// bytes. These are used by the instrumenter in the paddings. These DCHECKs
// need to be removed to support hot patching a function more than once.

#ifndef SYZYGY_AGENT_COMMON_HOT_PATCHER_H_
#define SYZYGY_AGENT_COMMON_HOT_PATCHER_H_

#include <base/macros.h>

namespace agent {
namespace common {

class HotPatcher {
 public:
  typedef void* FunctionPointer;

  HotPatcher() { }
  ~HotPatcher() { }

  // Applies hot patching to a function.
  // @param function_entry_point The start address of the function to be hot
  //     patched.
  // @param new_entry_point A new function with the same signature that should
  //     be called instead of the old one.
  // @pre The function must have been prepared for hot patching: it must start
  //     with an instruction that is at least two bytes long and must have
  //     at least 5-byte padding before it and must have at least 2-byte
  //     alignment.
  bool Patch(FunctionPointer function_entry_point,
             FunctionPointer new_entry_point);

 private:
  DISALLOW_COPY_AND_ASSIGN(HotPatcher);
};

}  // namespace common
}  // namespace agent

#endif  // SYZYGY_AGENT_COMMON_HOT_PATCHER_H_
