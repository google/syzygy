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

#include <cstdlib>
#include <ctime>
#include <iostream>

#include "syzygy/assm/assembler.h"
#include "syzygy/assm/assembler_base.h"
#include "syzygy/block_graph/basic_block_subgraph.h"
#include "syzygy/block_graph/basic_block_assembler.h"

#ifndef SYZYGY_PROTECT_PROTECT_LIB_CODE_RANDOMIZER_H_
#define SYZYGY_PROTECT_PROTECT_LIB_CODE_RANDOMIZER_H_

class RegState {
public:
  // Construct a state in which all registers are live
  RegState() {
    _live_regs.insert(assm::RegisterId::kRegisterEax);
    _live_regs.insert(assm::RegisterId::kRegisterEbx);
    _live_regs.insert(assm::RegisterId::kRegisterEcx);
    _live_regs.insert(assm::RegisterId::kRegisterEdx);
    //_live_regs.insert(assm::RegisterId::kRegisterEsi);
    //_live_regs.insert(assm::RegisterId::kRegisterEdi);
  }

  // Adds a register to the used register vector
  // @param reg register to be added
  void Add(assm::RegisterId reg) {
    _live_regs.insert(reg);
  }

  // Removes a register from the used register vector
  // @param reg register to be removed
  void Delete(assm::RegisterId reg) {
    _live_regs.erase(reg);
  }

  // Returns true if a register is safe to use,
  // false otherwise.
  // @param reg register to be removed
  bool IsSafe(assm::RegisterId reg) {
    if (_live_regs.count(reg) > 0)
      return false;

    return true;
  }

  // Function for pretty printing, prints
  // directly to stdout
  void Print() {
    for (auto it = _live_regs.begin(); it != _live_regs.end(); ++it)
      std::cout << *it << " ";

    std::cout << std::endl;
  }

  int instruction_count = 0;  // Instructions added so far
  int extra_stack = 0;  // Extra stack that has been allocated

protected:
  std::set<assm::RegisterId> _live_regs;
};

class CodeRandomizer {
public:
  typedef block_graph::BasicBlock::Instructions Instructions;
  typedef block_graph::Instruction Instruction;

  // Tries to reorder a list o instructions
  // @param where iterator to the starting point of the section
  // @param list list containing the range of instructions
  // @param size number of instructions that need to be shuffled
  static void Shuffle(const Instructions::iterator& where,
    Instructions *list, int size);

  // Adds a random ADD X / SUB -X to the assembler provided
  // @param assm assembler in which the randomized add/sub will be added
  // @param reg register to which the value is added
  // @param val value to be added
  // @param reg_size register size
  // @param state state used for keeping track of number of operations
  //        and used registers
  static void RandAdd(block_graph::BasicBlockAssembler &assm,
    const assm::Register32 &reg, uint32_t val, assm::ValueSize reg_size,
    RegState &state);

  // Adds a random SUB X / ADD -X to the assembler provided
  // @param assm assembler in which the randomized sub/add will be added
  // @param reg register to which the value is added
  // @param val value to be added
  // @param reg_size register size
  // @param state state used for keeping track of number of operations
  //        and used registers
  static void RandSub(block_graph::BasicBlockAssembler &assm,
    const assm::Register32 &reg, uint32_t val, assm::ValueSize reg_size,
    RegState &state);

  // Adds a PUSH or equivalent code to the assembler provided
  // @param assm assembler to which the randomized push will be added
  // @param T source from which the data is pushed; can be a register,
  //        immediate or operand
  // @param reg_size register size
  // @param state state used for keeping track of number of operations
  //        and used registers
  template<typename T>
  static void RandPush(block_graph::BasicBlockAssembler &assm,
    const T &source, assm::ValueSize reg_size,
    RegState &state);

  // Adds a POP or equivalent code to the assembler provided
  // @param assm assembler to which the randomized pop will be added
  // @param T dest from which the data is pushed; can be a register
  //          or operand
  // @param reg_size register size
  // @param state state used for keeping track of number of operations
  //        and used registers
  template<typename T>
  static void RandPop(block_graph::BasicBlockAssembler &assm,
    const T &dest, assm::ValueSize reg_size,
    RegState &state);

  // Applies a random modification to the ESP register, an ADD/SUB with a
  // random value
  // @param assm assembler to which the instruction will be added
  // @param state state used for keeping track of number of operations
  //        and used registers
  static void RandModifyESP(block_graph::BasicBlockAssembler &assm,
                            RegState &state);

  // Resets the value of ESP to the real one
  // Whenever RandPush or RandPop are used, this function needs to be called
  // afterwards, to ensure the correct state of the ESP register
  // @param assm assembler to which the instruction will be added
  // @param state state used for keeping track of number of operations
  //        and used registers
  static void ClearExtraStack(block_graph::BasicBlockAssembler &assm,
                              RegState &state);

  // Generates code that calculates a given addres in the provided reg
  // @param assm assembler to which the instruction will be added
  // @param reg register which will hold the calculated value
  // @param address address which has to be calculated
  // @param reg_size size of the address
  static void GenerateAddress(block_graph::BasicBlockAssembler &assm,
    const assm::Register32 &reg, uint32_t address, assm::ValueSize reg_size);

};

#endif  // SYZYGY_PROTECT_PROTECT_LIB_CODE_RANDOMIZER_H_