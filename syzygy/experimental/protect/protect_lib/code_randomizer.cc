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

#include "syzygy/experimental/protect/protect_lib/code_randomizer.h"

#include <string.h>
#include <algorithm>
#include <iostream>
#include <vector>
#include <type_traits>
#include <iterator>

#include "syzygy/core/disassembler_util.h"
#include "syzygy/assm/assembler.h"
#include "syzygy/assm/assembler_base.h"
#include "syzygy/block_graph/basic_block_subgraph.h"
#include "syzygy/block_graph/basic_block_assembler.h"
#include "syzygy/block_graph/basic_block_decomposer.h"
#include "syzygy/block_graph/analysis/liveness_analysis.h"

#include "syzygy/experimental/protect/protect_lib/equation_gen.h"


#define MOV "MOV"
#define PUSH "PUSH"
#define POP "POP"

// Calculates N0 as N1 OP1 N2 OP2 N3 and stores it in reg
void CodeRandomizer::GenerateAddress(block_graph::BasicBlockAssembler &assm,
  const assm::Register32 &reg, uint32_t N0, assm::ValueSize reg_size)
{
  uint32_t N1 = rand();
  uint32_t N2 = rand();
  uint32_t N3 = 0;
  int OP1_types = 8;

  assm.mov(reg, block_graph::Immediate(N1, reg_size));

  switch (rand() % OP1_types) {
  case 0:
    // ADD
    assm.add(reg, block_graph::Immediate(N2, reg_size));
    N3 = N1 + N2;
    break;

  case 1:
    // SUB
    assm.sub(reg, block_graph::Immediate(N2, reg_size));
    N3 = N1 - N2;
    break;

  case 2:
    // IMUL
    assm.imul(reg, reg, block_graph::Immediate(N2, reg_size));
    N3 = N1 * N2;
    break;

  case 3:
    // XOR
    assm.xor(reg, block_graph::Immediate(N2, reg_size));
    N3 = N1 ^ N2;
    break;

  case 4:
    // AND
    assm.and(reg, block_graph::Immediate(N2, reg_size));
    N3 = N1 & N2;
    break;

  case 5:
    // OR
    //assm.or(reg, block_graph::Immediate(N2, reg_size));
    //N3 = N1 | N2;
    //break;

  case 6:
    // SHR
    N2 = N2 % 32;
    assm.shr(reg, block_graph::Immediate((uint8_t)N2,
      assm::ValueSize::kSize8Bit));
    N3 = N1 >> N2;
    break;

  default:
    // SHL
    N2 = N2 % 32;
    assm.shl(reg, block_graph::Immediate((uint8_t)N2,
      assm::ValueSize::kSize8Bit));
    N3 = N1 << N2;
  }

  // We now have (N1 OP1 N2) in reg and the result as N3
  // Chose an inversable operation
  int OP2_types = 3;
  switch (rand() % OP2_types) {
  case 0:
    // ADD
    N3 = N0 - N3;
    assm.add(reg, block_graph::Immediate(N3, reg_size));
    break;

  case 1:
    // SUB
    N3 = N3 - N0;
    assm.sub(reg, block_graph::Immediate(N3, reg_size));
    break;

  default:
    // XOR
    N3 = N0 ^ N3;
    assm.xor(reg, block_graph::Immediate(N3, reg_size));
    break;
  }

  // We now have in reg the value of the address, and we can use it
}


// Finds an unused register, in the context of the given state
// @param assm assembler in use
// @param state current state of the registers
// @param save_reg out parameter marks the fact that the returned register
//        needs to be saved onto the stack
// @returns the register which can be used
const assm::Register32 FindSafeRegister(block_graph::BasicBlockAssembler &assm,
  RegState &state, bool &save_reg)
{
  // Try all registers
  std::vector<const assm::Register32> regs;
  regs.push_back(assm::eax);
  regs.push_back(assm::ebx);
  regs.push_back(assm::ecx);
  regs.push_back(assm::edx);
  //regs.push_back(assm::esi);
  //regs.push_back(assm::edi);

  std::random_shuffle(regs.begin(), regs.end());

  for (int i = 0; i < (int)regs.size(); ++i)
    if (state.IsSafe(regs[i].id())) {
      save_reg = false;
      return regs[i];
    }

  save_reg = true;
  return regs[0];
}

#define MAX_STEPS 32
#define INC_STEP 4
#define SKIPPING_LIKELINESS 6

void CodeRandomizer::RandModifyESP(block_graph::BasicBlockAssembler &assm,
                                   RegState &state)
{
  int range = MAX_STEPS;
  int val = (std::rand() % range) * INC_STEP;

  // On the first two cases we do either a SUB or an ADD
  switch (std::rand() % SKIPPING_LIKELINESS) {
  case 0:
    RandAdd(assm, assm::esp, val * 4, //bytes not bits
            assm::ValueSize::kSize32Bit, state);
    state.extra_stack -= val;
    state.instruction_count += 1;
    break;

  case 1:
  RandSub(assm, assm::esp, val * 4, //bytes not bits
            assm::ValueSize::kSize32Bit, state);
    state.extra_stack += val;
    state.instruction_count += 1;
    break;

  default:
    ;
  }
}

void CodeRandomizer::ClearExtraStack(block_graph::BasicBlockAssembler &assm,
                                     RegState &state)
{
  if (state.extra_stack) {
    RandAdd(assm, assm::esp, state.extra_stack * 4, // bytes not bits
      assm::ValueSize::kSize32Bit, state);
    state.instruction_count += 1;
    state.extra_stack = 0;
  }
}

void CodeRandomizer::RandAdd(block_graph::BasicBlockAssembler &assm,
  const assm::Register32 &reg, uint32_t val, assm::ValueSize reg_size,
  RegState &state)
{
  assm.add(reg, block_graph::Immediate(val, reg_size));
  state.instruction_count += 1;
}

void CodeRandomizer::RandSub(block_graph::BasicBlockAssembler &assm,
  const assm::Register32 &reg, uint32_t val, assm::ValueSize reg_size,
  RegState &state)
{
  assm.sub(reg, block_graph::Immediate(val, reg_size));
  state.instruction_count += 1;
}

template<typename T>
void CodeRandomizer::RandPush(block_graph::BasicBlockAssembler &assm,
  const T &source, assm::ValueSize size, RegState &state)
{
  uint32_t reg_size = (uint32_t)size / 8;
  if (std::rand() % 3 == 0) {
    ClearExtraStack(assm, state);
    assm.push(source);
    state.instruction_count += 1;

  }
  else {
    bool save_temp = true;
    bool transfer_directly = false; // mov from register or via another reg
    uint32_t offset = 0;
    const assm::Register32 temp = FindSafeRegister(assm, state, save_temp);

    // Unless the source is an operand, we can try to transfer
    // it directly to the stack
    if (!std::is_same<T, block_graph::BasicBlockAssembler::Operand>::value)
      if (std::rand() % 2)
        transfer_directly = true;

    // If there are no free registers, save the temp value
    if (save_temp && !transfer_directly) {
      // Bring back ESP to it's correct value and allocate
      // one extra space so that the temp can be saved
      ClearExtraStack(assm, state);
      RandSub(assm, assm::esp, reg_size, assm::ValueSize::kSize32Bit, state);
      assm.push(temp);

      state.instruction_count += 1;
      offset += reg_size;
    }

    // Emit the code
    // (maybe)SUB/ADD ESP, RAND * REG_SIZE
    // (maybe) PUSH TEMP
    // (maybe) MOV TEMP, SOURCE
    // (maybe)SUB / ADD ESP, RAND * REG_SIZE
    // MOV [ESP + offset], TEMP/SOURCE
    // (maybe)SUB / ADD ESP, RAND * REG_SIZE
    // (maybe) POP TEMP
    RandModifyESP(assm, state);

    if (transfer_directly) {
      state.extra_stack--;
      offset += state.extra_stack;

      if (std::is_same<T, assm::Register32>::value) {
        assm.mov(block_graph::Operand(assm::esp,
          block_graph::Displacement(offset * reg_size,
          assm::ValueSize::kSize32Bit)),
          *((assm::Register32 *)(&source)));
      }
      else if (std::is_same<T,
               block_graph::BasicBlockAssembler::Immediate>::value) {
        assm.mov(block_graph::Operand(assm::esp,
          block_graph::Displacement(offset * reg_size,
          assm::ValueSize::kSize32Bit)),
          *((block_graph::BasicBlockAssembler::Immediate *)(&source)));
      }

      state.instruction_count += 1;

    }
    else {
      assm.mov(temp, source);
      RandModifyESP(assm, state);

      state.extra_stack--;
      offset += state.extra_stack;
      assm.mov(block_graph::Operand(assm::esp,
        block_graph::Displacement(offset * reg_size,
        assm::ValueSize::kSize32Bit)),
        temp);

      state.instruction_count += 2;
    }

    // Restore the register if it was saved
    if (save_temp) {
      ClearExtraStack(assm, state);
      assm.pop(temp);
      state.instruction_count++;
      state.extra_stack++;
    }

    RandModifyESP(assm, state);
  }

  state.Delete(((assm::Register32 *)(&source))->id());
}

template<typename T>
void CodeRandomizer::RandPop(block_graph::BasicBlockAssembler &assm,
  const T &destination, assm::ValueSize reg_size, RegState &state)
{
  if (std::rand() % 3) {
    ClearExtraStack(assm, state);
    assm.pop(destination);
    state.instruction_count += 1;

  }
  else {
    bool save_temp = true;
    bool transfer_directly = false;
    uint32_t offset = 0;
    const assm::Register32 temp = FindSafeRegister(assm, state, save_temp);


    // Unless the source is an operand, we can try to transfer
    // it directly to the stack
    if (!std::is_same<T, block_graph::BasicBlockAssembler::Operand>::value)
      if (std::rand() % 2)
        transfer_directly = true;

    // If there are no free registers, save the temp register
    if (save_temp && !transfer_directly) {
      // Bring back ESP to it's correct value and allocate
      // one extra space so that the temp can be saved
      ClearExtraStack(assm, state);
      assm.push(temp);
      state.instruction_count += 2;
      offset += reg_size;
    }

    // Emit the code
    // (maybe)SUB / ADD ESP, RAND * REG_SIZE
    // (maybe) PUSH TEMP
    // (maybe)SUB / ADD ESP, RAND * REG_SIZE
    // MOV TEMP/DEST, [ESP + offset]
    // (maybe) MOV DEST, TEMP
    // (maybe)SUB / ADD ESP, RAND * REG_SIZE
    // (maybe) POP TEMP
    RandModifyESP(assm, state);

    // Pretty bad.
    if (transfer_directly) {
      offset += state.extra_stack;
      assm.mov(block_graph::Operand(assm::esp,
        block_graph::Displacement(offset, assm::ValueSize::kSize32Bit)),
        *((assm::Register32 *)(&destination)));

      state.instruction_count++;
      state.extra_stack++;

    }
    else {
      RandModifyESP(assm, state);
      offset += state.extra_stack;
      assm.mov(temp, block_graph::Operand(assm::esp,
        block_graph::Displacement(offset, assm::ValueSize::kSize32Bit)));
      assm.mov(destination, temp);

      state.instruction_count += 2;
      state.extra_stack++;
    }


    // Restore the register if it was saved
    if (save_temp)
      assm.pop(temp);

    // Restore the register if it was saved
    if (save_temp) {
      ClearExtraStack(assm, state);
      assm.pop(temp);
      state.instruction_count++;
    }

    RandModifyESP(assm, state);
  }

  if (std::is_same<T, assm::Register32>::value)
    state.Add(((assm::Register32 *)(&destination))->id());
}

template void CodeRandomizer::RandPush<assm::Register32>(
  block_graph::BasicBlockAssembler &,
  const assm::Register32 &, assm::ValueSize, RegState &);

template void CodeRandomizer::
RandPush<block_graph::BasicBlockAssembler::Immediate>(
    block_graph::BasicBlockAssembler &,
    const block_graph::BasicBlockAssembler::Immediate &,
    assm::ValueSize, RegState &);

template void CodeRandomizer::
RandPush<block_graph::BasicBlockAssembler::Operand>(
    block_graph::BasicBlockAssembler &,
    const block_graph::BasicBlockAssembler::Operand &,
    assm::ValueSize, RegState &);

template void CodeRandomizer::RandPop<assm::Register32>(
    block_graph::BasicBlockAssembler &,
    const assm::Register32 &, assm::ValueSize, RegState &);

template void CodeRandomizer::
RandPop<block_graph::BasicBlockAssembler::Operand>(
    block_graph::BasicBlockAssembler &,
    const block_graph::BasicBlockAssembler::Operand &, assm::ValueSize,
    RegState &);