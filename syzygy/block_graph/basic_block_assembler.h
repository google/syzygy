// Copyright 2012 Google Inc.
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
// Provides an assembler that assembles to basic block instruction lists.

#ifndef SYZYGY_BLOCK_GRAPH_BASIC_BLOCK_ASSEMBLER_H_
#define SYZYGY_BLOCK_GRAPH_BASIC_BLOCK_ASSEMBLER_H_

#include "syzygy/block_graph/basic_block.h"
#include "syzygy/core/assembler.h"

namespace block_graph {

class BasicBlockAssembler;
class Operand;

class Value {
 public:
  Value();
  // Constructs an 8 or 32 bit value.
  explicit Value(uint32 value);
  // Constructs a 32 bit absolute value referring to the basic block @p bb.
  explicit Value(BasicBlock* bb);
  // Constructs a 32 bit absolute value referring to @p block at @p offset.
  Value(BlockGraph::Block* block, BlockGraph::Offset offset);

  // @name Accessors.
  // @{
  uint32 value() const { return value_.value(); }
  core::ValueSize size() const { return value_.size(); }
  const BasicBlockReference &reference() const { return reference_; }
  // @}

 private:
  friend class BasicBlockAssembler;
  friend class Operand;

  BasicBlockReference reference_;
  core::ValueImpl value_;
};

// Displacements and immediates behave near-identically, but are semantically
// slightly different.
typedef Value Immediate;
typedef Value Displacement;

// An operand implies indirection to memory through one of the myriad
// modes supported by IA32.
class Operand {
 public:
  // A register-indirect mode.
  explicit Operand(core::Register base);

  // A register-indirect with displacement mode.
  Operand(core::Register base, const Displacement& displ);

  // A displacement-only mode.
  explicit Operand(const Displacement& displ);

  // The full [base + index * scale + displ32] mode.
  // @note esp cannot be used as an index register.
  Operand(core::Register base,
          core::Register index,
          core::ScaleFactor scale,
          const Displacement& displ);

  // @name Accessors.
  // @{
  core::RegisterCode base() const { return operand_.base(); }
  core::RegisterCode index() const { return operand_.index(); }
  core::ScaleFactor scale() const { return operand_.scale(); }
  const Displacement& displacement() const { return displacement_; }
  // @}

 private:
  friend class BasicBlockAssembler;

  core::OperandImpl operand_;
  Displacement displacement_;
};

class BasicBlockAssembler {
 public:
  typedef BasicBlock::Instructions Instructions;
  typedef core::Register Register;

  // Constructs a basic block assembler that inserts new instructions
  // into @p *list at @p where.
  BasicBlockAssembler(const Instructions::iterator& where,
                      Instructions *list);

  // @name mov in several varieties.
  // @{
  void mov(Register dst, Register src);
  void mov(Register dst, const Operand& src);
  void mov(const Operand& dst, Register src);
  void mov(Register dst, const Immediate& src);
  void mov(const Operand& dst, const Immediate& src);
  // @}

 private:
  class BasicBlockSerializer
      : public core::AssemblerImpl::InstructionSerializer {
   public:
    BasicBlockSerializer(const Instructions::iterator& where,
                         Instructions* list);

    virtual void AppendInstruction(uint32 location,
                                   const uint8* bytes,
                                   size_t num_bytes,
                                   const size_t *ref_locations,
                                   const void* const* refs,
                                   size_t num_refs) OVERRIDE;

   private:
    Instructions::iterator where_;
    Instructions* list_;
  };

  BasicBlockSerializer serializer_;
  core::AssemblerImpl asm_;
};

}  // namespace block_graph

#endif  // SYZYGY_BLOCK_GRAPH_BASIC_BLOCK_ASSEMBLER_H_
