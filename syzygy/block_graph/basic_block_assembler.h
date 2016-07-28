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
// Provides an assembler that assembles to basic block instruction lists.

#ifndef SYZYGY_BLOCK_GRAPH_BASIC_BLOCK_ASSEMBLER_H_
#define SYZYGY_BLOCK_GRAPH_BASIC_BLOCK_ASSEMBLER_H_

#include "syzygy/assm/assembler_base.h"
#include "syzygy/block_graph/basic_block.h"
#include "syzygy/block_graph/block_graph.h"

namespace block_graph {

using assm::ValueSize;

// Declares a BasicBlockReference-like class that has no type or size
// information. The size information is stored in the Operand or Value housing
// the untyped reference, and the type is inferred from the instruction being
// assembled.
class UntypedReference {
 public:
  typedef BlockGraph::Block Block;
  typedef BlockGraph::Offset Offset;

  // Default constructor.
  UntypedReference()
      : basic_block_(NULL), block_(NULL), offset_(0), base_(0) {
  }

  // Copy constructor.
  // @param other The reference to be copied.
  UntypedReference(const UntypedReference& other)
      : basic_block_(other.basic_block_), block_(other.block_),
        offset_(other.offset_), base_(other.base_) {
  }

  // Constructor from a basic block reference.
  // @param bb_ref The basic block reference to be copied.
  explicit UntypedReference(const BasicBlockReference& bb_ref)
      : basic_block_(bb_ref.basic_block()), block_(bb_ref.block()),
        offset_(bb_ref.offset()), base_(bb_ref.base()) {
    DCHECK(block_ != NULL || basic_block_ != NULL);
  }

  // Constructs a reference to a basic block.
  // @param basic_block The basic block to be referred to.
  explicit UntypedReference(BasicBlock* basic_block)
      : basic_block_(basic_block), block_(NULL), offset_(0), base_(0) {
    DCHECK(basic_block != NULL);
  }

  // Constructs a reference to a block.
  // @param block The block to be referred to.
  // @param offset The offset from the start of the block actually being
  //     pointed to.
  // @param base The offset from the start of the block semantically being
  //     referred to.
  UntypedReference(Block* block, Offset offset, Offset base)
      : basic_block_(NULL), block_(block), offset_(offset), base_(base) {
    DCHECK(block != NULL);
  }

  // @name Accessors.
  // @{
  BasicBlock* basic_block() const { return basic_block_; }
  Block* block() const { return block_; }
  Offset offset() const { return offset_; }
  Offset base() const { return base_; }
  // @}

  // @returns true if this reference is valid.
  bool IsValid() const { return block_ != NULL || basic_block_ != NULL; }

  // Returns the type of the object being referred to.
  BasicBlockReference::ReferredType referred_type() const {
    if (block_ != NULL)
      return BasicBlockReference::REFERRED_TYPE_BLOCK;
    if (basic_block_ != NULL)
      return BasicBlockReference::REFERRED_TYPE_BASIC_BLOCK;
    return BasicBlockReference::REFERRED_TYPE_UNKNOWN;
  }

  // Comparison operator.
  // @returns true if this reference is the same as the @p other.
  bool operator==(const UntypedReference& other) const {
    return basic_block_ == other.basic_block_ &&
        block_ == other.block_ &&
        offset_ == other.offset_ &&
        base_ == other.base_;
  }

  // Assignment operator.
  const UntypedReference& operator=(const UntypedReference& other) {
    basic_block_ = other.basic_block_;
    block_ = other.block_;
    offset_ = other.offset_;
    base_ = other.base_;

    return *this;
  }

 private:
  BasicBlock* basic_block_;
  Block* block_;
  Offset offset_;
  Offset base_;
};

class BasicBlockAssembler : public assm::AssemblerBase<UntypedReference> {
 public:
  typedef assm::AssemblerBase<UntypedReference> Super;

  typedef BlockGraph::Block::SourceRange SourceRange;
  typedef BasicBlock::Instructions Instructions;
  typedef assm::Register8 Register8;
  typedef assm::Register16 Register16;
  typedef assm::Register32 Register32;
  typedef assm::ConditionCode ConditionCode;

  // Constructs a basic block assembler that inserts new instructions
  // into @p *list at @p where.
  BasicBlockAssembler(const Instructions::iterator& where,
                      Instructions *list);

  // Constructs a basic block assembler that inserts new instructions into
  // @p *list at @p where, assuming a starting address of @p location.
  BasicBlockAssembler(uint32_t location,
                      const Instructions::iterator& where,
                      Instructions* list);

  // @returns The source range injected into created instructions.
  SourceRange source_range() const { return serializer_.source_range(); }

  // Set the SourceRange injected repeatedly into each instruction created via
  // the assembler. This should be used with care because it causes the OMAP
  // information to no longer be 1:1 mapping, and may confuse some debuggers.
  // @param source_range The source range set to each created instructions.
  void set_source_range(const SourceRange& source_range) {
    serializer_.set_source_range(source_range);
  }

  // @name Call instructions.
  // @{
  void call(const Immediate& dst);
  void call(const Operand& dst);
  // @}

  // @name Jmp instructions.
  // @{
  void jmp(const Immediate& dst);
  void jmp(const Operand& dst);
  void jmp(const Register32& dst);
  // @}

  // @name Conditional branch instruction.
  // @{
  void j(ConditionCode code, const Immediate& dst);
  // @}

 private:
  typedef BlockGraph::ReferenceType ReferenceType;

  class BasicBlockSerializer
      : public assm::AssemblerBase<UntypedReference>::InstructionSerializer {
   public:
    BasicBlockSerializer(const Instructions::iterator& where,
                         Instructions* list);

    void AppendInstruction(uint32_t location,
                           const uint8_t* bytes,
                           uint32_t num_bytes,
                           const ReferenceInfo* refs,
                           size_t num_refs) override;
    bool FinalizeLabel(uint32_t location,
                       const uint8_t* bytes,
                       size_t num_bytes) override;

    SourceRange source_range() const { return source_range_; }
    void set_source_range(const SourceRange& source_range) {
      source_range_ = source_range;
    }

    // Pushes back a reference type to be associated with a untyped reference.
    // @param type The type of the reference.
    // @param size The size of the reference, as a ValueSize.
    void PushReferenceInfo(ReferenceType type, assm::ValueSize size);

   private:
    Instructions::iterator where_;
    Instructions* list_;

    // Source range set to instructions appended by this serializer.
    SourceRange source_range_;
  };

  BasicBlockSerializer serializer_;
};

// @name Immediate factory functions.
// @{

// Default construction.
BasicBlockAssembler::Immediate Immediate();

// Constructs an 8- or 32-bit Immediate, depending on the minimum number of
// bits required to represent the Immediate. If the Immediate can be encoded
// using 8-bits to have the same representation under sign extension, then an
// 8-bit Immediate will be created; otherwise, a 32-bit absolute Immediate will
// be created.
// @param value The value to be stored.
BasicBlockAssembler::Immediate Immediate(uint32_t value);

// Constructs an absolute Immediate having a specific bit width.
// @param value The value to be stored.
// @param size The size of the value.
BasicBlockAssembler::Immediate Immediate(uint32_t value, assm::ValueSize size);

// Constructs a 32-bit direct reference to the basic block @p bb.
// @param bb The basic block to be referred to.
// @note This is fine even for jmps (which may be encoded using 8-bit
//     references) as the BB layout algorithm will use the shortest jmp
//     possible.
BasicBlockAssembler::Immediate Immediate(BasicBlock* bb);

// Constructs a 32-bit direct reference to @p block at the given @p offset.
// @param block The block to be referred to.
// @param offset The offset to be referred to, both semantically and
//     literally. The base and offset of the reference will be set to this.
// @note This is fine even for jmps (which may be encoded using 8-bit
//     references) as the BB layout algorithm will use the shortest jmp
//     possible.
BasicBlockAssembler::Immediate Immediate(
    BlockGraph::Block* block, BlockGraph::Offset offset);

// Constructs a 32-bit reference to @p block at the given @p offset and
// @p base.
// @param block The block to be referred to.
// @param offset The offset to be literally referred to.
// @param base The offset to be semantically referred to. This must be
//     within the data of @p block.
BasicBlockAssembler::Immediate Immediate(
    BlockGraph::Block* block, BlockGraph::Offset offset,
    BlockGraph::Offset base);

// Full constructor.
// @param value The value to be stored.
// @param size The size of the Immediate.
// @param ref The untyped reference backing this Immediate. The reference must
//     be valid.
BasicBlockAssembler::Immediate Immediate(uint32_t value,
                                         ValueSize size,
                                         const UntypedReference& ref);

// @}

// @name Displacement factory functions.
// @{

// Default construction.
BasicBlockAssembler::Displacement Displacement();

// Constructs an 8- or 32-bit Displacement, depending on the minimum number of
// bits required to represent the Displacement. If the Displacement can be
// encoded using 8-bits to have the same representation under sign extension,
// then an 8-bit Displacement will be created; otherwise, a 32-bit absolute
// Displacement will be created.
// @param value The value to be stored.
BasicBlockAssembler::Displacement Displacement(uint32_t value);

// Constructs an absolute Displacement having a specific bit width.
// @param value The value to be stored.
// @param size The size of the Displacement.
BasicBlockAssembler::Displacement Displacement(uint32_t value, ValueSize size);

// Constructs a 32-bit direct reference to the basic block @p bb.
// @param bb The basic block to be referred to.
// @note This is fine even for jmps (which may be encoded using 8-bit
//     references) as the BB layout algorithm will use the shortest jmp
//     possible.
BasicBlockAssembler::Displacement Displacement(BasicBlock* bb);

// Constructs a 32-bit direct reference to @p block at the given @p offset.
// @param block The block to be referred to.
// @param offset The offset to be referred to, both semantically and
//     literally. The base and offset of the reference will be set to this.
// @note This is fine even for jmps (which may be encoded using 8-bit
//     references) as the BB layout algorithm will use the shortest jmp
//     possible.
BasicBlockAssembler::Displacement Displacement(
    BlockGraph::Block* block, BlockGraph::Offset offset);

// Constructs a 32-bit reference to @p block at the given @p offset and
// @p base.
// @param block The block to be referred to.
// @param offset The offset to be literally referred to.
// @param base The offset to be semantically referred to. This must be
//     within the data of @p block.
BasicBlockAssembler::Displacement Displacement(BlockGraph::Block* block,
                                               BlockGraph::Offset offset,
                                               BlockGraph::Offset base);

// Full constructor.
// @param value The value to be stored.
// @param size The size of the Displacement.
// @param ref The untyped reference backing this Displacement. The reference
//     must be valid.
BasicBlockAssembler::Displacement Displacement(uint32_t value,
                                               ValueSize size,
                                               const UntypedReference& ref);

// @}

// @name Operand factory functions.
// @{

// A register-indirect mode.
BasicBlockAssembler::Operand Operand(const assm::Register32& base);

// A register-indirect with displacement mode.
BasicBlockAssembler::Operand Operand(
    const assm::Register32& base,
    const BasicBlockAssembler::Displacement& displ);

// A displacement-only mode.
BasicBlockAssembler::Operand Operand(
    const BasicBlockAssembler::Displacement& displ);

// The full [base + index * scale + displ32] mode.
// @note esp cannot be used as an index register.
BasicBlockAssembler::Operand Operand(
    const assm::Register32& base, const assm::Register32& index,
    assm::ScaleFactor scale, const BasicBlockAssembler::Displacement& displ);

// The full [base + index * scale] mode.
// @note esp cannot be used as an index register.
BasicBlockAssembler::Operand Operand(const assm::Register32& base,
                                     const assm::Register32& index,
                                     assm::ScaleFactor scale);

// The [index * scale + displ32] mode.
// @note esp cannot be used as an index register.
BasicBlockAssembler::Operand Operand(
    const assm::Register32& index, assm::ScaleFactor scale,
    const BasicBlockAssembler::Displacement& displ);

// @}

}  // namespace block_graph

#endif  // SYZYGY_BLOCK_GRAPH_BASIC_BLOCK_ASSEMBLER_H_
