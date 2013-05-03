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

#include "syzygy/block_graph/basic_block.h"
#include "syzygy/core/assembler.h"

namespace block_graph {

using core::ValueSize;

// Forward declarations.
class BasicBlockAssembler;
class Operand;

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

 private:
  BasicBlock* basic_block_;
  Block* block_;
  Offset offset_;
  Offset base_;
};

class Value {
 public:
  typedef BlockGraph::Block Block;
  typedef BlockGraph::Offset Offset;
  typedef core::ValueImpl ValueImpl;
  typedef core::ValueSize ValueSize;

  // Default construction.
  Value();

  // Constructs an 8- or 32-bit value, depending on the minimum number of bits
  // required to represent the Value. If the value can be encoded using 8-bits
  // to have the same representation under sign extension, then an 8-bit Value
  // will be created; otherwise, a 32-bit absolute Value will be created.
  // @param value The value to be stored.
  explicit Value(uint32 value);

  // Constructs an absolute value having a specific bit width.
  // @param value The value to be stored.
  // @param size The size of the value.
  Value(uint32 value, ValueSize size);

  // Constructs a 32-bit direct reference to the basic block @p bb.
  // @param bb The basic block to be referred to.
  // @note This is fine even for jmps (which may be encoded using 8-bit
  //     references) as the BB layout algorithm will use the shortest jmp
  //     possible.
  explicit Value(BasicBlock* bb);

  // Constructs a 32-bit direct reference to @p block at the given @p offset.
  // @param block The block to be referred to.
  // @param offset The offset to be referred to, both semantically and
  //     literally. The base and offset of the reference will be set to this.
  // @note This is fine even for jmps (which may be encoded using 8-bit
  //     references) as the BB layout algorithm will use the shortest jmp
  //     possible.
  Value(Block* block, Offset offset);

  // Constructs a 32-bit reference to @p block at the given @p offset and
  // @p base.
  // @param block The block to be referred to.
  // @param offset The offset to be literally referred to.
  // @param base The offset to be semantically referred to. This must be
  //     within the data of @p block.
  Value(Block* block, Offset offset, Offset base);

  // Full constructor.
  // @param value The value to be stored.
  // @param size The size of the value.
  // @param ref The untyped reference backing this value. The reference must
  //     be valid.
  Value(uint32 value, ValueSize size, const UntypedReference& ref);

  // Copy constructor.
  // @param other The value to be copied.
  Value(const Value& other);

  // Destructor.
  ~Value();

  // Assignment operator.
  const Value& operator=(const Value& other);

  // @name Accessors.
  // @{
  uint32 value() const { return value_.value(); }
  ValueSize size() const { return value_.size(); }
  const UntypedReference& reference() const { return reference_; }
  // @}

  // Comparison operator.
  bool operator==(const Value& rhs) const;

 private:
  // Private constructor for Operand.
  Value(const UntypedReference& ref, const core::ValueImpl& value);

  friend class BasicBlockAssembler;
  friend class Operand;

  UntypedReference reference_;
  ValueImpl value_;
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

  // The full [base + index * scale] mode.
  // @note esp cannot be used as an index register.
  Operand(core::Register base,
          core::Register index,
          core::ScaleFactor scale);

  // The [index * scale + displ32] mode.
  // @note esp cannot be used as an index register.
  Operand(core::Register index,
          core::ScaleFactor scale,
          const Displacement& displ);

  // Copy constructor.
  Operand(const Operand& o);

  // Destructor.
  ~Operand();

  // Assignment operator.
  const Operand& operator=(const Operand& other);

  // @name Accessors.
  // @{
  core::RegisterCode base() const { return operand_.base(); }
  core::RegisterCode index() const { return operand_.index(); }
  core::ScaleFactor scale() const { return operand_.scale(); }
  Displacement displacement() const {
    return Displacement(reference_, operand_.displacement());
  }
  // @}

 private:
  friend class BasicBlockAssembler;

  UntypedReference reference_;
  core::OperandImpl operand_;
};

class BasicBlockAssembler {
 public:
  typedef BlockGraph::Block::SourceRange SourceRange;
  typedef BasicBlock::Instructions Instructions;
  typedef core::Register Register;
  typedef core::ConditionCode ConditionCode;

  // Constructs a basic block assembler that inserts new instructions
  // into @p *list at @p where.
  BasicBlockAssembler(const Instructions::iterator& where,
                      Instructions *list);

  // Constructs a basic block assembler that inserts new instructions into
  // @p *list at @p where, assuming a starting address of @p location.
  BasicBlockAssembler(uint32 location,
                      const Instructions::iterator& where,
                      Instructions *list);

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
  // @}

  // @name Conditional branch instruction.
  // @{
  void j(ConditionCode code, const Immediate& dst);
  // @}

  // @name Manipulation of flags.
  // @{
  void pushfd();
  void popfd();
  void lahf();
  void sahf();
  void set(ConditionCode code, Register dst);
  // @}

  // @name Arithmetic operations.
  // @{
  void cmp(Register dst, Register src);
  void cmp(Register dst, const Operand& src);
  void cmp(const Operand& dst, Register src);
  void cmp(Register dst, const Immediate& src);
  void cmp(const Operand& dst, const Immediate& src);

  void add(Register dst, Register src);
  void add(Register dst, const Operand& src);
  void add(const Operand& dst, Register src);
  void add(Register dst, const Immediate& src);
  void add(const Operand& dst, const Immediate& src);

  void sub(Register dst, Register src);
  void sub(Register dst, const Operand& src);
  void sub(const Operand& dst, Register src);
  void sub(Register dst, const Immediate& src);
  void sub(const Operand& dst, const Immediate& src);
  // @}

  // @name Shifting operations.
  // @{
  void shl(Register dst, const Immediate& src);
  void shr(Register dst, const Immediate& src);
  // @}

  // @name Byte mov varieties.
  // @{
  void mov_b(const Operand& dst, const Immediate& src);
  // @}

  // @name Double-word mov varieties.
  // @{
  void mov(Register dst, Register src);
  void mov(Register dst, const Operand& src);
  void mov(const Operand& dst, Register src);
  void mov(Register dst, const Immediate& src);
  void mov(const Operand& dst, const Immediate& src);
  void mov_fs(Register dst, const Operand& src);
  void mov_fs(const Operand& dst, Register src);
  // @}

  // @name Load effective address.
  void lea(Register dst, const Operand& src);

  // @name Stack manipulation.
  // @{
  void push(Register src);
  void push(const Immediate& src);
  void push(const Operand& src);

  void pop(Register dst);
  void pop(const Operand& dst);
  // @}

  // @name Ret instructions.
  // @{
  void ret();
  void ret(uint16 n);
  // @}

 private:
  typedef BlockGraph::ReferenceType ReferenceType;

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

    SourceRange source_range() const { return source_range_; }
    void set_source_range(const SourceRange& source_range) {
      source_range_ = source_range;
    }

    // Pushes back a reference type to be associated with a untyped reference.
    // @param type The type of the reference.
    // @param size The size of the reference, as a ValueSize.
    void PushReferenceInfo(ReferenceType type, core::ValueSize size);

   private:
    struct ReferenceInfo {
      BlockGraph::ReferenceType type;
      size_t size;  // In bytes.
    };

    Instructions::iterator where_;
    Instructions* list_;

    // Source range set to instructions appended by this serializer.
    SourceRange source_range_;

    // The reference types and sizes associated with references in the
    // instructions parameters. These are provided to the serializer out of
    // band (not via Operand/Immediate/Value) by the implementations of the
    // various instructions. They allow the corresponding UntypedReferences to
    // be completed.
    ReferenceInfo ref_infos_[2];
    size_t num_ref_infos_;
  };

  // @name Utility functions for pushing/validating reference info.
  // @{
  void PushMandatoryReferenceInfo(ReferenceType type, const Immediate& imm);
  void PushOptionalReferenceInfo(ReferenceType type, const Immediate& imm);
  void PushOptionalReferenceInfo(ReferenceType type, const Operand& op);
  void CheckReferenceSize(core::ValueSize size, const Immediate& imm) const;
  void CheckReferenceSize(core::ValueSize size, const Operand& op) const;
  // @}

  BasicBlockSerializer serializer_;
  core::AssemblerImpl asm_;
};

}  // namespace block_graph

#endif  // SYZYGY_BLOCK_GRAPH_BASIC_BLOCK_ASSEMBLER_H_
