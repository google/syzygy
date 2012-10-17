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
// Provides the Basic-Block Graph representation and APIs.
//
// See http://en.wikipedia.org/wiki/Basic_block for a brief discussion of
// basic blocks, their uses, and related terminology.

#ifndef SYZYGY_BLOCK_GRAPH_BASIC_BLOCK_H_
#define SYZYGY_BLOCK_GRAPH_BASIC_BLOCK_H_

#include "base/string_piece.h"
#include "syzygy/block_graph/block_graph.h"
#include "syzygy/core/assembler.h"
#include "syzygy/core/disassembler_util.h"

#include "distorm.h"  // NOLINT

namespace block_graph {

// Forward declarations.
class BasicBlock;
class BasicCodeBlock;
class BasicDataBlock;
class Instruction;
class Successor;

// Represents a reference from one basic-block to another basic-block or to
// another code- or data-block altogether.
class BasicBlockReference {
 public:
  typedef BlockGraph::ReferenceType ReferenceType;
  typedef BlockGraph::Block Block;
  typedef BlockGraph::Offset Offset;
  typedef BlockGraph::Size Size;

  enum ReferredType {
    REFERRED_TYPE_UNKNOWN,
    REFERRED_TYPE_BLOCK,
    REFERRED_TYPE_BASIC_BLOCK,

    // This enum value should always be last.
    MAX_REFERRED_TYPE,
  };

  // Default constructor; needed for storage in stl containers.
  BasicBlockReference();

  // Create a reference to a block.
  //
  // @param type type of reference.
  // @param size size of reference.
  // @param block the referenced block.
  // @param offset offset of reference into @p block.
  // @param base base of the reference within @p block.
  BasicBlockReference(ReferenceType type,
                      Size size,
                      Block* block,
                      Offset offset,
                      Offset base);

  // Create a reference to a basic-block.
  //
  // @param type type of reference.
  // @param size size of reference.
  // @param basic_block the referenced basic block.
  BasicBlockReference(ReferenceType type,
                      Size size,
                      BasicBlock* basic_block);

  // Creates a reference to the same destination as @p ref, but with
  // a potentially new type and size.
  //
  // @param type type of reference.
  // @param size size of reference.
  // @param basic_block the destination for the new reference.
  BasicBlockReference(ReferenceType type,
                      Size size,
                      const BasicBlockReference& ref);

  // Copy constructor.
  BasicBlockReference(const BasicBlockReference& other);

  // Accessors.
  // @{

  // Retrieves the type of block (macro or basic) that it referenced.
  ReferredType referred_type() const { return referred_type_; }

  // Retrieves the type reference (absolute or relative) for this reference.
  ReferenceType reference_type() const { return reference_type_; }

  // Retrieves the size of the reference.
  Size size() const { return size_; }

  // Retrieves the referenced block or NULL if this reference does not
  // refer to a block.
  const Block* block() const {
    return referred_type_ == REFERRED_TYPE_BLOCK ? referred_block_ : NULL;
  }

  // Retrieves the referenced block or NULL if this reference does not
  // refer to a block.
  Block* block() {
    return referred_type_ == REFERRED_TYPE_BLOCK ? referred_block_ : NULL;
  }

  // Retrieves the referenced basic-block or NULL if this reference does not
  // refer to a basic block.
  const BasicBlock* basic_block() const {
    return referred_type_ == REFERRED_TYPE_BASIC_BLOCK ?
        referred_basic_block_ : NULL;
  }

  // Retrieves the referenced basic-block or NULL if this reference does not
  // refer to a basic block.
  BasicBlock* basic_block() {
    return referred_type_ == REFERRED_TYPE_BASIC_BLOCK ?
        referred_basic_block_ : NULL;
  }

  // Retrieves the offset into the referenced macro- or basic-block.
  Offset offset() const { return offset_; }

  // Retrieves the base offset to which this reference refers.
  Offset base() const { return base_; }
  // @}

  // Compare this BasicBlockReferences with another for equality.
  bool operator==(const BasicBlockReference& other) const {
    return (referred_type_ == other.referred_type_ &&
            reference_type_ == other.reference_type_ &&
            size_ == other.size_ &&
            referred_block_ == other.referred_block_ &&
            offset_ == other.offset_);
  }

  // Test if this reference has been initialized to refer to something.
  bool IsValid() const {
    return size_ != 0 && referred_block_ != NULL;
  }

 protected:
  // Denotes whether this reference is to a block or basic block.
  ReferredType referred_type_;

  // The type of this reference.
  ReferenceType reference_type_;

  // The size of this reference.
  // Absolute references are always pointer wide, but PC-relative
  // references can be 1, 2 or 4 bytes wide, which affects their range.
  Size size_;

  // The block or basic-block that is referenced.
  union {
    Block* referred_block_;
    BasicBlock* referred_basic_block_;
  };

  // The offset into the referenced block or basic-block. This may or may not
  // end up referring into the target block's byte range.
  Offset offset_;

  // The base of the reference, as an offset into the referenced block or
  // basic-block. This must be a location strictly within the target block's
  // byte range.
  Offset base_;
};

// This class keeps track of a reference from an external block to a basic
// block. Instances of this only make sense in the context of a given basic
// block breakdown.
class BasicBlockReferrer {
 public:
  typedef BlockGraph::Block Block;
  typedef BlockGraph::Offset Offset;

  // Create an empty (invalid) BasicBlockReferrer.
  BasicBlockReferrer();

  // Create a BasicBlockReferrer which tracks that an external block makes
  // reference to this basic block.
  // @param block The block which refers to this basic block.
  // @param offset The offset in the block at which the reference occurs.
  BasicBlockReferrer(const Block* block, Offset offset);

  // Create a copy of the @p other BasicBlockReferrer.
  // @param other A basic block referrer record to be copy constructed.
  BasicBlockReferrer(const BasicBlockReferrer& other);

  // Returns the block which refers to this basic block, or NULL.
  const Block* block() const {
    return referrer_;
  }

  // Returns the offset in the referrer at which the reference to
  // the basic block occurs.
  Offset offset() const { return offset_; }

  // Returns whether or not this is a valid basic block referrer object.
  bool IsValid() const;

  // Equality comparator.
  bool operator==(const BasicBlockReferrer& other) const {
    return referrer_ == other.referrer_ && offset_ == other.offset_;
  }

  // Less-than comparator. Useful for putting BasicBlockReferrers into
  // ordered containers.
  struct CompareAsLess {
    bool operator()(const BasicBlockReferrer& lhs,
                    const BasicBlockReferrer& rhs) const {
      return lhs.referrer_ < rhs.referrer_ ||
         (lhs.referrer_ == rhs.referrer_ && lhs.offset_ < rhs.offset_);
    }
  };

 protected:
  // The referring block.
  const Block* referrer_;

  // The source offset in the block where the reference occurs.
  Offset offset_;
};

// Represents an instruction in a basic-block.
class Instruction {
 public:
  typedef BlockGraph::Size Size;
  typedef BlockGraph::Offset Offset;
  typedef BlockGraph::Block::SourceRange SourceRange;
  typedef _DInst Representation;
  typedef std::map<Offset, BasicBlockReference> BasicBlockReferenceMap;

  // Initialize an Instruction instance.
  // @param value The low-level object representing this instruction.
  // @param source_range The source range for the instruction if any.
  // @param size The length (in bytes) that the instruction occupied in the
  //     original block.
  // @param data A pointer to a buffer containing a machine executable
  //     encoding of the instruction. The buffer is expected to be @p size
  //     bytes long.
  // @note @p data must have a lifetime that exceeds this instruction.
  // TODO(rogerm): Retire this constructor along with the representation_
  //     member.
  Instruction(const Representation& value,
              SourceRange source_range,
              Size size,
              const uint8* data);

  // Initialize an Instruction instance.
  // @param size the length (in bytes) of @p data.
  // @param data the data comprising the instruction.
  // @note this instruction will copy @p data.
  Instruction(Size size, const uint8* data);

  // Copy constructor.
  Instruction(const Instruction& other);

  // Destructor.
  ~Instruction();

  // Accessors.
  // @{
  const Representation& representation() const { return representation_; }
  Representation& representation() { return representation_; }
  const BasicBlockReferenceMap& references() const { return references_; }
  BasicBlockReferenceMap& references() { return references_; }

  SourceRange source_range() const { return source_range_; }
  void set_source_range(const SourceRange& source_range) {
    source_range_ = source_range;
  }
  const BlockGraph::Label& label() const { return label_; }
  void set_label(const BlockGraph::Label& label) { label_ = label; }
  bool has_label() const { return label_.IsValid(); }

  Size size() const { return size_; }
  const uint8* data() const { return data_; }
  bool owns_data() const { return owns_data_; }
  /// @}

  // @name Deprecated accessors.
  // @{
  Offset offset() const { return offset_; }
  void set_offset(Offset offset) { offset_ = offset; }
  // @}

  // @name Helper functions.
  // @{
  bool IsNop() const { return core::IsNop(representation_); }
  bool IsControlFlow() const { return core::IsControlFlow(representation_); }
  bool IsImplicitControlFlow() const {
    return core::IsImplicitControlFlow(representation_);
  }
  bool IsInterrupt() const { return core::IsInterrupt(representation_); }
  bool IsDebugInterrupt() const {
    return core::IsDebugInterrupt(representation_);
  }
  bool CallsNonReturningFunction() const;
  // @}

  // Returns the maximum size required to serialize this instruction.
  Size GetMaxSize() const { return size_; }

  // Add a reference @p ref to this instruction at @p offset. If the reference
  // is to a basic block, also update that basic blocks referrer set.
  bool SetReference(Offset offset, const BasicBlockReference& ref);

  // Finds the reference, if any, for @p operand_index of this instruction.
  // @param operand_index the desired operand, in the range 0-3.
  // @param reference on success returns the reference.
  // @returns true iff @p operand_index exists and has a reference.
  bool FindOperandReference(size_t operand_index,
                            BasicBlockReference* reference) const;

  // Helper function to invert a conditional branching opcode.
  static bool InvertConditionalBranchOpcode(uint16* opcode);

  // Returns true if the given PC-relative or indirect-memory call instruction
  // is to a non-returning function. The block (and offset into it) being
  // directly referenced by the call need to be provided explicitly.
  static bool CallsNonReturningFunction(const Representation& inst,
                                        const BlockGraph::Block* target,
                                        Offset offset);

 protected:
  // The internal representation of this instruction.
  Representation representation_;

  // Captures the references (if any) that this instruction makes to another
  // basic block or macro block.
  BasicBlockReferenceMap references_;

  // The label, if any, associated with this instruction.
  BlockGraph::Label label_;

  // The source range, if any, associated with this instruction.
  SourceRange source_range_;

  // The data associated with this instruction.
  // @{
  Size size_;
  const uint8* data_;
  bool owns_data_;
  // @}

  // Deprecated.
  Offset offset_;
};

// This class represents a control flow transfer to a basic block, which
// includes both the target basic block as well as the condition on which
// control flows to that basic block.
class Successor {
 public:
  typedef core::AbsoluteAddress AbsoluteAddress;
  typedef BlockGraph::Offset Offset;
  typedef BlockGraph::Size Size;
  typedef BlockGraph::Block::SourceRange SourceRange;
  typedef std::map<Offset, BasicBlockReference> BasicBlockReferenceMap;

  // The op-code of an binary instruction.
  typedef uint16 OpCode;

  // The set of logical branching flow a successor may embody.
  enum Condition {
    // Sentinel value denoting an invalid branch condition.
    kInvalidCondition = -1,

    // These correspond to the conditional branch instructions.
    // @{
    kConditionAbove = core::kAbove,  // JA and JNBE.
    kConditionAboveOrEqual = core::kAboveEqual,  // JAE, JNB and JNC.
    kConditionBelow = core::kBelow,  // JB, JNAE and JC.
    kConditionBelowOrEqual = core::kBelowEqual,  // JBE and JNA.
    kConditionEqual = core::kEqual,  // JE and JZ.
    kConditionGreater =  core::kGreater,  // JG and JNLE.
    kConditionGreaterOrEqual = core::kGreaterEqual,  // JGE and JNL.
    kConditionLess = core::kLess,  // JL and JNGE.
    kConditionLessOrEqual = core::kLessEqual,  // JLE and JNG.
    kConditionNotEqual = core::kNotEqual,  // JNZ, JNE.
    kConditionNotOverflow = core::kNoOverflow,  // JNO.
    kConditionNotParity = core::kParityOdd,  // JNP and JPO.
    kConditionNotSigned = core::kNotSign,  // JNS.
    kConditionOverflow = core::kOverflow,  // JO.
    kConditionParity = core::kParityEven,  // JP and JPE.
    kConditionSigned = core::kSign,  // JS.

    // Definitions for the bounding values for the conditional branches.
    // Note: that the maximum must be defined here to let all subsequent
    //     enum values be properly incremented.
    kMinConditionalBranch = core::kMinConditionCode,
    kMaxConditionalBranch = core::kMaxConditionCode,

    // Unconditional control flow instructions.
    // @{
    kConditionTrue,  // JMP.
    // @}

    // Sentinels for the largest successor condition values.
    kMaxCondition,
  };

  // Constructors.
  // @{

  // Creates a dangling successor.
  //
  // This needs to exist so that successors can be stored in STL containers.
  Successor();

  // Creates a successor that resolves to a known block or basic block.
  //
  // @param condition the branching condition for this successor.
  // @param target the basic block to which this successor refers.
  // @param offset the offset in the original block at which the instruction(s)
  //     for this successor are located.
  // @param size the length (in bytes) that the instructions for this successor
  //     occupies in the original block.
  Successor(Condition condition,
            const BasicBlockReference& target,
            Size instruction_size);

  // Copy-constructor.
  Successor(const Successor& other);
  // @}

  // Accessors.
  // @{
  // The type of branch represented by this successor.
  Condition condition() const { return condition_; }

  BasicBlockReference reference() const { return reference_; }
  void set_reference(const BasicBlockReference& reference) {
    reference_ = reference;
  };

  SourceRange source_range() const { return source_range_; }
  void set_source_range(const SourceRange& source_range) {
    source_range_ = source_range;
  }
  Size instruction_size() const { return instruction_size_; }
  const BlockGraph::Label& label() const { return label_; }
  void set_label(const BlockGraph::Label& label) { label_ = label; }
  bool has_label() const { return label_.IsValid(); }
  // @}

  // Set the target reference @p ref for this successor. If @p ref refers
  // to a basic block, also update that basic block's referrer set.
  bool SetReference(const BasicBlockReference& ref);

  // Get the branch type that corresponds to the given @p op_code.
  // @returns kInvalidCondition if @p op_code isn't a recognized branch
  //     instruction.
  static Condition OpCodeToCondition(OpCode op_code);

  // Get the condition that represents the inversion of the given @p condition.
  //
  // @p conditon the condition to invert.
  // @returns kInvalidCondition if @p condition is not invertible.
  static Condition InvertCondition(Condition condition);

  // Returns a textual description of this successor.
  std::string ToString() const;

 protected:
  // The type of branch represented by this successor.
  Condition condition_;

  // The destination for this successor.
  BasicBlockReference reference_;

  // The label, if any, associated with this successor.
  BlockGraph::Label label_;

  // The source range, if any, associated with this successor.
  SourceRange source_range_;

  // The size of the instruction this successor is derived from,
  // or zero if it's synthesized or added post-decomposition.
  Size instruction_size_;
};

// An indivisible portion of code or data within a code block.
//
// See http://en.wikipedia.org/wiki/Basic_block for a general description of
// the properties. This has been augmented with the ability to also represent
// blocks of data that are tightly coupled with the code (jump and case tables
// for example).
class BasicBlock {
 public:
  enum BasicBlockType {
    BASIC_CODE_BLOCK,
    BASIC_DATA_BLOCK,
    BASIC_PADDING_BLOCK,

    // This must be last.
    BASIC_BLOCK_TYPE_MAX
  };

  typedef BlockGraph::BlockId BlockId;
  typedef std::list<Instruction> Instructions;
  typedef BlockGraph::Size Size;
  typedef std::list<Successor> Successors;
  typedef BlockGraph::Offset Offset;

  // The collection of references this basic block makes to other basic
  // blocks, keyed by the references offset relative to the start of this
  // basic block.
  typedef Instruction::BasicBlockReferenceMap BasicBlockReferenceMap;

  // The set of the blocks that have a reference to this basic block.
  // This is keyed on block and source offset (not destination offset),
  // to allow us to easily locate and remove the back-references on change or
  // deletion.
  typedef std::set<BasicBlockReferrer, BasicBlockReferrer::CompareAsLess>
      BasicBlockReferrerSet;

  // This offset is used to denote that an instruction, successor, or
  // basic block has been synthesized and has no corresponding image in
  // the original block.
  static const Offset kNoOffset;

  // Virtual destructor to allow subclassing.
  virtual ~BasicBlock();

  // Return a textual label for a basic block type.
  static const char* BasicBlockTypeToString(BasicBlockType type);

  // Accessors.
  // @{
  BasicBlockType type() const { return type_; }
  const std::string& name() const { return name_; }

  Offset offset() const { return offset_; }
  void set_offset(Offset offset) { offset_ = offset; }

  const BasicBlockReferrerSet& referrers() const { return referrers_; }
  BasicBlockReferrerSet& referrers() { return referrers_; }
  // @}

  // Returns true iff this basic block is a valid block (i.e., it
  // is a BASIC_DATA_BLOCK the contains data XOR a BASIC_CODE_BLOCK that
  // contains instructions and/or successors.
  virtual bool IsValid() const = 0;

 protected:
  // Initialize a basic block.
  // @param name A textual identifier for this basic block.
  // @param type The disposition (code, data, padding) of this basic block.
  BasicBlock(const base::StringPiece& name,
             BasicBlockType type);

  // The type of this basic block.
  const BasicBlockType type_;

  // The name of this basic block.
  std::string name_;

  // The offset of this basic block in the oritinal block. Set to the offset
  // of the first byte the basic block originated from during decomposition.
  // Useful as a stable, unique identifier for basic blocks in a decomposition.
  Offset offset_;

  // The set of basic blocks references (from other basic blocks in same
  // original block) to this basic block.
  BasicBlockReferrerSet referrers_;

  // The label associated with this basic block.
  BlockGraph::Label label_;

 private:
  DISALLOW_COPY_AND_ASSIGN(BasicBlock);
};

class BasicCodeBlock : public BasicBlock {
 public:
  // Initialize a basic code block.
  // @param name A textual identifier for this basic block.
  explicit BasicCodeBlock(const base::StringPiece& name);

  // Down-cast from basic block to basic code block.
  static BasicCodeBlock* Cast(BasicBlock* basic_block);
  static const BasicCodeBlock* Cast(const BasicBlock* basic_block);

  // Accessors.
  // @{
  const Instructions& instructions() const { return instructions_; }
  Instructions& instructions() { return instructions_; }
  const Successors& successors() const { return successors_; }
  Successors& successors() { return successors_; }
  // @}

  // Returns true iff this basic block is a valid code block - i.e., it
  // contains at least one instruction and/or 0-2 successors.
  virtual bool IsValid() const OVERRIDE;

  // Return the number of bytes required to store the instructions
  // this basic block contains, exclusive successors.
  Size GetInstructionSize() const;

 private:
  // The set of non-branching instructions comprising this basic-block.
  // Any branching at the end of the basic-block is represented using the
  // successors_ member.
  Instructions instructions_;

  // The set of (logical) successors to this basic block. There can only be
  // 0, 1 or 2 successors in this list.
  // If there is a single successor, it must be unconditional.
  // If there are two successors, they must have complementary conditions.
  Successors successors_;

 private:
  DISALLOW_COPY_AND_ASSIGN(BasicCodeBlock);
};

class BasicDataBlock : public BasicBlock {
 public:
  typedef BlockGraph::Block::SourceRange SourceRange;

  // Initialize a basic data or padding block.
  // @param name A textual identifier for this basic block.
  // @param type The disposition (data or padding) of this basic block.
  // @param data The block's data, must be non-NULL.
  // @param size The size of @p data, must be greater than zero.
  // @note The block does not take ownership of @p data, and @p data must have
  //     a lifetime greater than the block.
  BasicDataBlock(const base::StringPiece& name,
                 BasicBlockType type,
                 const uint8* data,
                 Size size);

  // Down-cast from basic block to basic data block.
  static BasicDataBlock* Cast(BasicBlock* basic_block);
  static const BasicDataBlock* Cast(const BasicBlock* basic_block);

  // Accessors.
  // @{
  Size size() const { return size_; }
  const uint8* data() const { return data_; }

  const BasicBlockReferenceMap& references() const { return references_; }
  BasicBlockReferenceMap& references() { return references_; }

  SourceRange source_range() const { return source_range_; }
  void set_source_range(const SourceRange& source_range) {
    source_range_ = source_range;
  }

  const BlockGraph::Label& label() const { return label_; }
  void set_label(const BlockGraph::Label& label) { label_ = label; }
  bool has_label() const { return label_.IsValid(); }
  // @}

  // Add a reference @p ref to this basic block at @p offset.
  bool SetReference(Offset offset, const BasicBlockReference& ref);

  // Returns true iff this basic block is a valid block i.e., it contains data.
  virtual bool IsValid() const OVERRIDE;

 private:
  // The number of bytes of data in the original block that corresponds with
  // this basic block.
  Size size_;

  // The data in the original block that corresponds with this basic block
  // will be referenced here.
  const uint8* data_;

  // The source range, if any, associated with this data block.
  SourceRange source_range_;

  // The map of references (if any) that this block makes to other basic blocks
  // from the original block.
  BasicBlockReferenceMap references_;

 private:
  DISALLOW_COPY_AND_ASSIGN(BasicDataBlock);
};

}  // namespace block_graph

#endif  // SYZYGY_BLOCK_GRAPH_BASIC_BLOCK_H_
