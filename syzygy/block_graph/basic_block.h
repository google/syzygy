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
// Provides the Basic-Block Graph representation and APIs.
//
// See http://en.wikipedia.org/wiki/Basic_block for a brief discussion of
// basic blocks, their uses, and related terminology.

#ifndef SYZYGY_BLOCK_GRAPH_BASIC_BLOCK_H_
#define SYZYGY_BLOCK_GRAPH_BASIC_BLOCK_H_

#include "base/string_piece.h"
#include "syzygy/block_graph/block_graph.h"

#include "distorm.h"  // NOLINT

namespace block_graph {

class Instruction;
class BasicBlock;

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
  // @param basic_block the referenced basic block.
  // @param offset offset of reference into basic_block.
  BasicBlockReference(ReferenceType type,
                      Size size,
                      Block* basic_block,
                      Offset offset);

  // Create a reference to a basic-block.
  //
  // @param type type of reference.
  // @param size size of reference.
  // @param basic_block the referenced basic block.
  // @param offset offset of reference into basic_block.
  BasicBlockReference(ReferenceType type,
                      Size size,
                      BasicBlock* basic_block,
                      Offset offset);

  // Copy constructor.
  BasicBlockReference(const BasicBlockReference& other);

  // Accessors.
  // @{

  ReferredType referred_type() const { return referred_type_; }

  // Retrieves the type of block (macro or basic) that it referenced.
  ReferenceType reference_type() const { return reference_type_; }

  // Retrieves the size of the reference.
  Size size() const { return size_; }

  // Retrieves the referenced block or NULL if this reference does not
  // refer to a block.
  Block* block() {
    return static_cast<Block*>(
        referred_type_ == REFERRED_TYPE_BLOCK ? referred_ : NULL);
  }

  // Retrieves the referenced basic-block or NULL if this reference does not
  // refer to a basic block.
  BasicBlock* basic_block() {
    return static_cast<BasicBlock*>(
        referred_type_ == REFERRED_TYPE_BASIC_BLOCK ? referred_ : NULL);
  }

  // Retrieves the offset into the referenced macro- or basic-block.
  Offset offset() const { return offset_; }

  // @}

  // Compare this BasicBlockReferences with another for equality.
  bool operator==(const BasicBlockReference& other) const {
    return (referred_type_ == other.referred_type_ &&
            reference_type_ == other.reference_type_ &&
            size_ == other.size_ &&
            referred_ == other.referred_ &&
            offset_ == other.offset_);
  }

  // Test if this reference has been initialized to refer to something.
  bool IsValid() const {
    return size_ != 0 && referred_ != NULL;
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
  void* referred_;

  // The offset into the referenced block or basic-block.
  Offset offset_;
};

// This class denotes a block or basic block have a reference to a basic
// block. Instances of this only make sense in the context of a give
// basic block.
class BasicBlockReferrer {
 public:
  typedef BlockGraph::Block Block;
  typedef BlockGraph::Offset Offset;
  typedef BlockGraph::Size Size;

  enum ReferrerType {
    REFERRER_TYPE_UNKNOWN,
    REFERRER_TYPE_BLOCK,
    REFERRER_TYPE_BASIC_BLOCK,

    // This enum value should always be last.
    MAX_REFERRER_TYPE,
  };

  // Create an empty (invalid) BasicBlockReferrer.
  BasicBlockReferrer();

  // Create a BasicBlockReferrer which tracks that an external block makes
  // reference to this basic block.
  // @param block The block which refers to this basic block.
  // @param offset The offset in the block at which the reference occurs.
  BasicBlockReferrer(Block* block, Offset offset);

  // Create a BasicBlockReferrer which tracks that another basic block makes
  // reference to this basic block.
  // @param basic_block The basic block which refers to this basic block.
  // @param offset The offset in the basic block at which the reference occurs.
  BasicBlockReferrer(BasicBlock* basic_block, Offset offset);

  // Create a copy of the @p other BasicBlockReferrer.
  // @param other A basic block referrer record to be copy constructed.
  BasicBlockReferrer(const BasicBlockReferrer& other);

  // Returns the type of referrer this object describes.
  ReferrerType referrer_type() const { return referrer_type_; }

  // Returns the block which refers to this basic block, or NULL.
  Block* block() {
    return static_cast<Block*>(
        referrer_type_ == REFERRER_TYPE_BLOCK ? referrer_ : NULL);
  }

  // Returns the basic block which refers to this basic block, or NULL.
  BasicBlock* basic_block() {
    return static_cast<BasicBlock*>(
      referrer_type_ == REFERRER_TYPE_BASIC_BLOCK ? referrer_ : NULL);
  }

  // Returns the offset in the referrer at which the reference to
  // the basic block occurs.
  Offset offset() const { return offset_; }

  // Returns whether or not this is a valid basic block referrer object.
  bool IsValid() const {
    return referrer_type_ != REFERRER_TYPE_UNKNOWN &&
        referrer_ != NULL &&
        offset_ >= 0;
  }

  // Equality comparator.
  bool operator==(const BasicBlockReferrer& other) const {
    return referrer_type_ == other.referrer_type_ &&
        referrer_ == other.referrer_ &&
        offset_ == other.offset_;
  }

 protected:
  // Flags whether the referrer is a block or basic block.
  ReferrerType referrer_type_;

  // The referring block or basic block.
  void* referrer_;

  // The source offset in the block or basic block where the reference
  // occurs.
  Offset offset_;
};

// Represents an instruction in a basic-block.
class Instruction {
 public:
  typedef BlockGraph::Size Size;
  typedef BlockGraph::Offset Offset;
  typedef _DInst Representation;
  typedef std::map<Offset, BasicBlockReference> BasicBlockReferenceMap;

  // Initialize an Instruction instance.
  // @param value The low-level object representing this instruction.
  // @param offset The offset in the original block at which the instruction
  //     was located.
  // @param size The length (in bytes) that the instruction occupied in the
  //     original block.
  Instruction(const Representation& value, Offset offset, Size size);

  // Accessors.
  // @{
  const Representation& representation() const { return representation_; }
  Representation& representation() { return representation_; }
  const BasicBlockReferenceMap& references() const { return references_; }
  BasicBlockReferenceMap& references() { return references_; }
  Offset offset() const { return offset_; }
  Size size() const { return size_; }
  /// @}

  // Helper function to invert a conditional branching opcode.
  static bool InvertConditionalBranchOpcode(uint16* opcode);

 protected:
  // The internal representation of this instruction.
  Representation representation_;

  // Captures the references (if any) that this instruction makes to another
  // basic block or macro block.
  BasicBlockReferenceMap references_;

  // The byte range in the original block where this instruction originates.
  // @{
  Offset offset_;
  Size size_;
  // @}
};

// This class represents a control flow transfer to a basic block, which
// includes both the target basic block as well as the condition on which
// control flows to that basic block.
class Successor {
 public:
  typedef core::AbsoluteAddress AbsoluteAddress;
  typedef BlockGraph::Offset Offset;
  typedef BlockGraph::Size Size;

  // The op-code of an binary instruction.
  typedef uint16 OpCode;

  // The set of logical branching flow a successor may embody.
  enum Condition {
    // Sentinel value denoting an invalid branch condition.
    kInvalidCondition,

    // Unconditional control flow instructions.
    // @{
    kConditionTrue,  // Equivalent to JMP.
    // @}

    // These correspond to the conditional branch instructions.
    // @{
    kConditionAbove,  // Equivalent to JA and JNBE.
    kConditionAboveOrEqual,  // Equivalent to JAE, JNB and JNC.
    kConditionBelow,  // Equivalent to JB, JNAE and JC.
    kConditionBelowOrEqual,  // Equivalent to JBE and JNA.
    kConditionEqual,  // Equivalent to JE and JZ.
    kConditionGreater,  // Equivalent to JG and JNLE.
    kConditionGreaterOrEqual,  // Equivalent to JGE and JNL.
    kConditionLess,  // Equivalent to JL and JNGE.
    kConditionLessOrEqual,  // Equivalent to JLE and JNG.
    kConditionNotEqual,  // Equivalent to JNZ, JNE.
    kConditionNotOverflow,  // Equivalent to JNO
    kConditionNotParity,  // Equivalent to JNP and JPO.
    kConditionNotSigned,  // Equivalent to JNS.
    kConditionOverflow,  // Equivalent to JO.
    kConditionParity,  // Equivalent to JP, JPE.
    kConditionSigned,  // Equivalent to JS.

    // The countdown conditional.
    // @{
    kCounterIsZero,  // Equivalent to JCXZ and JECXZ.
    // @}

    // The looping branch family of conditionals.
    // @{
    kLoopTrue,  // Equivalent to LOOP
    kLoopIfEqual,  // Equivalent to LOOPE and LOOPZ.
    kLoopIfNotEqual,  // Equivalent to LOOPNE and LOOPNZ.
    // @}

    // The following are pseudo instructions used to denote the logical
    // inverse of one of the above conditional branches, where no such
    // actual inverse conditional branch exists in the instruction set.
    // @{
    kInverseCounterIsZero,
    kInverseLoopTrue,
    kInverseLoopIfEqual,
    kInverseLoopIfNotEqual,
    // @}

    // A sentinel for the largest successor condition value.
    kMaxCondition,
  };

  // Constructors.
  // @{

  // Creates a dangling successor.
  //
  // This needs to exist so that successors can be stored in STL containers.
  Successor();

  // Creates a successor without resolving it to a basic block.
  //
  // It is expected that a subsequent pass through the basic-block address
  // space will be used to resolve each absolute address to a basic block
  // structure and that each successor will have its branch_target set.
  //
  // @param condition the branching condition for this successor.
  // @param target the absolute address to which this successor refers.
  // @param offset the offset in the original block at which the instruction(s)
  //     for this successor are located.
  // @param size the length (in bytes) that the instructions for this successor
  //     occupies in the original block.
  Successor(Condition condition,
            AbsoluteAddress target,
            Offset offset,
            Size size);

  // Creates a successor that resolves to a known block or basic block.
  //
  // @param condition the branching condition for this successor.
  // @param target the basic block to which this successor refers.
  // @param offset the offset in the original block at which the instruction(s)
  //     for this successor are located.
  // @param size the length (in bytes) that the instructions for this successor
  //     occupies in the original block.
  Successor(Condition condition,
            const BasicBlockReference& target_,
            Offset offset,
            Size size);
  // @}

  // Accessors.
  // @{
  // The type of branch represented by this successor.
  Condition condition() const { return condition_; }
  const BasicBlockReference& branch_target() const { return branch_target_; }
  void set_branch_target(const BasicBlockReference& target) {
    branch_target_ = target;
  }
  AbsoluteAddress original_target_address() const {
    return original_target_address_;
  }
  Offset offset() const { return offset_; }
  Size size() const { return size_; }
  // @}

  // Get the branch type that corresponds to the given @p op_code.
  // @returns kInvalidCondition if @p op_code isn't a recognized branch
  //     instruction.
  static Condition OpCodeToCondition(OpCode op_code);

  // Get the condition that represents the inversion of the given @p condition.
  //
  // @p conditon the condition to invert.
  // @returns kInvalidCondition if @p condition is not invertible.
  static Condition InvertCondition(Condition condition);

  // Set the branch target to @p target.
  //
  // @pre The successor is not yet resolved to a basic block or already
  //     resolves to @p target.
  // @return true of the block target is successfully set to @p target.
  bool ResolvesTo(BasicBlock* target);

  // Returns a textual description of this successor.
  std::string ToString() const;

 protected:
  // The type of branch represented by this successor.
  Condition condition_;

  // The original address of the branch target. Setting this on construction
  // facilitates resolving the target basic block after the fact.
  AbsoluteAddress original_target_address_;

  // The basic block of instructions that are the target of this successor.
  BasicBlockReference branch_target_;

  // The byte range in the original block where this instruction originates.
  // @{
  Offset offset_;
  Size size_;
  // @}
};

// An indivisible portion of code or data within a code block.
//
// See http://en.wikipedia.org/wiki/Basic_block for a general description of
// the properties. This has been augmented with the ability to also represent
// blocks of data that are tightly coupled with the code (jump and case tables
// for example).
class BasicBlock {
 public:
  typedef BlockGraph::BlockId BlockId;
  typedef BlockGraph::BlockType BlockType;
  typedef std::list<Instruction> Instructions;
  typedef BlockGraph::Size Size;
  typedef std::list<Successor> Successors;
  typedef BlockGraph::Offset Offset;
  typedef core::AddressRange<core::AbsoluteAddress, Size> SourceRange;

  // The collection of references this basic block makes to other basic
  // blocks, keyed by the references offset relative to the start of this
  // basic block.
  typedef std::map<Offset, BasicBlockReference> BasicBlockReferenceMap;

  // The set of the basic blocks that have a reference to this basic block.
  // This is keyed on basic block and source offset (not destination offset),
  // to allow us to easily locate and remove the backreferences on change or
  // deletion.
  // @{
  typedef std::pair<BasicBlock*, Offset> BasicBlockReferrer;
  typedef std::set<BasicBlockReferrer> BasicBlockReferrerSet;
  // @}

  // The collection of references this basic block makes to other macro
  // blocks (other than the original macro block in which this basic
  // block resides).
  typedef BlockGraph::Block::ReferenceMap ReferenceMap;

  // The set of macro blocks that have a reference to this basic block.
  // @{
  typedef BlockGraph::Block::Referrer Referrer;
  typedef BlockGraph::Block::ReferrerSet ReferrerSet;
  // @}

  // Initialize a basic block.
  // @param id A unique identifier for this basic block.
  // @param name A textual identifier for this basic block.
  // @param type The disposition (code, data, padding) of this basic block.
  // @param offset The offset (in the original block) where this basic block
  //     originated. Set to -1 to indicate that this is a programmatically
  //     generated basic block.
  // @param size The number of bytes this basic block occupied in the original
  //     block. Set to 0 if this is programmatically generated basic block.
  // @param
  BasicBlock(BlockId id,
             const base::StringPiece& name,
             BlockType type,
             Offset offset,
             Size size,
             const uint8* data);

  // Accessors.
  // @{
  BlockId id() const { return id_; }
  BlockType type() const { return type_; }
  const std::string& name() const { return name_; }
  Offset offset() const { return offset_; }
  Size size() const { return size_; }
  const uint8* data() const { return data_; }
  const Instructions& instructions() const { return instructions_; }
  Instructions& instructions() { return instructions_; }
  const Successors& successors() const { return successors_; }
  Successors& successors() { return successors_; }
  BasicBlockReferenceMap& references() { return references_; }
  BasicBlockReferrerSet& referrers() { return referrers_; }
  // @}

  // Returns true if this basic block represents a valid block (i.e., it
  // is a BASIC_DATA_BLOCK the contains data XOR a BASIC_CODE_BLOCK that
  // contains instructions and/or successors.
  bool IsValid() const;

 protected:
  // The ID for this basic block.
  BlockId id_;

  // The name of this basic block.
  std::string name_;

  // The type of this basic block.
  BlockType type_;

  // The offset in the original block that corresponds with the start of this
  // basic block. A negative offset denotes that there is no corresponding
  // offset in the original block.
  Offset offset_;

  // The number of bytes of data in the original block that corresponds with
  // this basic block.
  Size size_;

  // The data in the original block that corresponds with this basic block
  // will be referenced here.
  const uint8* data_;

  // The map of references (if any) that this block makes to other basic blocks
  // from the original block.
  BasicBlockReferenceMap references_;

  // The set of basic blocks referenes (from other basic blocks in same
  // original block) to this basic block.
  BasicBlockReferrerSet referrers_;

  // The set of non-branching instructions comprising this basic-block.
  // Any branching at the end of the basic-block is represented using the
  // successors_ member.
  Instructions instructions_;

  // The set of (logical) branching instructions that terminate this basic
  // block. There should be exactly 0, 1 or 2 branching instructions in this
  // set, each referencing their respective branch target. The instructions
  // in this list should be ordered such that the last instruction represents
  // the fall-through (default) path of control flow and the penultimate
  // instruction (if any) is a conditional branch.
  // TODO(rogerm): reverse this order? infer which is which?
  Successors successors_;
};

}  // namespace block_graph

#endif  // SYZYGY_BLOCK_GRAPH_BASIC_BLOCK_H_
