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
#include "syzygy/core/assembler.h"

#include "distorm.h"  // NOLINT

namespace block_graph {

// Forward declarations.
class BasicBlock;
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
  // @param basic_block the referenced basic block.
  // @param offset offset of reference into basic_block.
  BasicBlockReference(ReferenceType type,
                      Size size,
                      Block* basic_block,
                      Offset offset,
                      Offset base);

  // Create a reference to a basic-block.
  //
  // @param type type of reference.
  // @param size size of reference.
  // @param basic_block the referenced basic block.
  // @param offset offset of reference into basic_block.
  BasicBlockReference(ReferenceType type,
                      Size size,
                      BasicBlock* basic_block,
                      Offset offset,
                      Offset base);

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
    return static_cast<const Block*>(
        referred_type_ == REFERRED_TYPE_BLOCK ? referred_ : NULL);
  }

  // Retrieves the referenced block or NULL if this reference does not
  // refer to a block.
  Block* block() {
    return static_cast<Block*>(
        referred_type_ == REFERRED_TYPE_BLOCK ? referred_ : NULL);
  }

  // Retrieves the referenced basic-block or NULL if this reference does not
  // refer to a basic block.
  const BasicBlock* basic_block() const {
    return static_cast<const BasicBlock*>(
        referred_type_ == REFERRED_TYPE_BASIC_BLOCK ? referred_ : NULL);
  }

  // Retrieves the referenced basic-block or NULL if this reference does not
  // refer to a basic block.
  BasicBlock* basic_block() {
    return static_cast<BasicBlock*>(
        referred_type_ == REFERRED_TYPE_BASIC_BLOCK ? referred_ : NULL);
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

  // The offset into the referenced block or basic-block. This may or may not
  // end up referring into the target block's byte range.
  Offset offset_;

  // The base of the reference, as an offset into the referenced block or
  // basic-block. This must be a location strictly within the target block's
  // byte range.
  Offset base_;
};

// This class denotes a block or basic block have a reference to a basic
// block. Instances of this only make sense in the context of a give
// basic block.
class BasicBlockReferrer {
 public:
  typedef BlockGraph::Block Block;
  typedef BlockGraph::Offset Offset;

  enum ReferrerType {
    REFERRER_TYPE_UNKNOWN,
    REFERRER_TYPE_BLOCK,
    REFERRER_TYPE_BASIC_BLOCK,
    REFERRER_TYPE_INSTRUCTION,
    REFERRER_TYPE_SUCCESSOR,

    // This enum value should always be last.
    MAX_REFERRER_TYPE,
  };

  // Create an empty (invalid) BasicBlockReferrer.
  BasicBlockReferrer();

  // Create a BasicBlockReferrer which tracks that an external block makes
  // reference to this basic block.
  // @param block The block which refers to this basic block.
  // @param offset The offset in the block at which the reference occurs.
  BasicBlockReferrer(const Block* block, Offset offset);

  // Create a BasicBlockReferrer which tracks that another basic block makes
  // reference to this basic block.
  // @param basic_block The basic block which refers to this basic block.
  // @param offset The offset in the basic block at which the reference occurs.
  BasicBlockReferrer(const BasicBlock* basic_block, Offset offset);

  // Create a BasicBlockReferrer which tracks that an instruction makes
  // reference to this basic block.
  // @param instruction The instruction which refers to this basic block.
  // @param offset The offset in the instruction at which the reference occurs.
  BasicBlockReferrer(const Instruction* instruction, Offset offset);

  // Create a BasicBlockReferrer which tracks that a successor makes
  // reference to this basic block.
  // @param successor The successor which refers to this basic block.
  explicit BasicBlockReferrer(const Successor* successor);

  // Create a copy of the @p other BasicBlockReferrer.
  // @param other A basic block referrer record to be copy constructed.
  BasicBlockReferrer(const BasicBlockReferrer& other);

  // Returns the type of referrer this object describes.
  ReferrerType referrer_type() const { return referrer_type_; }

  // Returns the block which refers to this basic block, or NULL.
  const Block* block() const {
    return static_cast<const Block*>(
        referrer_type_ == REFERRER_TYPE_BLOCK ? referrer_ : NULL);
  }

  // Returns the basic block which refers to this basic block, or NULL.
  const BasicBlock* basic_block() const {
    return static_cast<const BasicBlock*>(
      referrer_type_ == REFERRER_TYPE_BASIC_BLOCK ? referrer_ : NULL);
  }

  // Returns the instruction which refers to this basic block, or NULL.
  const Instruction* instruction() const {
    return static_cast<const Instruction*>(
        referrer_type_ == REFERRER_TYPE_INSTRUCTION ? referrer_ : NULL);
  }

  // Returns the basic block which refers to this basic block, or NULL.
  const Successor* successor() const {
    return static_cast<const Successor*>(
      referrer_type_ == REFERRER_TYPE_SUCCESSOR ? referrer_ : NULL);
  }

  // Returns the offset in the referrer at which the reference to
  // the basic block occurs.
  Offset offset() const { return offset_; }

  // Returns whether or not this is a valid basic block referrer object.
  bool IsValid() const;

  // Equality comparator.
  bool operator==(const BasicBlockReferrer& other) const {
    return referrer_type_ == other.referrer_type_ &&
        referrer_ == other.referrer_ &&
        offset_ == other.offset_;
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
  // Flags whether the referrer is a block or basic block.
  ReferrerType referrer_type_;

  // The referring block or basic block.
  const void* referrer_;

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
  // @param data A pointer to a buffer containing a machine executable
  //     encoding of the instruction. The buffer is expected to be @p size
  //     bytes long.
  Instruction(const Representation& value,
              Offset offset,
              Size size,
              const uint8* data);

  // Accessors.
  // @{
  const Representation& representation() const { return representation_; }
  Representation& representation() { return representation_; }
  const BasicBlockReferenceMap& references() const { return references_; }
  BasicBlockReferenceMap& references() { return references_; }
  const uint8* data() const { return data_; }
  Offset offset() const { return offset_; }
  Size size() const { return size_; }
  /// @}

  // Returns the maximum size required to serialize this instruction.
  Size GetMaxSize() const { return size_; }

  // Add a reference @p ref to this instruction at @p offset. If the reference
  // is to a basic block, also update that basic blocks referrer set.
  bool SetReference(Offset offset, const BasicBlockReference& ref);

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
  const uint8* const data_;
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

    // The countdown conditional.
    // @{
    kCounterIsZero,  // JCXZ and JECXZ.
    // @}

    // The looping branch family of conditionals.
    // @{
    kLoopTrue,  // LOOP
    kLoopIfEqual,  // LOOPE and LOOPZ.
    kLoopIfNotEqual,  // LOOPNE and LOOPNZ.
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

    // Sentinels for the largest successor condition values.
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
  // structure and that each successor will have its reference set.
  //
  // @param condition the branching condition for this successor.
  // @param target the absolute address to which this successor refers.
  // @param offset the offset in the original block at which the instruction(s)
  //     for this successor are located.
  // @param size the length (in bytes) that the instructions for this successor
  //     occupies in the original block.
  Successor(Condition condition,
            Offset bb_target_offset,
            Offset instruction_offset,
            Size instruction_size);

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
            Offset instruction_offset,
            Size instruction_size);
  // @}

  // Accessors.
  // @{
  // The type of branch represented by this successor.
  Condition condition() const { return condition_; }
  const BasicBlockReference& reference() const;
  Offset bb_target_offset() const { return bb_target_offset_; }
  Offset instruction_offset() const { return instruction_offset_; }
  Size instruction_size() const { return instruction_size_; }
  // @}

  // Set the target reference @p ref for this successor. If @p ref refers
  // to a basic block, also update that basic block's referrer set.
  // @pre The @p offset must be BasicBlock::kNoOffset. It is retained in this
  //     interface for compatibility with utility functions.
  bool SetReference(const BasicBlockReference& ref);

  // Return the maximum size needed to synthesize this successor as one
  // or more instructions.
  Size GetMaxSize() const;

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

  // The original address of the branch target. Setting this on construction
  // facilitates resolving the target basic block after the fact.
  Offset bb_target_offset_;

  // A container for the reference made by this successor. There will only
  // ever be one entry here, but we reuse the reference map to allow us to
  // leverage the same utility function for all the other basic-block
  // subgraph elements.
  BasicBlockReferenceMap references_;

  // The byte range in the original block where this instruction originates.
  // @{
  Offset instruction_offset_;
  Size instruction_size_;
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
  // TODO(rogerm): Get rid of BasicBlockType and reuse LabelAttributes
  //     instead? There isn't quite parity there, as padding isn't labeled.
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
  typedef core::AddressRange<core::AbsoluteAddress, Size> SourceRange;

  // The collection of references this basic block makes to other basic
  // blocks, keyed by the references offset relative to the start of this
  // basic block.
  typedef std::map<Offset, BasicBlockReference> BasicBlockReferenceMap;

  // The set of the basic blocks that have a reference to this basic block.
  // This is keyed on basic block and source offset (not destination offset),
  // to allow us to easily locate and remove the back-references on change or
  // deletion.
  typedef std::set<BasicBlockReferrer, BasicBlockReferrer::CompareAsLess>
      BasicBlockReferrerSet;

  // This offset is used to denote that an instruction, successor, or
  // basic block has been synthesized and has no corresponding image in
  // the original block.
  static const Offset kNoOffset;

  // Initialize a basic block.
  // @param id A unique identifier for this basic block.
  // @param name A textual identifier for this basic block.
  // @param type The disposition (code, data, padding) of this basic block.
  // @param offset The offset (in the original block) where this basic block
  //     originated. Set to kNoOffset to indicate that this is a
  //     programmatically generated basic block.
  // @param size The number of bytes this basic block occupied in the original
  //     block. Set to 0 if this is a programmatically generated basic block.
  // @param data The underlying data representing the basic block.
  BasicBlock(BlockId id,
             const base::StringPiece& name,
             BasicBlockType type,
             Offset offset,
             Size size,
             const uint8* data);

  // Return a textual label for a basic block type.
  static const char* BasicBlockTypeToString(BasicBlockType type);

  // Accessors.
  // @{
  BlockId id() const { return id_; }
  BasicBlockType type() const { return type_; }
  const std::string& name() const { return name_; }
  Offset offset() const { return offset_; }
  Size size() const { return size_; }
  const uint8* data() const { return data_; }
  const Instructions& instructions() const { return instructions_; }
  Instructions& instructions() { return instructions_; }
  const Successors& successors() const { return successors_; }
  Successors& successors() { return successors_; }
  const BasicBlockReferenceMap& references() const { return references_; }
  BasicBlockReferenceMap& references() { return references_; }
  const BasicBlockReferrerSet& referrers() const { return referrers_; }
  BasicBlockReferrerSet& referrers() { return referrers_; }
  // @}

  // Returns true if this basic block represents a valid block (i.e., it
  // is a BASIC_DATA_BLOCK the contains data XOR a BASIC_CODE_BLOCK that
  // contains instructions and/or successors.
  bool IsValid() const;

  // Return the maximum number of bytes this basic block can require (not
  // including any trailing padding).
  size_t GetMaxSize() const;

  // Add a reference @p ref to this basic block at @p offset. If the reference
  // is to a basic block, also update that basic blocks referrer set.
  // @pre This should be a basic data block; otherwise the references should
  //     be set on a code basic block's instructions and successors.
  bool SetReference(Offset offset, const BasicBlockReference& ref);

 protected:
  // The ID for this basic block.
  BlockId id_;

  // The name of this basic block.
  std::string name_;

  // The type of this basic block.
  BasicBlockType type_;

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
