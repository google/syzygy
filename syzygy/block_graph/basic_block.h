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
// Provides the Basic-Block Graph representation and APIs.

#ifndef SYZYGY_BLOCK_GRAPH_BASIC_BLOCK_H_
#define SYZYGY_BLOCK_GRAPH_BASIC_BLOCK_H_

#include "syzygy/block_graph/block_graph.h"

#include "distorm.h"  // NOLINT

namespace block_graph {

class Instruction;
class BasicBlock;

// Represents a reference from one basic-block to another basic-block or to
// another code- or data-block altogether.
class BasicBlockReference {
 public:
  typedef BlockGraph::BlockType BlockType;
  typedef BlockGraph::ReferenceType ReferenceType;
  typedef BlockGraph::Block Block;
  typedef BlockGraph::Offset Offset;
  typedef BlockGraph::Size Size;

  // Default constructor; needed for storage in stl containers.
  BasicBlockReference();

  // Create a reference to a macro-block.
  //
  // @param type type of reference.
  // @param size size of reference.
  // @param macro_block the referenced macro block.
  // @param offset offset of reference into macro_block.
  BasicBlockReference(ReferenceType type,
                      Size size,
                      Block* macro_block,
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

  // Retrieves the block type.
  BlockType block_type() const { return block_type_; }

  // Retrieves the type of block (macro or basic) that it referenced.
  ReferenceType reference_type() const { return reference_type_; }

  // Retrieves the size of the reference.
  Size size() const { return size_; }

  // Retrieves the referenced macro block. This should only be called on
  // a referenced to a macro block.
  Block* macro_block() const {
    DCHECK(RefersToMacroBlock());
    return referenced_.macro_block;
  }

  // Retrieves the referenced basic-block. This should only be called on
  // a referenced to a macro block.
  BasicBlock* basic_block() const {
    DCHECK(RefersToBasicBlock());
    return referenced_.basic_block;
  }

  // Retrieves the offset into the referenced macro- or basic-block.
  Offset offset() const { return offset_; }

  // @}

  // Compare this BasicBlockReferences with another for equality.
  bool operator==(const BasicBlockReference& other) const {
    return (block_type_ == other.block_type_ &&
            reference_type_ == other.reference_type_ &&
            size_ == other.size_ &&
            referenced_.basic_block == other.referenced_.basic_block &&
            offset_ == other.offset_);
  }

  // Test if this reference has been initialized to refer to something.
  bool IsValid() const {
    return size_ != 0 && referenced_.basic_block != NULL;
  }

  // Test if this reference to to a BasicBlock.
  bool RefersToBasicBlock() const {
    return IsValid() && (block_type_ == BlockGraph::BASIC_CODE_BLOCK ||
                         block_type_ == BlockGraph::BASIC_DATA_BLOCK);
  }

  // Test if this reference to to a Block.
  bool RefersToMacroBlock() const {
    return IsValid() && (block_type_ == BlockGraph::CODE_BLOCK ||
                         block_type_ == BlockGraph::DATA_BLOCK);
  }

 protected:
  // The type of the referred block.
  BlockType block_type_;

  // Type of this reference.
  ReferenceType reference_type_;

  // Size of this reference.
  // Absolute references are always pointer wide, but PC-relative
  // references can be 1, 2 or 4 bytes wide, which affects their range.
  Size size_;

  // The block or basic-block that is referenced.
  union {
    Block* macro_block;
    BasicBlock* basic_block;
  } referenced_;

  // Offset into the referenced block or basic-block.
  Offset offset_;
};

// Represents an instruction in a basic-block.
class Instruction {
 public:
  typedef BlockGraph::Size Size;
  typedef BlockGraph::Offset Offset;
  typedef core::AddressRange<core::AbsoluteAddress, Size> SourceRange;
  typedef _DInst Representation;

  Instruction(const Representation& value, const SourceRange& source_range);

  // Accessors.
  // @{
  const BasicBlockReference& reference() const { return reference_; }
  BasicBlockReference& reference() { return reference_; }
  const SourceRange& source_range() const { return source_range_; }
  SourceRange& source_range() { return source_range_; }
  const Representation& representation() const { return representation_; }
  Representation& representation() { return representation_; }
  /// @}

  // Helper function to invert a conditional branching opcode.
  static bool InvertConditionalBranchOpcode(uint16* opcode);

 protected:
  // The internal representation of this instruction.
  Representation representation_;

  // Captures the reference (if any) that this instruction makes to another
  // basic block or macro block.
  BasicBlockReference reference_;

  // The byte range in the original image where this instruction originates.
  SourceRange source_range_;
};

class BasicBlock {
 public:
  typedef BlockGraph::BlockId BlockId;
  typedef BlockGraph::BlockType BlockType;
  typedef std::list<Instruction> Instructions;
  typedef BlockGraph::Size Size;
  typedef std::list<Instruction> Successors;
  typedef BlockGraph::Offset Offset;
  typedef std::map<Offset, BasicBlockReference> ReferenceMap;

  BasicBlock(BlockId id,
             BlockType type,
             const uint8* data,
             Size size,
             const char* name);

  // Immutable Accessors.
  // @{
  BlockId id() const { return id_; }
  BlockType type() const { return type_; }
  const char* name() const { return name_.c_str(); }
  const uint8* data() const { return data_; }
  Size size() const { return size_; }
  const Instructions& instructions() const { return instructions_; }
  Instructions& instructions() { return instructions_; }
  const Successors& successors() const { return successors_; }
  Successors& successors() { return successors_; }
  // @}

  // Returns true if this basic block represents a valid block (i.e., it
  // is a BASIC_DATA_BLOCK the contains data XOR a BASIC_CODE_BLOCK that
  // contains instructions and/or successors.
  bool IsValid() const;

  // Validates that the basic block can have it's successors inverted. For
  // this to return true, the basic block must have two successors, the
  // first of which is an invertible conditional branch, and the second
  // an unconditional branch.
  bool CanInvertSuccessors() const;

  // Inverts the control flow of the successors. For example, if the
  // basic block ends with a JNZ instruction to A with a fall through
  // to B, this function will mutate the successors such that the basic
  // block ends with a JZ to B with a fall-through to A.
  //
  // @pre CanInvertSuccessors() return true.
  bool InvertSuccessors();

 protected:
  // The ID for this block.
  BlockId id_;

  // The type of this basic block.
  BlockType type_;

  // The name of this basic block.
  std::string name_;

  // If the block type if BASIC_DATA_BLOCK, a pointer to the data will be
  // stored here.
  const uint8* data_;

  // If the block type if BASIC_DATA_BLOCK, the length of the data will
  // be stored here.
  Size size_;

  // If the block type if BASIC_DATA_BLOCK, the alignment of the data will
  // be stored here.
  Size alignment_;

  // If the block type if BASIC_DATA_BLOCK, the map of references (if any)
  // that this block makes to other blocks. This map is indexed by the offset
  // from the start of the basic block.
  ReferenceMap references_;

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
  Instructions successors_;
};

}  // namespace block_graph

#endif  // SYZYGY_BLOCK_GRAPH_BASIC_BLOCK_H_
