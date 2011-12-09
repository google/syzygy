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
// Implements the Basic-Block Graph representation and APIs.

#include "syzygy/block_graph/basic_block.h"

#include "mnemonics.h"  // NOLINT

namespace block_graph {

namespace {

bool IsUnconditionalBranch(const Instruction& inst) {
  return META_GET_FC(inst.representation().meta) == FC_UNC_BRANCH;
}

bool IsConditionalBranch(const Instruction& inst) {
  return META_GET_FC(inst.representation().meta) == FC_CND_BRANCH;
}

}  // namespace

BasicBlockReference::BasicBlockReference()
    : block_type_(BlockGraph::BASIC_CODE_BLOCK),
      reference_type_(BlockGraph::RELATIVE_REF),
      size_(0),
      offset_(0) {
  referenced_.basic_block = NULL;
}

BasicBlockReference::BasicBlockReference(ReferenceType type,
                                         Size size,
                                         Block* macro_block,
                                         Offset offset)
    : reference_type_(type),
      size_(size),
      offset_(offset) {
  DCHECK(macro_block != NULL);
  block_type_ = macro_block->type();
  referenced_.macro_block = macro_block;
}

BasicBlockReference::BasicBlockReference(ReferenceType type,
                                         Size size,
                                         BasicBlock* basic_block,
                                         Offset offset)
    : reference_type_(type),
      size_(size),
      offset_(offset) {
  DCHECK(basic_block != NULL);
  block_type_ = basic_block->type();
  referenced_.basic_block = basic_block;
}

BasicBlockReference::BasicBlockReference(const BasicBlockReference& other)
    : block_type_(other.block_type_),
      reference_type_(other.reference_type_),
      size_(other.size_),
      referenced_(other.referenced_),
      offset_(other.offset_) {
}

Instruction::Instruction(const Instruction::Representation& value,
                         const Instruction::SourceRange& source_range)
    : representation_(value),
      source_range_(source_range) {
}

BasicBlock::BasicBlock(BasicBlock::BlockId id,
                       BasicBlock::BlockType type,
                       const uint8* data,
                       BasicBlock::Size size,
                       const char* name)
    : id_(id), type_(type), data_(data), size_(size), name_(name) {
  DCHECK(data != NULL);
  DCHECK(size > 0);
}

bool BasicBlock::IsValid() const {
  if (type() == BlockGraph::BASIC_DATA_BLOCK)
    return true;

  if (type() != BlockGraph::BASIC_CODE_BLOCK)
    return false;

#ifndef NDEBUG
  Instructions::const_iterator it = instructions().begin();
  for (; it != instructions().end(); ++it) {
    if (IsConditionalBranch(*it) || IsUnconditionalBranch(*it))
      return false;
  }
#endif

  switch (successors_.size()) {
    case 0:
      // If the basic code block has no successors, we expect that it would
      // have instructions; otherwise, it doesn't need to exist. We would
      // also expect that it ends in control-flow change that we can't
      // necessarily trace statically (ie., RET or computed jump).
      // TODO(rogerm): Validate that this is really true?
      return instructions().size() != 0 &&
          (instructions().back().representation().opcode == I_RET ||
           instructions().back().representation().opcode == I_JMP);

    case 1:
      // A basic code block having exactly one successor implies that the
      // successor is unconditional.
      return IsUnconditionalBranch(successors().front());

    case 2:
      // A basic code block having exactly two successors implies that the
      // successor first successor is conditional and the second is is
      // unconditional.
      return IsConditionalBranch(successors().front()) &&
          IsUnconditionalBranch(successors().back());

    default:
      // Any other number of successors implies that the data is borked.
      NOTREACHED();
      return false;
  }
}

}  // namespace block_graph
