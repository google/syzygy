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

namespace block_graph {

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

}  // namespace block_graph
