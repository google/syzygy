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

#include "syzygy/block_graph/block_util.h"

#include <algorithm>
#include <vector>

#include "mnemonics.h" // NOLINT

namespace block_graph {

bool CodeBlockAttributesAreBasicBlockSafe(
    const block_graph::BlockGraph::Block* block) {
  DCHECK(block != NULL);
  DCHECK_EQ(BlockGraph::CODE_BLOCK, block->type());

  // If the block was built by our toolchain it's inherently safe. This
  // attribute is used to whitelist a block.
  if (block->attributes() & BlockGraph::BUILT_BY_SYZYGY)
    return true;

  // Any of the following attributes make it unsafe to basic-block
  // decompose the code block.
  static const BlockGraph::BlockAttributes kInvalidAttributes =
      BlockGraph::GAP_BLOCK |
      BlockGraph::PADDING_BLOCK |
      // TODO(chrisha): Make this configurable.
      BlockGraph::HAS_INLINE_ASSEMBLY |
      BlockGraph::BUILT_BY_UNSUPPORTED_COMPILER |
      BlockGraph::ERRORED_DISASSEMBLY |
      BlockGraph::HAS_EXCEPTION_HANDLING |
      // TODO(chrisha): Remove this!
      BlockGraph::DISASSEMBLED_PAST_END;
  if ((block->attributes() & kInvalidAttributes) != 0)
    return false;

  return true;
}

bool GetBasicBlockSourceRange(const BasicCodeBlock& bb,
                              BlockGraph::Block::SourceRange* source_range) {
  DCHECK(source_range != NULL);

  typedef BlockGraph::Block::SourceRange SourceRange;
  std::vector<SourceRange> ranges;

  // Collect all the instruction and successor source ranges.
  BasicBlock::Instructions::const_iterator inst_it(bb.instructions().begin());
  for (; inst_it != bb.instructions().end(); ++inst_it) {
    const SourceRange& range = inst_it->source_range();
    if (range.size() > 0)
      ranges.push_back(range);
  }
  BasicBlock::Successors::const_iterator succ_it(bb.successors().begin());
  for (; succ_it != bb.successors().end(); ++succ_it) {
    const SourceRange& range = succ_it->source_range();
    if (range.size() > 0)
      ranges.push_back(range);
  }

  if (ranges.empty())
    return false;

  // Sort the ranges.
  std::sort(ranges.begin(), ranges.end());

  // Test that they're all contiguous, while computing their total length.
  SourceRange::Size size = ranges[0].size();
  for (size_t i = 0; i < ranges.size() - 1; ++i) {
    size += ranges[i + 1].size();
    if (ranges[i].start() + ranges[i].size() != ranges[i + 1].start())
      return false;
  }
  *source_range = SourceRange(ranges[0].start(), size);

  return true;
}

bool IsUnsafeReference(const BlockGraph::Block* referrer,
                       const BlockGraph::Reference& ref) {
  // Skip references with a non-zero offset if we're
  // not instrumenting unsafe references.
  if (ref.offset() != 0)
    return true;

  BlockGraph::BlockAttributes kUnsafeAttribs =
      BlockGraph::HAS_INLINE_ASSEMBLY |
      BlockGraph::BUILT_BY_UNSUPPORTED_COMPILER;

  bool unsafe_referrer = false;
  if (referrer->type() == BlockGraph::CODE_BLOCK &&
      (referrer->attributes() & kUnsafeAttribs) != 0) {
    unsafe_referrer = true;
  }

  DCHECK_EQ(BlockGraph::CODE_BLOCK, ref.referenced()->type());
  bool unsafe_block = (ref.referenced()->attributes() & kUnsafeAttribs) != 0;

  // If both the referrer and the referenced blocks are unsafe, we can't
  // safely assume that this reference represents a call semantics,
  // e.g. where a return address is at the top of stack at entry.
  // Ideally we'd decide this on the basis of a full stack analysis, but
  // beggers can't be choosers, plus for hand-coded assembly that's
  // the halting problem :).
  // For instrumentation that uses return address swizzling, instrumenting
  // an unsafe reference leads to crashes, so better to back off and get
  // slightly less coverage.
  return unsafe_referrer && unsafe_block;
}

bool HasUnexpectedStackFrameManipulation(
    block_graph::BasicBlockSubGraph* subgraph) {
  DCHECK(subgraph != NULL);

  BasicBlockSubGraph::BBCollection::iterator it =
      subgraph->basic_blocks().begin();

  // Process each basic block to find an invalid stack manipulation.
  for (; it != subgraph->basic_blocks().end(); ++it) {
    BasicCodeBlock* bb = BasicCodeBlock::Cast(*it);
    if (bb == NULL)
      continue;

    // Process each instruction.
    BasicBlock::Instructions::iterator iter_inst = bb->instructions().begin();
    for (; iter_inst != bb->instructions().end(); ++iter_inst) {
      const _DInst& repr = iter_inst->representation();

      // Consider only instructions whose first operand is EBP (read/write).
      if (repr.ops[0].type == O_REG && repr.ops[0].index == R_EBP) {
        // PUSH/POP EBP is valid.
        if (repr.opcode == I_POP || repr.opcode == I_PUSH)
          continue;

        // MOV EBP, ESP is valid.
        if (repr.opcode == I_MOV &&
            repr.ops[1].type == O_REG && repr.ops[1].index == R_ESP)
          continue;

        // We found a non conventional write to register EBP (stack pointer).
        return true;
      }
    }
  }

  // There is no unconventional/unexpected stack frame manipulation.
  return false;
}

bool GetJumpTableSize(const BlockGraph::Block* block,
    BlockGraph::Block::LabelMap::const_iterator jump_table_label,
    size_t* table_size) {
  DCHECK(block != NULL);
  DCHECK(table_size != NULL);
  DCHECK(block->HasLabel(jump_table_label->first) &&
      block->labels().at(jump_table_label->first) == jump_table_label->second);

  // Ensure that this label has the jump table attribute.
  if (!jump_table_label->second.has_attributes(BlockGraph::JUMP_TABLE_LABEL)) {
    LOG(ERROR) << "This label doesn't have the jump table attribute.";
    return false;
  }

  BlockGraph::Offset beginning_offset = jump_table_label->first;
  BlockGraph::Offset end_offset = beginning_offset;

  // The maximum end offset for this jump table is either the offset of the next
  // label or the end of this block.
  BlockGraph::Offset max_end_offset = 0;
  BlockGraph::Block::LabelMap::const_iterator next_label = ++(jump_table_label);
  if (next_label != block->labels().end())
    max_end_offset = next_label->first;
  else
    max_end_offset = block->size();

  DCHECK_NE(0, max_end_offset);

  BlockGraph::Block::ReferenceMap::const_iterator iter_ref =
      block->references().find(beginning_offset);
  DCHECK(iter_ref != block->references().end());
  DCHECK(iter_ref->first == beginning_offset);
  DCHECK(iter_ref->second.type() == BlockGraph::ABSOLUTE_REF ||
         iter_ref->second.type() == BlockGraph::RELATIVE_REF);
  DCHECK_EQ(BlockGraph::Reference::kMaximumSize, iter_ref->second.size());

  BlockGraph::Size reference_size = iter_ref->second.size();

  // Iterates over the references to calculate the size of this jump table, we
  // stop once we reach the maximum end offset or as soon as we find a reference
  // that is not contiguous to the previous one.
  while (end_offset < max_end_offset) {
    end_offset += reference_size;
    ++iter_ref;
    if (iter_ref == block->references().end() || iter_ref->first != end_offset)
      break;
    DCHECK_EQ(end_offset, iter_ref->first);
    DCHECK(iter_ref->second.type() == BlockGraph::ABSOLUTE_REF ||
           iter_ref->second.type() == BlockGraph::RELATIVE_REF);
    DCHECK_EQ(BlockGraph::Reference::kMaximumSize, iter_ref->second.size());
  }

  *table_size = (end_offset - beginning_offset) /
      BlockGraph::Reference::kMaximumSize;

  return true;
}

}  // namespace block_graph
