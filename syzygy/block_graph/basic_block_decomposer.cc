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
// Implementation of basic block decomposer.

#include "syzygy/block_graph/basic_block_decomposer.h"

#include <algorithm>
#include <vector>

#include "base/logging.h"
#include "base/strings/stringprintf.h"
#include "syzygy/block_graph/basic_block.h"
#include "syzygy/block_graph/basic_block_subgraph.h"
#include "syzygy/block_graph/block_graph.h"
#include "syzygy/block_graph/block_util.h"

#include "mnemonics.h"  // NOLINT

namespace block_graph {

namespace {

using block_graph::BasicBlock;
using block_graph::BasicBlockReference;
using block_graph::BasicBlockReferrer;
using block_graph::BasicBlockSubGraph;
using block_graph::BlockGraph;
using block_graph::Instruction;
using block_graph::Successor;
using core::Disassembler;

typedef BlockGraph::Block Block;
typedef BlockGraph::Offset Offset;
typedef BlockGraph::Size Size;
typedef core::AddressSpace<Offset, size_t, BasicBlock*> BBAddressSpace;
typedef BBAddressSpace::Range Range;
typedef BBAddressSpace::RangeMap RangeMap;
typedef BBAddressSpace::RangeMapConstIter RangeMapConstIter;
typedef BBAddressSpace::RangeMapIter RangeMapIter;

const size_t kPointerSize = BlockGraph::Reference::kMaximumSize;

// We use a (somewhat) arbitrary value as the disassembly address for a block
// so we can tell the difference between a reference to the beginning of the
// block (offset=0) and a null address.
const size_t kDisassemblyAddress = 65536;

// Look up the reference made from an instruction's byte range within the
// given block. The reference should start AFTER the instruction starts
// and there should be exactly 1 reference in the byte range.
// Returns true if the reference was found, false otherwise.
bool GetReferenceOfInstructionAt(const Block* block,
                                 Offset instr_offset,
                                 Size instr_size,
                                 BlockGraph::Reference* ref) {
  DCHECK(block != NULL);
  DCHECK_LE(0, instr_offset);
  DCHECK_LT(0U, instr_size);
  DCHECK(ref != NULL);

  // Find the first reference following the instruction offset.
  Block::ReferenceMap::const_iterator ref_iter =
      block->references().upper_bound(instr_offset);

  // If no reference is found then we're done.
  if (ref_iter == block->references().end())
    return false;

  // If the reference occurs outside the instruction then we're done.
  Offset next_instr_offset = instr_offset + instr_size;
  if (ref_iter->first >= next_instr_offset)
    return false;

  // Otherwise, the reference should fit into the instruction.
  CHECK_LE(static_cast<size_t>(next_instr_offset),
           ref_iter->first + ref_iter->second.size());

  // And it should be the only reference in the instruction.
  if (ref_iter != block->references().begin()) {
    Block::ReferenceMap::const_iterator prev_iter = ref_iter;
    --prev_iter;
    CHECK_GE(static_cast<size_t>(instr_offset),
             prev_iter->first + prev_iter->second.size());
  }
  Block::ReferenceMap::const_iterator next_iter = ref_iter;
  ++next_iter;
  CHECK(next_iter == block->references().end() ||
        next_iter->first >= next_instr_offset);

  *ref = ref_iter->second;
  return true;
}

// Transfer instructions from original to tail, starting with the instruction
// starting at offset.
bool SplitInstructionListAt(Offset offset,
                            BasicBlock::Instructions* original,
                            BasicBlock::Instructions* tail) {
  DCHECK(original != NULL);
  DCHECK(tail != NULL && tail->empty());

  BasicBlock::Instructions::iterator it(original->begin());
  while (offset > 0 && it != original->end()) {
    offset -= it->size();
    ++it;
  }

  // Did we terminate at an instruction boundary?
  if (offset != 0)
    return false;

  tail->splice(tail->end(), *original, it, original->end());
  return true;
}

}  // namespace

BasicBlockDecomposer::BasicBlockDecomposer(const BlockGraph::Block* block,
                                           BasicBlockSubGraph* subgraph)
    : block_(block),
      subgraph_(subgraph),
      current_block_start_(0),
      check_decomposition_results_(true) {
  // TODO(rogerm): Once we're certain this is stable for all input binaries
  //     turn on check_decomposition_results_ by default only ifndef NDEBUG.
  DCHECK(block != NULL);
  DCHECK(block->type() == BlockGraph::CODE_BLOCK);

  // If no subgraph was provided then use a scratch one.
  if (subgraph == NULL) {
    scratch_subgraph_.reset(new BasicBlockSubGraph());
    subgraph_ = scratch_subgraph_.get();
  }
}

bool BasicBlockDecomposer::Decompose() {
  DCHECK(subgraph_->basic_blocks().empty());
  DCHECK(subgraph_->block_descriptions().empty());
  DCHECK(original_address_space_.empty());
  subgraph_->set_original_block(block_);

  bool disassembled = Disassemble();
  CHECK(disassembled);

  // Don't bother with the following bookkeeping work if the results aren't
  // being looked at.
  if (scratch_subgraph_.get() != NULL)
    return true;

  typedef BasicBlockSubGraph::BlockDescription BlockDescription;
  subgraph_->block_descriptions().push_back(BlockDescription());
  BlockDescription& desc = subgraph_->block_descriptions().back();
  desc.name = block_->name();
  desc.compiland_name = block_->compiland_name();
  desc.type = block_->type();
  desc.alignment = block_->alignment();
  desc.attributes = block_->attributes();
  desc.section = block_->section();

  // Add the basic blocks to the block descriptor.
  Offset offset = 0;
  RangeMapConstIter it = original_address_space_.begin();
  for (; it != original_address_space_.end(); ++it) {
    DCHECK_EQ(it->first.start(), offset);
    desc.basic_block_order.push_back(it->second);

    // Any data basic blocks (jump and case tables) with 0 mod 4 alignment
    // are marked so that the alignment is preserved by the block builder.
    if (desc.alignment >= kPointerSize &&
        it->second->type() == BasicBlock::BASIC_DATA_BLOCK &&
        (offset % kPointerSize) == 0) {
      it->second->set_alignment(kPointerSize);
    }

    offset += it->first.size();
  }

  return true;
}

bool BasicBlockDecomposer::DecodeInstruction(Offset offset,
                                             Offset code_end_offset,
                                             Instruction* instruction) const {
  // The entire offset range should fall within the extent of block_ and the
  // output instruction pointer must not be NULL.
  DCHECK_LE(0, offset);
  DCHECK_LT(offset, code_end_offset);
  DCHECK_LE(static_cast<Size>(code_end_offset), block_->size());
  DCHECK(instruction != NULL);

  // Decode the instruction.
  const uint8* buffer = block_->data() + offset;
  size_t max_length = code_end_offset - offset;
  if (!Instruction::FromBuffer(buffer, max_length, instruction)) {
    VLOG(1) << "Failed to decode instruction at offset " << offset
            << " of block '" << block_->name() << "'.";

    // Dump the bytes to aid in debugging.
    std::string dump;
    size_t dump_length = std::min(max_length, Instruction::kMaxSize);
    for (size_t i = 0; i < dump_length; ++i)
      base::StringAppendF(&dump, " %02X", buffer[i]);
    VLOG(2) << ".text =" << dump << (dump_length < max_length ? "..." : ".");

    // Return false to indicate an error.
    return false;
  }

  VLOG(3) << "Disassembled " << instruction->GetName()
          << " instruction (" << instruction->size()
          << " bytes) at offset " << offset << ".";

  // Track the source range.
  instruction->set_source_range(
      GetSourceRange(offset, instruction->size()));

  // If the block is labeled, preserve the label.
  BlockGraph::Label label;
  if (block_->GetLabel(offset, &label)) {
    // If this instruction has run into known data, then we have a problem!
    CHECK(!label.has_attributes(BlockGraph::DATA_LABEL))
        << "Disassembling into data at offset " << offset << " of "
        << block_->name() << ".";
    instruction->set_label(label);
  }

  return true;
}

BasicBlockDecomposer::SourceRange BasicBlockDecomposer::GetSourceRange(
    Offset offset, Size size) const {
  // Find the source range for the original bytes. We may not have a data
  // range for bytes that were synthesized in other transformations. As a
  // rule, however, there should be a covered data range for each instruction,
  // successor, that relates back to the original image.
  const Block::SourceRanges::RangePair* range_pair =
      block_->source_ranges().FindRangePair(offset, size);
  // Return an empty range if we found nothing.
  if (range_pair == NULL)
    return SourceRange();

  const Block::DataRange& data_range = range_pair->first;
  const Block::SourceRange& source_range = range_pair->second;
  if (offset == data_range.start() && size == data_range.size()) {
    // We match a data range exactly, so let's use the entire
    // matching source range.
    return source_range;
  }

  // The data range doesn't match exactly, so let's slice the corresponding
  // source range. The assumption here is that no transformation will ever
  // slice the data or source ranges for an instruction, so we should always
  // have a covering data and source ranges.
  DCHECK_GE(offset, data_range.start());
  DCHECK_LE(offset + size, data_range.start() + data_range.size());

  Offset start_offs = offset - data_range.start();
  return SourceRange(source_range.start() + start_offs, size);
}

bool BasicBlockDecomposer::FindBasicBlock(Offset offset,
                                          BasicBlock** basic_block,
                                          Range* range) const {
  DCHECK_LE(0, offset);
  DCHECK(basic_block != NULL);
  DCHECK(range != NULL);
  DCHECK(subgraph_->original_block() != NULL);
  DCHECK_GE(subgraph_->original_block()->size(), static_cast<size_t>(offset));

  RangeMapConstIter bb_iter =
      original_address_space_.FindFirstIntersection(Range(offset, 1));

  if (bb_iter == original_address_space_.end())
    return false;

  *basic_block = bb_iter->second;
  *range = bb_iter->first;
  return true;
}

BasicBlock* BasicBlockDecomposer::GetBasicBlockAt(Offset offset) const {
  DCHECK_LE(0, offset);
  DCHECK(subgraph_->original_block() != NULL);
  DCHECK_GE(subgraph_->original_block()->size(), static_cast<size_t>(offset));

  BasicBlock* bb = NULL;
  Range range;
  CHECK(FindBasicBlock(offset, &bb, &range));
  DCHECK(bb != NULL);
  DCHECK_EQ(offset, range.start());
  return bb;
}

void BasicBlockDecomposer::InitJumpTargets(Offset code_end_offset) {
  DCHECK_LE(static_cast<Size>(code_end_offset), block_->size());

  // Make sure the jump target set is empty.
  jump_targets_.clear();

  // For each referrer, check if it references code. If so, it's a jump target.
  BlockGraph::Block::ReferrerSet::const_iterator ref_iter =
      block_->referrers().begin();
  for (; ref_iter != block_->referrers().end(); ++ref_iter) {
    BlockGraph::Reference ref;
    bool found = ref_iter->first->GetReference(ref_iter->second, &ref);
    DCHECK(found);
    DCHECK_EQ(block_, ref.referenced());
    DCHECK_LE(0, ref.base());
    DCHECK_LE(static_cast<size_t>(ref.base()), block_->size());

    // Ignore references to the data portion of the block.
    if (ref.base() >= code_end_offset)
      continue;

    jump_targets_.insert(ref.base());
  }
}

bool BasicBlockDecomposer::HandleInstruction(const Instruction& instruction,
                                             Offset offset) {
  // We do not handle the SYS* instructions. These should ONLY occur inside
  // the OS system libraries, mediated by an OS system call. We expect that
  // they NEVER occur in application code.
  if (instruction.IsSystemCall()) {
    VLOG(1) << "Encountered an unexpected " << instruction.GetName()
            << " instruction at offset " << offset << " of block '"
            << block_->name() << "'.";
    return false;
  }

  // Calculate the offset of the next instruction. We'll need this if this
  // instruction marks the end of a basic block.
  Offset next_instruction_offset = offset + instruction.size();

  // If the instruction is not a branch then it needs to be appended to the
  // current basic block... which we close if the instruction is a return or
  // a call to a non-returning function.
  if (!instruction.IsBranch()) {
    current_instructions_.push_back(instruction);
    if (instruction.IsReturn()) {
      EndCurrentBasicBlock(next_instruction_offset);
    } else if (instruction.IsCall()) {
      BlockGraph::Reference ref;
      bool found = GetReferenceOfInstructionAt(
          block_, offset, instruction.size(), &ref);
      if (found && Instruction::IsCallToNonReturningFunction(
              instruction.representation(), ref.referenced(), ref.offset())) {
        EndCurrentBasicBlock(next_instruction_offset);
      }
    }
    return true;
  }

  // If the branch is not PC-Relative then it also needs to be appended to
  // the current basic block... which we then close.
  if (!instruction.HasPcRelativeOperand(0)) {
    current_instructions_.push_back(instruction);
    EndCurrentBasicBlock(next_instruction_offset);
    return true;
  }

  // Otherwise, we're dealing with a branch whose destination is explicit.
  DCHECK(instruction.IsBranch());
  DCHECK(instruction.HasPcRelativeOperand(0));

  // Make sure we understand the branching condition. If we don't, then
  // there's an instruction we have failed to consider.
  Successor::Condition condition = Successor::OpCodeToCondition(
      instruction.opcode());
  CHECK_NE(Successor::kInvalidCondition, condition)
      << "Received unknown condition for branch instruction: "
      << instruction.GetName() << ".";

  // If this is a conditional branch add the inverse conditional successor
  // to represent the fall-through. If we don't understand the inverse, then
  // there's an instruction we have failed to consider.
  if (instruction.IsConditionalBranch()) {
    Successor::Condition inverse_condition =
        Successor::InvertCondition(condition);
    CHECK_NE(Successor::kInvalidCondition, inverse_condition)
        << "Non-invertible condition seen for branch instruction: "
        << instruction.GetName() << ".";

    // Create an (unresolved) successor pointing to the next instruction.
    BasicBlockReference ref(BlockGraph::PC_RELATIVE_REF,
                            1,  // The size is irrelevant in successors.
                            const_cast<Block*>(block_),
                            next_instruction_offset,
                            next_instruction_offset);
    current_successors_.push_front(Successor(inverse_condition, ref, 0));
    jump_targets_.insert(next_instruction_offset);
  }

  // Attempt to figure out where the branch is going by finding a
  // reference inside the instruction's byte range.
  BlockGraph::Reference ref;
  bool found = GetReferenceOfInstructionAt(
      block_, offset, instruction.size(), &ref);

  // If a reference was found, prefer its destination information to the
  // information conveyed by the bytes in the instruction. This should
  // handle all inter-block jumps (thunks, tail-call elimination, etc).
  // Otherwise, create a reference into the current block.
  if (found) {
    // This is an explicit branching instruction so we expect the reference to
    // be direct.
    if (!ref.IsDirect()) {
      VLOG(1) << "Encountered an explicit control flow instruction containing "
              << "an indirect reference.";
      return false;
    }
  } else {
    Offset target_offset =
        next_instruction_offset + instruction.representation().imm.addr;

    // If we don't have a reference (coming from a fixup) for a PC-relative jump
    // then we expect its destination to be in the block. We only see otherwise
    // in assembly generated code where section contributions don't correspond
    // to entire function bodies.
    if (target_offset < 0 ||
        static_cast<Size>(target_offset) >= block_->size()) {
      VLOG(1) << "Unexpected PC-relative target offset is external to block.";
      return false;
    }

    ref = BlockGraph::Reference(BlockGraph::PC_RELATIVE_REF,
                                1,  // Size is irrelevant in successors.
                                const_cast<Block*>(block_),
                                target_offset,
                                target_offset);
  }

  // If the reference points to the current block, track the target offset.
  if (ref.referenced() == block_)
    jump_targets_.insert(ref.offset());

  // Create the successor, preserving the source range and label.
  BasicBlockReference bb_ref(
      ref.type(), ref.size(), ref.referenced(), ref.offset(), ref.base());
  Successor succ(condition, bb_ref, instruction.size());
  succ.set_source_range(instruction.source_range());
  succ.set_label(instruction.label());
  current_successors_.push_front(succ);

  // Having just branched, we need to end the current basic block.
  EndCurrentBasicBlock(next_instruction_offset);
  return true;
}

bool BasicBlockDecomposer::EndCurrentBasicBlock(Offset end_offset) {
  // We have reached the end of the current walk or we handled a conditional
  // branch. Let's mark this as the end of a basic block.
  int basic_block_size = end_offset - current_block_start_;
  DCHECK_LT(0, basic_block_size);
  if (!InsertBasicBlockRange(current_block_start_,
                             basic_block_size,
                             BasicBlock::BASIC_CODE_BLOCK)) {
    return false;
  }

  // Remember the end offset as the start of the next basic block.
  current_block_start_ = end_offset;
  return true;
}

bool BasicBlockDecomposer::GetCodeRangeAndCreateDataBasicBlocks(Offset* end) {
  DCHECK_NE(reinterpret_cast<Offset*>(NULL), end);

  *end = 0;

  // By default, we assume the entire block is code.
  Offset code_end = block_->size();

  // Iterate over all labels, looking for data labels.
  BlockGraph::Block::LabelMap::const_reverse_iterator it =
      block_->labels().rbegin();
  bool saw_non_data_label = false;
  for (; it != block_->labels().rend(); ++it) {
    const BlockGraph::Label& label = it->second;
    if (label.has_attributes(BlockGraph::DATA_LABEL)) {
      // There should never be data labels beyond the end of the block.
      if (it->first >= static_cast<Offset>(block_->size())) {
        VLOG(1) << "Encountered a data label at offset " << it->first
                << "of block \"" << block_->name() << "\" of size "
                << block_->size() << ".";
        return false;
      }

      // If a non-data label was already encountered, and now there's another
      // data label then bail: the block does not respect the 'code first,
      // data second' supported layout requirement.
      if (saw_non_data_label) {
        VLOG(1) << "Block \"" << block_->name() << "\" has an unsupported "
                << "code-data layout.";
        VLOG(1) << "Unexpected data label at offset " << it->first << ".";
        return false;
      }

      // Create a data block and update the end-of-code offset. This should
      // never fail because this is the first time blocks are being created and
      // they are strictly non-overlapping by the iteration logic of this
      // function.
      size_t size = code_end - it->first;
      CHECK(InsertBasicBlockRange(it->first, size,
                                  BasicBlock::BASIC_DATA_BLOCK));
      code_end = it->first;
    } else {
      // We ignore the debug-end label, as it can come after block data.
      if (label.attributes() == BlockGraph::DEBUG_END_LABEL)
        continue;

      // Remember that a non-data label was seen. No further data labels should
      // be encountered.
      saw_non_data_label = true;
    }
  }

  *end = code_end;

  return true;
}

bool BasicBlockDecomposer::ParseInstructions() {
  // Find the beginning and ending offsets of code bytes within the block.
  Offset code_end_offset = 0;
  if (!GetCodeRangeAndCreateDataBasicBlocks(&code_end_offset))
    return false;

  // Initialize jump_targets_ to include un-discoverable targets.
  InitJumpTargets(code_end_offset);

  // Disassemble the instruction stream into rudimentary basic blocks.
  Offset offset = 0;
  current_block_start_ = offset;
  while (offset < code_end_offset) {
    // Decode the next instruction.
    Instruction instruction;
    if (!DecodeInstruction(offset, code_end_offset, &instruction))
      return false;

    // Handle the decoded instruction.
    if (!HandleInstruction(instruction, offset))
      return false;

    // Advance the instruction offset.
    offset += instruction.size();
  }

  // If we get here then we must have successfully consumed the entire code
  // range; otherwise, we should have failed to decode a partial instruction.
  CHECK_EQ(offset, code_end_offset);

  // If the last bb we were working on didn't end with a RET or branch then
  // we need to close it now. We can detect this if the current_block_start_
  // does not match the current (end) offset.
  if (current_block_start_ != code_end_offset)
    EndCurrentBasicBlock(code_end_offset);

  return true;
}

bool BasicBlockDecomposer::Disassemble() {
  // Parse the code bytes into instructions and rudimentary basic blocks.
  if (!ParseInstructions())
    return false;

  // Everything below this point is simply book-keeping that can't fail. These
  // can safely be skipped in a dry-run.
  if (scratch_subgraph_.get() != NULL)
    return true;

  // Split the basic blocks at branch targets.
  SplitCodeBlocksAtBranchTargets();

  // At this point we have basic blocks for all code and data. Now create a
  // basic-block to represent the end of the block. This will potentially carry
  // labels and references beyond the end of the block.
  CHECK(InsertBasicBlockRange(block_->size(), 0, BasicBlock::BASIC_END_BLOCK));

  // By this point, we should have basic blocks for all visited code.
  CheckAllJumpTargetsStartABasicCodeBlock();

  // We should now have contiguous block ranges that cover every byte in the
  // macro block. Verify that this is so.
  CheckHasCompleteBasicBlockCoverage();

  // We should have propagated all of the labels in the original block into
  // the basic-block subgraph.
  CheckAllLabelsArePreserved();

  // Populate the referrers in the basic block data structures by copying
  // them from the original source block.
  CopyExternalReferrers();

  // Populate the references in the basic block data structures by copying
  // them from the original source block. This does not handle the successor
  // references.
  CopyReferences();

  // Wire up the basic-block successors. These are not handled by
  // CopyReferences(), above.
  ResolveSuccessors();

  // All the control flow we have derived should be valid.
  CheckAllControlFlowIsValid();

  // Mark all unreachable code blocks as padding.
  MarkUnreachableCodeAsPadding();

  // ... and we're done.
  return true;
}

void BasicBlockDecomposer::CheckAllJumpTargetsStartABasicCodeBlock() const {
  if (!check_decomposition_results_)
    return;

  JumpTargets::const_iterator offset_iter(jump_targets_.begin());
  for (; offset_iter != jump_targets_.end(); ++offset_iter) {
    // The target basic-block should be a code basic-block.
    BasicBlock* target_bb = GetBasicBlockAt(*offset_iter);
    CHECK(target_bb != NULL);
    CHECK_EQ(BasicBlock::BASIC_CODE_BLOCK, target_bb->type());
  }
}

void BasicBlockDecomposer::CheckHasCompleteBasicBlockCoverage() const {
  if (!check_decomposition_results_)
    return;

  // Walk through the basic-block address space.
  Offset next_start = 0;
  RangeMapConstIter it(original_address_space_.begin());
  for (; it != original_address_space_.end(); ++it) {
    CHECK_EQ(it->first.start(), next_start);
    CHECK_EQ(it->first.start(), it->second->offset());

    size_t size = it->first.size();

    BasicDataBlock* data_block = BasicDataBlock::Cast(it->second);
    if (data_block != NULL) {
      // Data block's size should match the address segment exactly.
      CHECK_EQ(size, data_block->size());
    }

    BasicCodeBlock* code_block = BasicCodeBlock::Cast(it->second);
    if (code_block != NULL) {
      // Code blocks may be short the trailing successor instruction.
      BasicCodeBlock::Successors::const_iterator succ_it(
          code_block->successors().begin());
      Size block_size = code_block->GetInstructionSize();
      for (; succ_it != code_block->successors().end(); ++succ_it)
        block_size += succ_it->instruction_size();

      CHECK_GE(size, block_size);
    }

    BasicEndBlock* end_block = BasicEndBlock::Cast(it->second);
    if (end_block != NULL) {
      CHECK_EQ(0u, end_block->size());
      size = 0;
    }

    // The basic-block must have parsed as one of the fundamental types.
    CHECK(data_block != NULL || code_block != NULL || end_block != NULL);

    next_start += size;
  }

  // At this point, if there were no gaps, next start will be the same as the
  // full size of the block we're decomposing.
  CHECK_EQ(block_->size(), static_cast<size_t>(next_start));
}

void BasicBlockDecomposer::CheckAllControlFlowIsValid() const {
  if (!check_decomposition_results_)
    return;

  // Check that the subgraph is valid. This will make sure that the
  // instructions and successors generally make sense.
  CHECK(subgraph_->IsValid());

  // The only thing left to check is that synthesized flow-through
  // successors refer to the adjacent basic-blocks.
  RangeMapConstIter it(original_address_space_.begin());
  for (; it != original_address_space_.end(); ++it) {
    const BasicCodeBlock* bb = BasicCodeBlock::Cast(it->second);
    if (bb == NULL)
      continue;

    const BasicBlock::Successors& successors = bb->successors();

    // There may be at most 2 successors.
    switch (successors.size()) {
      case 0:
        break;

      case 1:
        // If the successor is synthesized, then flow is from this basic-block
        // to the next adjacent one.
        if (successors.back().instruction_size() == 0) {
          RangeMapConstIter next(it);
          ++next;
          CHECK(next != original_address_space_.end());
          CHECK_EQ(successors.back().reference().basic_block(), next->second);
        }
        break;

      case 2: {
        // Exactly one of the successors should have been synthesized.
        bool front_synthesized = successors.front().instruction_size() == 0;
        bool back_synthesized = successors.back().instruction_size() == 0;
        CHECK_NE(front_synthesized, back_synthesized);

        // The synthesized successor flows from this basic-block to the next
        // adjacent one.
        const Successor& synthesized =
            front_synthesized ? successors.front() : successors.back();
        RangeMapConstIter next(it);
        ++next;
        CHECK(next != original_address_space_.end());
        CHECK_EQ(synthesized.reference().basic_block(), next->second);
        break;
      }

      default:
        NOTREACHED();
    }
  }
}

void BasicBlockDecomposer::CheckAllLabelsArePreserved() const {
  if (!check_decomposition_results_)
    return;

  const Block* original_block = subgraph_->original_block();
  if (original_block == NULL)
    return;

  // Remove any labels that fall *after* the given block. This can happen for
  // scope and debug-end labels when the function has no epilog. It is rare, but
  // has been observed in the wild.
  // TODO(chrisha): Find a way to preserve these. We may need the notion of an
  //     empty basic-block which gets assigned the label, or we may need to
  //     augment BBs/instructions with the ability to have two labels: one tied
  //     to the beginning of the object, and one to the end.
  Block::LabelMap::const_iterator it_past_block_end =
      original_block->labels().lower_bound(original_block->size());

  // Grab a copy of the original labels (except any that are beyond the end of
  // the block data). We will be matching against these to ensure that they are
  // preserved in the BB decomposition.
  const Block::LabelMap original_labels(original_block->labels().begin(),
                                        it_past_block_end);
  if (original_labels.empty())
    return;

  // A map to track which labels (by offset) have been found in the subgraph.
  std::map<Offset, bool> labels_found;

  // Initialize the map of labels found in the subgraph.
  Block::LabelMap::const_iterator label_iter = original_labels.begin();
  for (; label_iter != original_labels.end(); ++label_iter)
    labels_found.insert(std::make_pair(label_iter->first, false));

  // Walk through the subgraph and mark all of the labels found.
  BasicBlockSubGraph::BBCollection::const_iterator bb_iter =
      subgraph_->basic_blocks().begin();
  for (; bb_iter != subgraph_->basic_blocks().end(); ++bb_iter) {
    const BasicDataBlock* data_block = BasicDataBlock::Cast(*bb_iter);
    if (data_block != NULL) {
      // Account for labels attached to basic-blocks.
      if (data_block->has_label()) {
        BlockGraph::Label label;
        CHECK(original_block->GetLabel(data_block->offset(), &label));
        CHECK(data_block->label() == label);
        labels_found[data_block->offset()] = true;
      }
    }

    const BasicCodeBlock* code_block = BasicCodeBlock::Cast(*bb_iter);
    if (code_block != NULL) {
      // Account for labels attached to instructions.
      BasicBlock::Instructions::const_iterator inst_iter =
          code_block->instructions().begin();
      Offset inst_offset = code_block->offset();
      for (; inst_iter != code_block->instructions().end(); ++inst_iter) {
        const Instruction& inst = *inst_iter;
        if (inst.has_label()) {
          BlockGraph::Label label;
          CHECK(original_block->GetLabel(inst_offset, &label));
          CHECK(inst.label() == label);
          labels_found[inst_offset] = true;
        }
        inst_offset += inst.size();
      }

      // Account for labels attached to successors.
      BasicBlock::Successors::const_iterator succ_iter =
          code_block->successors().begin();
      for (; succ_iter != code_block->successors().end(); ++succ_iter) {
        const Successor& succ = *succ_iter;
        if (succ.has_label()) {
          BlockGraph::Label label;
          CHECK_NE(0U, succ.instruction_size());
          CHECK(original_block->GetLabel(inst_offset, &label));
          CHECK(succ.label() == label);
          labels_found[inst_offset] = true;
        }
        inst_offset += succ.instruction_size();
      }
    }
  }

  // We should have the right number of labels_found (check if we added
  // something to the wrong place).
  CHECK_EQ(original_labels.size(), labels_found.size());

  // Make sure all of the items in labels_found have been set to true.
  std::map<Offset, bool>::const_iterator found_iter = labels_found.begin();
  for (; found_iter != labels_found.end(); ++found_iter) {
    CHECK(found_iter->second);
  }
}

bool BasicBlockDecomposer::InsertBasicBlockRange(Offset offset,
                                                 size_t size,
                                                 BasicBlockType type) {
  DCHECK_LE(0, offset);
  DCHECK_LE(offset + size, block_->size());
  DCHECK(type == BasicBlock::BASIC_CODE_BLOCK || current_instructions_.empty());
  DCHECK(type == BasicBlock::BASIC_CODE_BLOCK || current_successors_.empty());

  // Find or create a name for this basic block. Reserve the label, if any,
  // to propagate to the basic block if there are no instructions in the
  // block to carry the label(s).
  BlockGraph::Label label;
  std::string basic_block_name;
  bool have_label = block_->GetLabel(offset, &label);
  if (have_label) {
    basic_block_name = label.ToString();
  } else {
    basic_block_name =
        base::StringPrintf("<%s+%04X-%s>",
                           block_->name().c_str(),
                           offset,
                           BasicBlock::BasicBlockTypeToString(type));
  }

  // Pre-flight address space insertion to make sure there's no
  // pre-existing conflicting range.
  Range byte_range(offset, size);
  if (original_address_space_.FindFirstIntersection(byte_range) !=
          original_address_space_.end()) {
    LOG(ERROR) << "Attempted to insert overlapping basic block.";
    return false;
  }

  if (type == BasicBlock::BASIC_CODE_BLOCK) {
    DCHECK_LT(0u, size);

    // Create the code block.
    BasicCodeBlock* code_block = subgraph_->AddBasicCodeBlock(basic_block_name);
    if (code_block == NULL)
      return false;
    CHECK(original_address_space_.Insert(byte_range, code_block));

    // Populate code basic-block with instructions and successors.
    code_block->set_offset(offset);
    code_block->instructions().swap(current_instructions_);
    code_block->successors().swap(current_successors_);
  } else if (type == BasicBlock::BASIC_DATA_BLOCK) {
    DCHECK_LT(0u, size);

    // Create the data block.
    BasicDataBlock* data_block = subgraph_->AddBasicDataBlock(
        basic_block_name, size, block_->data() + offset);
    if (data_block == NULL)
      return false;
    CHECK(original_address_space_.Insert(byte_range, data_block));

    // Capture the source range (if any) for the data block.
    data_block->set_source_range(GetSourceRange(offset, size));

    // Data basic-blocks carry their labels at the head of the basic blocks.
    // A padding basic-block might also be labeled if the block contains
    // unreachable code (for example, INT3 or NOP instructions following a call
    // to a non-returning function).
    data_block->set_offset(offset);
    if (have_label)
      data_block->set_label(label);
  } else {
    DCHECK_EQ(0u, size);
    DCHECK_EQ(BasicBlock::BASIC_END_BLOCK, type);

    // Create the end block.
    BasicEndBlock* end_block = subgraph_->AddBasicEndBlock();
    if (end_block == NULL)
      return false;

    // We insert the basic end block with a size of 1, as the address space
    // does not support empty blocks. However, the block itself has no length.
    // This is only for internal book-keeping, and does not affect the
    // BasicBlockSubGraph representation.
    CHECK(original_address_space_.Insert(Range(offset, 1), end_block));

    // Set the offset and any labels.
    end_block->set_offset(offset);
    if (have_label)
      end_block->set_label(label);
  }

  return true;
}

void BasicBlockDecomposer::SplitCodeBlocksAtBranchTargets() {
  JumpTargets::const_iterator jump_target_iter(jump_targets_.begin());
  for (; jump_target_iter != jump_targets_.end(); ++jump_target_iter) {
    // Resolve the target basic-block.
    Offset target_offset = *jump_target_iter;
    BasicBlock* target_bb = NULL;
    Range target_bb_range;
    CHECK(FindBasicBlock(target_offset, &target_bb, &target_bb_range));

    // If we're jumping to the start of a basic block, there isn't any work
    // to do.
    if (target_offset == target_bb_range.start())
      continue;

    // The target must be a code block.
    BasicCodeBlock* target_code_block = BasicCodeBlock::Cast(target_bb);
    CHECK(target_code_block != NULL);

    // Otherwise, we have found a basic-block that we need to split.
    // Let's contract the range the original occupies in the basic-block
    // address space, then add a second block at the target offset.
    size_t left_split_size = target_offset - target_bb_range.start();
    bool removed = original_address_space_.Remove(target_bb_range);
    DCHECK(removed);

    Range left_split_range(target_bb_range.start(), left_split_size);
    bool inserted =
        original_address_space_.Insert(left_split_range, target_code_block);
    DCHECK(inserted);

    // Now we split up containing_range into two new ranges and replace
    // containing_range with the two new entries.

    // Slice the trailing half of the instructions and the successors
    // off the block.
    DCHECK(current_instructions_.empty());
    DCHECK(current_successors_.empty());
    bool split = SplitInstructionListAt(left_split_size,
                                        &target_code_block->instructions(),
                                        &current_instructions_);
    DCHECK(split);
    target_code_block->successors().swap(current_successors_);

    // Set-up the flow-through successor for the first "half".
    BasicBlockReference ref(BlockGraph::PC_RELATIVE_REF,
                            1,  // Size is immaterial in successors.
                            const_cast<Block*>(block_),
                            target_offset,
                            target_offset);
    target_code_block->successors().push_back(
        Successor(Successor::kConditionTrue, ref, 0));

    // This shouldn't fail because the range used to exist, and we just resized
    // it.
    CHECK(InsertBasicBlockRange(target_offset,
                                target_bb_range.size() - left_split_size,
                                target_code_block->type()));
  }
}

void BasicBlockDecomposer::CopyExternalReferrers() {
  const BlockGraph::Block::ReferrerSet& referrers = block_->referrers();
  BlockGraph::Block::ReferrerSet::const_iterator iter = referrers.begin();
  for (; iter != referrers.end(); ++iter) {
    // Find the reference this referrer record describes.
    const BlockGraph::Block* referrer = iter->first;
    DCHECK(referrer != NULL);

    // We only care about external referrers.
    if (referrer == block_)
      continue;

    // This is an external referrer. Find the reference in the referring block.
    Offset source_offset = iter->second;
    BlockGraph::Reference reference;
    bool found = referrer->GetReference(source_offset, &reference);
    DCHECK(found);

    // Find the basic block the reference refers to.
    BasicBlock* target_bb = GetBasicBlockAt(reference.base());
    DCHECK(target_bb != NULL);

    // Insert the referrer into the target bb's referrer set. Note that there
    // is no corresponding reference update to the referring block. The
    // target bb will track these so a BlockBuilder can properly update
    // the referrers when merging a subgraph back into the block-graph.
    bool inserted = target_bb->referrers().insert(
        BasicBlockReferrer(referrer, source_offset)).second;
    DCHECK(inserted);
  }
}

void BasicBlockDecomposer::CopyReferences(
    Offset item_offset, Size item_size, BasicBlockReferenceMap* refs) {
  DCHECK_LE(0, item_offset);
  DCHECK_LT(0U, item_size);
  DCHECK(refs != NULL);

  // Figure out the bounds of item.
  BlockGraph::Offset end_offset = item_offset + item_size;

  // Get iterators encompassing all references within the bounds of item.
  BlockGraph::Block::ReferenceMap::const_iterator ref_iter =
     block_->references().lower_bound(item_offset);
  BlockGraph::Block::ReferenceMap::const_iterator end_iter =
     block_->references().lower_bound(end_offset);

  for (; ref_iter != end_iter; ++ref_iter) {
    // Calculate the local offset of this reference within item.
    BlockGraph::Offset local_offset = ref_iter->first - item_offset;
    const BlockGraph::Reference& reference = ref_iter->second;

    // We expect long references for everything except flow control.
    CHECK_EQ(4U, reference.size());
    DCHECK_LE(local_offset + reference.size(), static_cast<Size>(end_offset));

    if (reference.referenced() != block_) {
      // For external references, we can directly reference the other block.
      bool inserted = refs->insert(std::make_pair(
            local_offset,
            BasicBlockReference(reference.type(), reference.size(),
                                reference.referenced(), reference.offset(),
                                reference.base()))).second;
      DCHECK(inserted);
    } else {
      // For intra block_ references, find the corresponding basic block in
      // the basic block address space.
      BasicBlock* target_bb = GetBasicBlockAt(reference.base());
      DCHECK(target_bb != NULL);

      // Create target basic-block relative values for the base and offset.
      // TODO(chrisha): Make BasicBlockReferences handle indirect references.
      CHECK_EQ(reference.offset(), reference.base());

      // Insert a reference to the target basic block.
      bool inserted = refs->insert(std::make_pair(
          local_offset,
          BasicBlockReference(reference.type(),
                              reference.size(),
                              target_bb))).second;
      DCHECK(inserted);
    }
  }
}

void BasicBlockDecomposer::CopyReferences() {
  // Copy the references for the source range of each basic-block (by
  // instruction for code basic-blocks). External referrers and successors are
  // handled in separate passes.
  BasicBlockSubGraph::BBCollection::iterator bb_iter =
      subgraph_->basic_blocks().begin();
  for (; bb_iter != subgraph_->basic_blocks().end(); ++bb_iter) {
    BasicCodeBlock* code_block = BasicCodeBlock::Cast(*bb_iter);
    if (code_block != NULL) {
      DCHECK_EQ(BasicBlock::BASIC_CODE_BLOCK, code_block->type());

      Offset inst_offset = code_block->offset();
      BasicBlock::Instructions::iterator inst_iter =
          code_block->instructions().begin();
      for (; inst_iter != code_block->instructions().end(); ++inst_iter) {
        CopyReferences(inst_offset,
                       inst_iter->size(),
                       &inst_iter->references());
        inst_offset += inst_iter->size();
      }
    }

    BasicDataBlock* data_block = BasicDataBlock::Cast(*bb_iter);
    if (data_block != NULL) {
      DCHECK_NE(BasicBlock::BASIC_CODE_BLOCK, data_block->type());
      CopyReferences(data_block->offset(),
                     data_block->size(),
                     &data_block->references());
    }
  }
}

void BasicBlockDecomposer::ResolveSuccessors() {
  BasicBlockSubGraph::BBCollection::iterator bb_iter =
      subgraph_->basic_blocks().begin();
  for (; bb_iter != subgraph_->basic_blocks().end(); ++bb_iter) {
    // Only code basic-blocks have successors and instructions.
    BasicCodeBlock* code_block = BasicCodeBlock::Cast(*bb_iter);
    if (code_block == NULL)
      continue;

    BasicBlock::Successors::iterator succ_iter =
        code_block->successors().begin();
    BasicBlock::Successors::iterator succ_iter_end =
        code_block->successors().end();
    for (; succ_iter != succ_iter_end; ++succ_iter) {
      if (succ_iter->reference().block() != block_)
        continue;

      // Find the basic block the successor references.
      BasicBlock* target_code_block =
          GetBasicBlockAt(succ_iter->reference().offset());
      DCHECK(target_code_block != NULL);

      // We transform all successor branches into 4-byte pc-relative targets.
      succ_iter->set_reference(
          BasicBlockReference(
              BlockGraph::PC_RELATIVE_REF, 4, target_code_block));
      DCHECK(succ_iter->reference().IsValid());
    }
  }
}

void BasicBlockDecomposer::MarkUnreachableCodeAsPadding() {
  BasicBlockSubGraph::ReachabilityMap rm;
  subgraph_->GetReachabilityMap(&rm);
  DCHECK_EQ(rm.size(), subgraph_->basic_blocks().size());
  BasicBlockSubGraph::BBCollection::iterator bb_iter =
      subgraph_->basic_blocks().begin();
  for (; bb_iter != subgraph_->basic_blocks().end(); ++bb_iter) {
    BasicCodeBlock* code_bb = BasicCodeBlock::Cast(*bb_iter);
    if (code_bb != NULL) {
      if (!subgraph_->IsReachable(rm, code_bb))
        code_bb->MarkAsPadding();
    }
  }
}

}  // namespace block_graph
