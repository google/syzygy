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
//
// TODO(rogerm): Refactor this to just do a straight disassembly of all bytes
//     (up to the start of embedded data: jump and case tables) to a list of
//     instructions, then chop up the instruction list into basic blocks in
//     a second pass, splicing the instructions into the basic-block instruction
//     lists and generating successors.

#include "syzygy/block_graph/basic_block_decomposer.h"

#include <algorithm>
#include <vector>

#include "base/logging.h"
#include "base/stringprintf.h"
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

}  // namespace

BasicBlockDecomposer::BasicBlockDecomposer(const BlockGraph::Block* block,
                                           BasicBlockSubGraph* subgraph)
    : Disassembler(block->data(),
                   block->size(),
                   AbsoluteAddress(kDisassemblyAddress),
                   Disassembler::InstructionCallback()),
      block_(block),
      subgraph_(subgraph),
      current_block_start_(0),
      check_decomposition_results_(true) {
  // TODO(rogerm): Once we're certain this is stable for all input binaries
  //     turn on check_decomposition_results_ by default only ifndef NDEBUG.
  DCHECK(block != NULL);
  DCHECK(block->type() == BlockGraph::CODE_BLOCK);
  DCHECK(CodeBlockAttributesAreBasicBlockSafe(block));
  DCHECK(subgraph != NULL);
}

bool BasicBlockDecomposer::Decompose() {
  DCHECK(subgraph_->basic_blocks().empty());
  DCHECK(subgraph_->block_descriptions().empty());
  DCHECK(original_address_space_.empty());
  subgraph_->set_original_block(block_);

  InitUnvisitedAndJumpTargets();

  WalkResult result = Walk();
  if (result != Disassembler::kWalkSuccess &&
      result != Disassembler::kWalkIncomplete) {
    return false;
  }

  typedef BasicBlockSubGraph::BlockDescription BlockDescription;
  subgraph_->block_descriptions().push_back(BlockDescription());
  BlockDescription& desc = subgraph_->block_descriptions().back();
  desc.name = block_->name();
  desc.type = block_->type();
  desc.alignment = block_->alignment();
  desc.attributes = block_->attributes();
  desc.section = block_->section();

  Offset offset = 0;
  RangeMapConstIter it = original_address_space_.begin();
  for (; it != original_address_space_.end(); ++it) {
    DCHECK_EQ(it->first.start(), offset);
    desc.basic_block_order.push_back(it->second);
    offset += it->first.size();
  }

  return true;
}

bool BasicBlockDecomposer::FindBasicBlock(Offset offset,
                                          BasicBlock** basic_block,
                                          Range* range) const {
  DCHECK_LE(0, offset);
  DCHECK(basic_block != NULL);
  DCHECK(range != NULL);
  DCHECK(subgraph_->original_block() != NULL);
  DCHECK_GT(subgraph_->original_block()->size(), static_cast<size_t>(offset));

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
  DCHECK_GT(subgraph_->original_block()->size(), static_cast<size_t>(offset));

  BasicBlock* bb = NULL;
  Range range;
  CHECK(FindBasicBlock(offset, &bb, &range));
  DCHECK(bb != NULL);
  DCHECK_EQ(offset, range.start());
  return bb;
}

void BasicBlockDecomposer::InitUnvisitedAndJumpTargets() {
  jump_targets_.clear();
  // We initialize our jump_targets_ and unvisited sets to the set of
  // referenced code locations. This covers all locations which are
  // externally referenced, as well as those that are internally referenced
  // via a branching instruction or jump table.
  BlockGraph::Block::ReferrerSet::const_iterator ref_iter =
      block_->referrers().begin();
  for (; ref_iter != block_->referrers().end(); ++ref_iter) {
    BlockGraph::Reference ref;
    bool found = ref_iter->first->GetReference(ref_iter->second, &ref);
    DCHECK(found);
    DCHECK_EQ(block_, ref.referenced());
    DCHECK_LE(0, ref.base());
    DCHECK_LT(static_cast<size_t>(ref.base()), block_->size());
    DCHECK_EQ(ref.base(), ref.offset());

    // Look for the first label past the reference. Back up if we can to the
    // previous label.
    BlockGraph::Block::LabelMap::const_iterator label_iter =
        block_->labels().upper_bound(ref.base());
    if (label_iter != block_->labels().begin())
      --label_iter;

    // If there is no previous label, or it is not a data label, then this is
    // a safe jump target.
    if (label_iter == block_->labels().end() ||
        label_iter->first > ref.offset() ||
        !label_iter->second.has_attributes(BlockGraph::DATA_LABEL)) {
      AbsoluteAddress addr(code_addr_ + ref.base());
      Unvisited(addr);
      jump_targets_.insert(addr);
    }
  }
}

Disassembler::CallbackDirective BasicBlockDecomposer::OnInstruction(
    AbsoluteAddress addr, const _DInst& inst) {
  Offset offset = addr - code_addr_;

  // If this instruction has run into known data, then we have a problem in
  // the decomposer.
  BlockGraph::Label label;
  CHECK(!block_->GetLabel(offset, &label) ||
        !label.has_attributes(BlockGraph::DATA_LABEL))
      << "Disassembling into data at offset " << offset << " of "
      << block_->name() << ".";

  VLOG(3) << "Disassembled " << GET_MNEMONIC_NAME(inst.opcode)
          << " instruction (" << static_cast<int>(inst.size)
          << " bytes) at offset " << offset << ".";

  current_instructions_.push_back(
      Instruction(inst, offset, inst.size, code_ + offset));
  if (label.IsValid())
    current_instructions_.back().set_label(label);

  // If continuing this basic-block would disassemble into known data then
  // end the current basic-block.
  if (block_->GetLabel(offset + inst.size, &label) &&
      label.has_attributes(BlockGraph::DATA_LABEL)) {
    return kDirectiveTerminatePath;
  }

  // If this instruction is a call to a non-returning function, then this is
  // essentially a control flow operation, and we need to end this basic block.
  // We'll schedule the disassembly of any instructions which follow it as
  // a separate basic block, and mark that basic block as unreachable in a
  // post pass.
  if (META_GET_FC(inst.meta) == FC_CALL &&
      (inst.ops[0].type == O_PC || inst.ops[0].type == O_DISP)) {
    BlockGraph::Reference ref;
    bool found = GetReferenceOfInstructionAt(block_, offset, inst.size, &ref);
    CHECK(found);
    if (Instruction::CallsNonReturningFunction(inst, ref.referenced(),
                                               ref.offset())) {
      Unvisited(addr + inst.size);
      return kDirectiveTerminatePath;
    }
  }

  return kDirectiveContinue;
}

Disassembler::CallbackDirective BasicBlockDecomposer::OnBranchInstruction(
    AbsoluteAddress addr, const _DInst& inst, AbsoluteAddress dest) {
  // Note: Both addr and dest are fabricated addresses. The code_addr_ has
  //     been selected such that addr will never be 0; similarly, dest should
  //     only be 0 for control flow instructions having no explicit destination.
  //     Do not use dest to resolve the destination, instead find the
  //     corresponding reference in the byte range of the original instruction.

  // The branch instruction should have already been appended to the
  // instruction list.
  DCHECK_EQ(0, ::memcmp(&current_instructions_.back().representation(),
                        &inst,
                        sizeof(inst)));

  // Make sure we understand the branching condition. If we don't, then there's
  // an instruction we have failed to consider.
  Successor::Condition condition = Successor::OpCodeToCondition(inst.opcode);
  CHECK_NE(Successor::kInvalidCondition, condition)
      << "Received unknown condition for branch instruction: "
      << GET_MNEMONIC_NAME(inst.opcode) << ".";

  // If this is a conditional branch add the inverse conditional successor to
  // represent the fall-through. If we don't understand the inverse, then
  // there's an instruction we have failed to consider.
  if (META_GET_FC(inst.meta) == FC_CND_BRANCH) {
    Successor::Condition inverse_condition =
        Successor::InvertCondition(condition);
    CHECK_NE(Successor::kInvalidCondition, inverse_condition)
        << "Non-invertible condition seen for branch instruction: "
        << GET_MNEMONIC_NAME(inst.opcode) << ".";

    // Create an (unresolved) successor pointing to the next instruction.
    current_successors_.push_front(
        Successor(inverse_condition,
                  (addr + inst.size) - code_addr_,
                  BasicBlock::kNoOffset,
                  0));
    jump_targets_.insert(addr + inst.size);
  }

  // Note that some control flow instructions have no explicit target (for
  // example, RET, SYS* and computed branches); for these dest will be 0.
  // We do not explicitly model these with successor relationships. Instead,
  // we leave the instruction (and its corresponding references, in the case
  // of computed jumps) intact and move on.
  if (dest.value() != 0) {
    // Take the last instruction out of the instruction list, we'll represent
    // it as a successor instead.
    Successor::Offset instr_offset = current_instructions_.back().offset();
    Successor::Size instr_size = current_instructions_.back().size();
    BlockGraph::Label instr_label = current_instructions_.back().label();
    current_instructions_.pop_back();
    DCHECK_EQ(addr - code_addr_, instr_offset);
    DCHECK_EQ(inst.size, instr_size);

    // Figure out where the branch is going by finding the reference that's
    // inside the instruction's byte range.
    BlockGraph::Reference ref;
    bool found = GetReferenceOfInstructionAt(
        block_, instr_offset, instr_size, &ref);

    // Create the appropriate successor depending on whether or not the target
    // is intra- or inter-block.
    if (!found || ref.referenced() == block_) {
      // This is an intra-block reference. The target basic block may not
      // exist yet, so we'll defer patching up this reference until later.
      Offset target_offset = dest - code_addr_;

      // If a reference was found, prefer its destination information
      // to the information conveyed by the bytes in the instruction.
      if (found) {
        target_offset = dest - code_addr_;
        dest = AbsoluteAddress(kDisassemblyAddress + target_offset);
      }

      CHECK_LE(0, target_offset);
      CHECK_LT(static_cast<size_t>(target_offset), code_size_);
      current_successors_.push_front(
          Successor(condition, target_offset, instr_offset, instr_size));
      jump_targets_.insert(dest);
    } else {
      // This is an inter-block jump. We can create a fully resolved reference.
      BasicBlockReference bb_ref(
          ref.type(), ref.size(), ref.referenced(), ref.offset(), ref.base());
      current_successors_.push_front(
          Successor(condition, bb_ref, instr_offset, instr_size));
    }

    if (instr_label.IsValid())
      current_successors_.front().set_label(instr_label);
  }

  // This marks the end of a basic block. Note that the disassembler will
  // handle ending the instruction run and beginning a new one for the next
  // basic block (including the branch-not-taken arc).
  return kDirectiveContinue;
}

// Called every time disassembly is started from a new address. Will be
// called for at least every address in unvisited_.
Disassembler::CallbackDirective BasicBlockDecomposer::OnStartInstructionRun(
    AbsoluteAddress start_address) {
  // The address of the beginning of the current basic block.
  current_block_start_ = start_address;
  DCHECK(current_instructions_.empty());
  DCHECK(current_successors_.empty());
  return kDirectiveContinue;
}

// Called when a walk from a given entry point has terminated.
Disassembler::CallbackDirective BasicBlockDecomposer::OnEndInstructionRun(
    AbsoluteAddress addr, const _DInst& inst, ControlFlowFlag control_flow) {
  // If an otherwise straight run of instructions is split because it crosses
  // a basic block boundary we need to set up the implicit control flow arc
  // here.
  if (control_flow == kControlFlowContinues) {
    DCHECK(current_successors_.empty());
    DCHECK(!current_instructions_.empty());
    DCHECK(!current_instructions_.back().IsImplicitControlFlow());

    current_successors_.push_front(
        Successor(Successor::kConditionTrue,
                  (addr + inst.size) - code_addr_,  // To be resolved later.
                  BasicBlock::kNoOffset,
                  0));
  }

  // We have reached the end of the current walk or we handled a conditional
  // branch. Let's mark this as the end of a basic block.
  size_t basic_block_size = addr - current_block_start_ + inst.size;
  DCHECK_LT(0U, basic_block_size);
  if (!InsertBasicBlockRange(current_block_start_,
                             basic_block_size,
                             BasicBlock::BASIC_CODE_BLOCK)) {
    return kDirectiveAbort;
  }

  return kDirectiveContinue;
}

Disassembler::CallbackDirective BasicBlockDecomposer::OnDisassemblyComplete() {
  // Split code blocks at branch targets.
  if (!SplitCodeBlocksAtBranchTargets()) {
    LOG(ERROR) << "Failed to split code blocks at branch targets.";
    return kDirectiveAbort;
  }

  // By this point, we should have basic blocks for all visited code.
  CheckAllJumpTargetsStartABasicCodeBlock();

  // Demarcate the data basic blocks. There should be no overlap with code.
  if (!FillInDataBlocks()) {
    LOG(ERROR) << "Failed to fill in data basic-block ranges.";
    return kDirectiveAbort;
  }

  // We may not have covered some ranges of the macro block. For all such
  // ranges, build basic blocks and mark them as padding. This might
  // include unreachable code in unoptimized input binaries.
  if (!FillInPaddingBlocks()) {
    LOG(ERROR) << "Failed to fill in padding basic-block ranges.";
    return kDirectiveAbort;
  }

  // We should now have contiguous block ranges that cover every byte in the
  // macro block. Verify that this is so.
  CheckHasCompleteBasicBlockCoverage();

  // We should have propagated all of the labels in the original block into
  // the basic-block subgraph.
  CheckAllLabelsArePreserved();

  // Populate the referrers in the basic block data structures by copying
  // them from the original source block.
  if (!CopyExternalReferrers()) {
    LOG(ERROR) << "Failed to populate basic-block referrers.";
    return kDirectiveAbort;
  }

  // Populate the references in the basic block data structures by copying
  // them from the original source block. This does not handle the successor
  // references.
  if (!CopyReferences()) {
    LOG(ERROR) << "Failed to populate basic-block references.";
    return kDirectiveAbort;
  }

  // Wire up the the basic-block successors. These are not handled by
  // CopyReferences(), above.
  if (!ResolveSuccessors()) {
    LOG(ERROR) << "Failed to resolve basic-block successors.";
    return kDirectiveAbort;
  }

  // All the control flow we have derived should be valid.
  CheckAllControlFlowIsValid();

  // ... and we're done.
  return kDirectiveContinue;
}

void BasicBlockDecomposer::CheckAllJumpTargetsStartABasicCodeBlock() const {
  if (!check_decomposition_results_)
    return;

  AddressSet::const_iterator addr_iter(jump_targets_.begin());
  for (; addr_iter != jump_targets_.end(); ++addr_iter) {
    // The target basic-block should be a code basic-block.
    BasicBlock* target_bb = GetBasicBlockAt(*addr_iter - code_addr_);
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
    CHECK_EQ(it->first.size(), it->second->size());
    next_start += it->first.size();
  }

  // At this point, if there were no gaps, next start will be the same as the
  // full size of the block we're decomposing.
  CHECK_EQ(code_size_, static_cast<size_t>(next_start));
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
    const BasicBlock* bb = it->second;
    if (bb->type() != BasicBlock::BASIC_CODE_BLOCK)
      continue;

    const BasicBlock::Instructions& instructions = bb->instructions();
    const BasicBlock::Successors& successors = bb->successors();

    // There may be at most 2 successors.
    switch (successors.size()) {
      case 0:
        break;

      case 1:
        // If the successor is synthesized, then flow is from this basic-block
        // to the next adjacent one.
        if (successors.back().instruction_offset() == -1) {
          RangeMapConstIter next(it);
          ++next;
          CHECK(next != original_address_space_.end());
          CHECK_EQ(successors.back().reference().basic_block(), next->second);
        }
        break;

      case 2: {
        // Exactly one of the successors should have been synthesized.
        bool front_synthesized = successors.front().instruction_offset() == -1;
        bool back_synthesized = successors.back().instruction_offset() == -1;
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

  const Block::LabelMap original_labels = original_block->labels();
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
    // Account for labels attached to basic-blocks.
    const BasicBlock& bb = bb_iter->second;
    if (bb.has_label()) {
      BlockGraph::Label label;
      CHECK(original_block->GetLabel(bb.offset(), &label));
      CHECK(bb.label() == label);
      labels_found[bb.offset()] = true;
    }

    // Account for labels attached to instructions.
    BasicBlock::Instructions::const_iterator inst_iter =
        bb.instructions().begin();
    for (; inst_iter != bb.instructions().end(); ++inst_iter) {
      const Instruction& inst = *inst_iter;
      if (inst.has_label()) {
        BlockGraph::Label label;
        CHECK(original_block->GetLabel(inst.offset(), &label));
        CHECK(inst.label() == label);
        labels_found[inst.offset()] = true;
      }
    }

    // Account for labels attached to successors.
    BasicBlock::Successors::const_iterator succ_iter =
        bb.successors().begin();
    for (; succ_iter != bb.successors().end(); ++succ_iter) {
      const Successor& succ = *succ_iter;
      if (succ.has_label()) {
        BlockGraph::Label label;
        CHECK_NE(BasicBlock::kNoOffset, succ.instruction_offset());
        CHECK(original_block->GetLabel(succ.instruction_offset(), &label));
        CHECK(succ.label() == label);
        labels_found[succ.instruction_offset()] = true;
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

bool BasicBlockDecomposer::InsertBasicBlockRange(AbsoluteAddress addr,
                                                 size_t size,
                                                 BasicBlockType type) {
  DCHECK(type == BasicBlock::BASIC_CODE_BLOCK || current_instructions_.empty());
  DCHECK(type == BasicBlock::BASIC_CODE_BLOCK || current_successors_.empty());

  BasicBlock::Offset offset = addr - code_addr_;
  DCHECK_LE(0, offset);

  // Find or create a name for this basic block. Reserve the label, if any,
  // to propagate to the basic block if there are no instructions in the
  // block to carry the label(s).
  BlockGraph::Label label;
  std::string basic_block_name;
  if (block_->GetLabel(offset, &label)) {
    basic_block_name = label.ToString();
  } else {
    basic_block_name =
        base::StringPrintf("<anonymous-%04X-%s>",
                           addr.value(),
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

  // Create the basic block.
  BasicBlock* new_basic_block = subgraph_->AddBasicBlock(
      basic_block_name, type, offset, size, code_ + offset);
  if (new_basic_block == NULL)
    return false;

  CHECK(original_address_space_.Insert(byte_range, new_basic_block));

  // Code basic-blocks carry their labels in their instructions and successors.
  // Data basic-blocks carry their labels at the head of the basic blocks.
  // A padding basic-block might also be labeled if the block contains
  // unreachable code (for example, INT3 or NOP instructions following a call
  // to a non-returning function).
  if (type != BasicBlock::BASIC_CODE_BLOCK && label.IsValid()) {
    new_basic_block->set_label(label);
  }

  // Populate code basic-block with instructions and successors.
  if (type == BasicBlock::BASIC_CODE_BLOCK) {
    new_basic_block->instructions().swap(current_instructions_);
    new_basic_block->successors().swap(current_successors_);
  }

  return true;
}

bool BasicBlockDecomposer::SplitCodeBlocksAtBranchTargets() {
  // TODO(rogerm): Refactor the basic-block splitting inner-function to the
  //     BasicBlockSubGraph. Note that the subgraph currently maintains a
  //     picture of the original address space of the source block. This should
  //     also be factored out; the original address space is only relevant to
  //     the BasicBlockDecomposer.
  AddressSet::const_iterator jump_target_iter(jump_targets_.begin());
  for (; jump_target_iter != jump_targets_.end(); ++jump_target_iter) {
    // Resolve the target basic-block.
    Offset target_offset = *jump_target_iter - code_addr_;
    BasicBlock* target_bb = NULL;
    Range target_bb_range;
    CHECK(FindBasicBlock(target_offset, &target_bb, &target_bb_range));

    // If we're jumping to the start of a basic block, there isn't any work
    // to do.
    if (target_offset == target_bb_range.start())
      continue;

    // Otherwise, we have found a basic-block that we need to split. Let's
    // create a backup copy of the target basic-block and remove the original
    // from the basic-block address space. We'll replace it with two new
    // blocks split at the target offset.
    size_t left_split_size = target_offset - target_bb_range.start();
    BasicBlock target_bb_copy(*target_bb);
    original_address_space_.Remove(target_bb_range);
    subgraph_->basic_blocks().erase(target_bb->id());
    target_bb = &target_bb_copy;

    // Now we split up containing_range into two new ranges and replace
    // containing_range with the two new entries.

    // Setup the first "half" of the basic block. Note that we are reusing
    // current_instructions_ and current_successors_ so that we can use
    // InsertBlockRange to create the new basic-blocks.
    DCHECK(current_instructions_.empty());
    DCHECK(current_successors_.empty());
    while (!target_bb->instructions().empty() &&
           target_bb->instructions().front().offset() < target_offset) {
      current_instructions_.splice(current_instructions_.end(),
                                   target_bb->instructions(),
                                   target_bb->instructions().begin());
    }

    // The next offset (to an instruction or successor) should correspond to
    // the target offset.
    if (!target_bb->instructions().empty()) {
      DCHECK_EQ(target_offset, target_bb->instructions().front().offset());
    } else {
      DCHECK(!target_bb->successors().empty());
      DCHECK_EQ(target_offset,
                target_bb->successors().front().instruction_offset());
    }

    // Set-up the flow-through successor for the first "half".
    current_successors_.push_back(Successor(
        Successor::kConditionTrue, target_offset, BasicBlock::kNoOffset, 0));

    // Create the basic-block representing the first "half".
    if (!InsertBasicBlockRange(code_addr_ + target_bb_range.start(),
                               left_split_size,
                               target_bb->type())) {
      LOG(ERROR) << "Failed to insert first half of split block.";
      return false;
    }

    // Create the basic-block representing the second "half".
    DCHECK(current_instructions_.empty());
    DCHECK(current_successors_.empty());
    current_instructions_.swap(target_bb->instructions());
    current_successors_.swap(target_bb->successors());
    if (!InsertBasicBlockRange(code_addr_ + target_offset,
                               target_bb_range.size() - left_split_size,
                               target_bb->type())) {
      LOG(ERROR) << "Failed to insert second half of split block.";
      return false;
    }
  }

  return true;
}

bool BasicBlockDecomposer::FillInDataBlocks() {
  BlockGraph::Block::LabelMap::const_iterator iter = block_->labels().begin();
  BlockGraph::Block::LabelMap::const_iterator end = block_->labels().end();
  for (; iter != end; ++iter) {
    if (!iter->second.has_attributes(BlockGraph::DATA_LABEL))
      continue;

    BlockGraph::Block::LabelMap::const_iterator next = iter;
    ++next;

    BlockGraph::Offset bb_start = iter->first;
    BlockGraph::Offset bb_end = (next == end) ? block_->size() : next->first;
    size_t bb_size = bb_end - bb_start;
    AbsoluteAddress bb_addr(code_addr_ + bb_start);
    if (!InsertBasicBlockRange(bb_addr, bb_size, BasicBlock::BASIC_DATA_BLOCK))
      return false;
  }
  return true;
}

bool BasicBlockDecomposer::FillInPaddingBlocks() {
  // Add an initial interstitial if needed.
  size_t interstitial_size = original_address_space_.empty() ?
      code_size_ : original_address_space_.begin()->first.start();
  DCHECK_LE(0U, interstitial_size);
  if (interstitial_size > 0) {
    if (!InsertBasicBlockRange(code_addr_,
                               interstitial_size,
                               BasicBlock::BASIC_PADDING_BLOCK)) {
      LOG(ERROR) << "Failed to insert initial padding block at 0";
      return false;
    }
  }

  // Handle all remaining gaps, including the end.
  RangeMapConstIter curr_range = original_address_space_.begin();
  for (; curr_range != original_address_space_.end(); ++curr_range) {
    RangeMapConstIter next_range = curr_range;
    ++next_range;
    AbsoluteAddress curr_range_end =
        code_addr_ + curr_range->first.start() + curr_range->first.size();

    interstitial_size = 0;
    if (next_range == original_address_space_.end()) {
      DCHECK_LE(curr_range_end, code_addr_ + code_size_);
      interstitial_size = code_addr_ + code_size_ - curr_range_end;
    } else {
      DCHECK_LE(curr_range_end, code_addr_ + next_range->first.start());
      interstitial_size =
          code_addr_ + next_range->first.start() - curr_range_end;
    }

    if (interstitial_size > 0) {
      if (!InsertBasicBlockRange(curr_range_end,
                                 interstitial_size,
                                 BasicBlock::BASIC_PADDING_BLOCK)) {
        LOG(ERROR) << "Failed to insert padding block at "
                   << curr_range_end.value();
        return false;
      }
    }
  }

  return true;
}

bool BasicBlockDecomposer::CopyExternalReferrers() {
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

    // Find the basic block the reference refers to. It can only have an
    // offset that's different from the base if it's not a code block.
    BasicBlock* target_bb = GetBasicBlockAt(reference.base());
    DCHECK(target_bb != NULL);
    DCHECK(reference.base() == reference.offset() ||
           target_bb->type() != BasicBlock::BASIC_CODE_BLOCK);

    // Insert the referrer into the target bb's referrer set. Note that there
    // is no corresponding reference update to the referring block. The
    // target bb will track these so a BlockBuilder can properly update
    // the referrers when merging a subgraph back into the block-graph.
    bool inserted = target_bb->referrers().insert(
        BasicBlockReferrer(referrer, source_offset)).second;
    DCHECK(inserted);
  }

  return true;
}

template<typename ItemType>
bool BasicBlockDecomposer::CopyReferences(ItemType* item) {
  DCHECK(item != NULL);

  // Figure out the bounds of item.
  BlockGraph::Offset start_offset = item->offset();
  BlockGraph::Offset end_offset = start_offset + item->size();

  // Get iterators encompassing all references within the bounds of item.
  BlockGraph::Block::ReferenceMap::const_iterator ref_iter =
     block_->references().lower_bound(start_offset);
  BlockGraph::Block::ReferenceMap::const_iterator end_iter =
     block_->references().lower_bound(end_offset);

  for (; ref_iter != end_iter; ++ref_iter) {
    // Calculate the local offset of this reference within item.
    BlockGraph::Offset local_offset = ref_iter->first - start_offset;
    const BlockGraph::Reference& reference = ref_iter->second;

    // We expect long references for everything except flow control.
    CHECK_EQ(4U, reference.size());
    DCHECK_LE(local_offset + reference.size(), item->GetMaxSize());

    if (reference.referenced() != block_) {
      // For external references, we can directly reference the other block.
      bool inserted = item->SetReference(
          local_offset,
          BasicBlockReference(reference.type(), reference.size(),
                              reference.referenced(), reference.offset(),
                              reference.base()));
      DCHECK(inserted);
    } else {
      // For intra block_ references, find the corresponding basic block in
      // the basic block address space.
      BasicBlock* target_bb = GetBasicBlockAt(reference.base());
      DCHECK(target_bb != NULL);

      // Create target basic-block relative values for the base and offset.
      CHECK_EQ(reference.offset(), reference.base());

      // Insert a reference to the target basic block.
      bool inserted = item->SetReference(
          local_offset,
          BasicBlockReference(reference.type(), reference.size(), target_bb));
      DCHECK(inserted);
    }
  }
  return true;
}

bool BasicBlockDecomposer::CopyReferences() {
  // Copy the references for the source range of each basic-block (by
  // instruction for code basic-blocks). External referrers and successors are
  // handled in separate passes.
  BasicBlockSubGraph::BBCollection::iterator bb_iter =
      subgraph_->basic_blocks().begin();
  for (; bb_iter != subgraph_->basic_blocks().end(); ++bb_iter) {
    BasicBlock* bb = &bb_iter->second;
    if (bb->type() == BasicBlock::BASIC_CODE_BLOCK) {
      BasicBlock::Instructions::iterator inst_iter = bb->instructions().begin();
      for (; inst_iter != bb->instructions().end(); ++inst_iter) {
        if (!CopyReferences(&(*inst_iter)))
          return false;
      }
    } else {
      if (!CopyReferences(bb))
        return false;
    }
  }
  return true;
}

bool BasicBlockDecomposer::ResolveSuccessors() {
  BasicBlockSubGraph::BBCollection::iterator bb_iter =
      subgraph_->basic_blocks().begin();
  for (; bb_iter != subgraph_->basic_blocks().end(); ++bb_iter) {
    // Only code basic-blocks have successors and instructions.
    BasicBlock* bb = &bb_iter->second;
    if (bb->type() != BasicBlock::BASIC_CODE_BLOCK) {
      DCHECK(bb->successors().empty());
      DCHECK(bb->instructions().empty());
      continue;
    }

    BasicBlock::Successors::iterator succ_iter = bb->successors().begin();
    BasicBlock::Successors::iterator succ_iter_end = bb->successors().end();
    for (; succ_iter != succ_iter_end; ++succ_iter) {
      if (succ_iter->reference().IsValid()) {
        // The branch target is already resolved; it must have been inter-block.
        DCHECK(succ_iter->reference().block() != block_);
        DCHECK(succ_iter->reference().block() != NULL);
        continue;
      }

      // Find the basic block the successor references.
      BasicBlock* target_bb = GetBasicBlockAt(succ_iter->bb_target_offset());
      DCHECK(target_bb != NULL);

      // We transform all successor branches into 4-byte pc-relative targets.
      bool inserted = succ_iter->SetReference(
          BasicBlockReference(BlockGraph::PC_RELATIVE_REF, 4, target_bb));
      DCHECK(inserted);
      DCHECK(succ_iter->reference().IsValid());
    }
  }

  return true;
}

}  // namespace block_graph
