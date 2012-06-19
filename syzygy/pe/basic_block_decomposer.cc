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
// Implementation of basic block disassembler.

#include "syzygy/pe/basic_block_decomposer.h"

#include <algorithm>
#include <vector>

#include "base/logging.h"
#include "base/stringprintf.h"
#include "syzygy/block_graph/basic_block.h"
#include "syzygy/block_graph/block_graph.h"
#include "syzygy/pe/basic_block_subgraph.h"
#include "syzygy/pe/block_util.h"

#include "mnemonics.h"  // NOLINT

namespace pe {

namespace {

using block_graph::BasicBlock;
using block_graph::BasicBlockReference;
using block_graph::BasicBlockReferrer;
using block_graph::BlockGraph;
using block_graph::Instruction;
using block_graph::Successor;
using core::Disassembler;

typedef BasicBlockSubGraph::BBAddressSpace BBAddressSpace;
typedef BBAddressSpace::Range Range;
typedef BBAddressSpace::RangeMap RangeMap;
typedef BBAddressSpace::RangeMapConstIter RangeMapConstIter;
typedef BBAddressSpace::RangeMapIter RangeMapIter;

// We use a (somewhat) arbitrary value as the disassembly address for a block
// so we can tell the difference between a reference to the beginning of the
// block (offset=0) and a null address.
const size_t kDisassemblyAddress = 65536;

// TODO(rogerm): The core of this function belongs as a helper on Instruction,
//     with a convenience ranged loop check on BasicBlock.
bool HasControlFlow(BasicBlock::Instructions::const_iterator start,
                    BasicBlock::Instructions::const_iterator end) {
  for (; start != end; ++start) {
    uint8 fc = META_GET_FC(start->representation().meta);
    if (fc == FC_CND_BRANCH || fc == FC_UNC_BRANCH ||
        fc == FC_RET || fc == FC_SYS) {
      return true;
    }
  }
  return false;
}

// TODO(rogerm): Belongs as a helper on Instruction.
bool HasImplicitControlFlow(const Instruction& instruction) {
  uint8 fc = META_GET_FC(instruction.representation().meta);
  if (fc == FC_RET || fc == FC_SYS) {
    // Control flow jumps implicitly out of the block.
    return true;
  } else if (fc == FC_CND_BRANCH || fc == FC_UNC_BRANCH) {
    uint8 type = instruction.representation().ops[0].type;
    if (type == O_REG || type == O_MEM ||
        type == O_SMEM || type == O_DISP) {
      // There is an explicit branch, but the target is computed, stored
      // in a register, or indirect. We don't follow those.
      return true;
    }
  }
  return false;
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
  DCHECK(CodeBlockIsClConsistent(block));
  DCHECK(subgraph != NULL);
}

bool BasicBlockDecomposer::Decompose() {
  DCHECK(subgraph_->basic_blocks().empty());
  DCHECK(subgraph_->block_descriptions().empty());
  DCHECK(subgraph_->original_address_space().empty());
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
  RangeMapConstIter it = subgraph_->original_address_space().begin();
  for (; it != subgraph_->original_address_space().end(); ++it) {
    DCHECK_EQ(it->first.start(), offset);
    desc.basic_block_order.push_back(it->second);
    offset += it->first.size();
  }

  return true;
}

void BasicBlockDecomposer::InitUnvisitedAndJumpTargets() {
  jump_targets_.clear();
  // We initialize our jump_targets_ and unvisited sets to the set of
  // referenced code locations. This covers all locations which are
  // externally referenced, as well as those that are internally referenced
  // via a branching instruction or jump table.
  DCHECK(!block_->labels().empty());
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

    BlockGraph::Block::LabelMap::const_iterator label_iter =
        block_->labels().upper_bound(ref.base());
    DCHECK(label_iter != block_->labels().begin());
    --label_iter;
    if (!label_iter->second.has_attributes(BlockGraph::DATA_LABEL)) {
      AbsoluteAddress addr(code_addr_ + ref.base());
      Unvisited(addr);
      jump_targets_.insert(addr);
    }
  }
}

Disassembler::CallbackDirective BasicBlockDecomposer::OnInstruction(
    AbsoluteAddress addr, const _DInst& inst) {
  VLOG(3) << "Disassembled " << GET_MNEMONIC_NAME(inst.opcode)
          << " instruction (" << static_cast<int>(inst.size)
          << " bytes) at offset " << (addr - code_addr_) << ".";
  current_instructions_.push_back(
      Instruction(inst, addr - code_addr_, inst.size));
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
                  BasicBlock::kEphemeralSourceOffset,
                  0));
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
    current_instructions_.pop_back();
    DCHECK_EQ(addr - code_addr_, instr_offset);
    DCHECK_EQ(inst.size, instr_size);

    // Figure out where the branch is going by finding the reference that's
    // inside the instruction's byte range. There should be exactly 1 reference
    // in the instruction byte range.
    BlockGraph::Block::ReferenceMap::const_iterator ref_iter =
        block_->references().upper_bound(instr_offset);
    DCHECK(ref_iter != block_->references().end());
#ifndef NDEBUG
    if (ref_iter != block_->references().begin()) {
      BlockGraph::Block::ReferenceMap::const_iterator prev_iter = ref_iter;
      --prev_iter;
      DCHECK(prev_iter->first < instr_offset);
    }
    BlockGraph::Block::ReferenceMap::const_iterator next_iter = ref_iter;
    ++next_iter;
    DCHECK(next_iter == block_->references().end() ||
           next_iter->first >= instr_offset + static_cast<Offset>(instr_size));
#endif

    // Create the appropriate successor depending on whether or not the target
    // is intra- or inter-block.
    if (ref_iter->second.referenced() == block_) {
      // This is an intra-block reference. The target basic block may not
      // exist yet, so we'll defer patching up this reference until later.
      // The self reference should already have been considered in the list
      // of disassembly start points and jump targets.
      DCHECK_EQ(1U,
                jump_targets_.count(code_addr_ + ref_iter->second.offset()));
      current_successors_.push_front(
          Successor(condition,
                    ref_iter->second.offset(),  // To be resolved later.
                    instr_offset,
                    instr_size));
    } else {
      // This is an inter-block jump. We can create a fully resolved reference.
      current_successors_.push_front(
          Successor(condition,
                    BasicBlockReference(ref_iter->second.type(),
                                        ref_iter->second.size(),
                                        ref_iter->second.referenced(),
                                        ref_iter->second.offset(),
                                        ref_iter->second.base()),
                    instr_offset,
                    instr_size));
    }
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
    DCHECK(!HasImplicitControlFlow(current_instructions_.back()));

    current_successors_.push_front(
        Successor(Successor::kConditionTrue,
                  (addr + inst.size) - code_addr_,  // To be resolved later.
                  BasicBlock::kEphemeralSourceOffset,
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

  // Populate the referrers in the basic block data structures by copying
  // them from the original source block.
  if (!PopulateBasicBlockReferrers()) {
    LOG(ERROR) << "Failed to populate basic-block referrers.";
    return kDirectiveAbort;
  }

  // Populate the references in the basic block data structures by copying
  // them from the original source block.
  if (!PopulateBasicBlockReferences()) {
    LOG(ERROR) << "Failed to populate basic-block referrences.";
    return kDirectiveAbort;
  }

  // Wire up the the basic-block successors.
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

  const BBAddressSpace& basic_block_address_space =
      subgraph_->original_address_space();

  AddressSet::const_iterator addr_iter(jump_targets_.begin());
  for (; addr_iter != jump_targets_.end(); ++addr_iter) {
    // Find the basic block that maps to the jump target.
    Offset target_offset = *addr_iter - code_addr_;
    RangeMapConstIter target_bb_iter =
        basic_block_address_space.FindFirstIntersection(
            Range(target_offset, 1));

    // The target must exist.
    CHECK(target_bb_iter != basic_block_address_space.end());

    // The target offset should refer to the start of the basic block.
    CHECK_EQ(target_offset, target_bb_iter->first.start());

    // The target basic-block should be a code basic-block.
    CHECK_EQ(BasicBlock::BASIC_CODE_BLOCK, target_bb_iter->second->type());
  }
}

void BasicBlockDecomposer::CheckHasCompleteBasicBlockCoverage() const {
  if (!check_decomposition_results_)
    return;

  const BBAddressSpace& basic_block_address_space =
      subgraph_->original_address_space();

  // Walk through the basic-block address space.
  Offset next_start = 0;
  RangeMapConstIter it(basic_block_address_space.begin());
  for (; it != basic_block_address_space.end(); ++it) {
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

  const BBAddressSpace& basic_block_address_space =
      subgraph_->original_address_space();

  RangeMapConstIter it(basic_block_address_space.begin());
  for (; it != basic_block_address_space.end(); ++it) {
    const BasicBlock* bb = it->second;
    if (bb->type() != BasicBlock::BASIC_CODE_BLOCK)
      continue;

    // TODO(rogerm): All references to this block should be to its head.

    const BasicBlock::Instructions& instructions = bb->instructions();
    const BasicBlock::Successors& successors = bb->successors();

    // There may be at most 2 successors.
    size_t num_successors = successors.size();
    CHECK_GE(2U, num_successors);
    switch (num_successors) {
      case 0: {
        // If there are no successors, then there must be some instructions in
        // the basic block.
        CHECK(!instructions.empty());

        // There should be no control flow in anything but the last instruction.
        CHECK(!HasControlFlow(instructions.begin(), --instructions.end()));

        // Either there's is an implicit control flow insruction at the end
        // or this function has been tagged as non-returning.
        bool no_return =
            (block_->attributes() & BlockGraph::NON_RETURN_FUNCTION) != 0;
        CHECK(HasImplicitControlFlow(instructions.back()) || no_return);
        break;
      }

      case 1: {
        // There should be no control flow instructions in the entire sequence.
        CHECK(!HasControlFlow(instructions.begin(), instructions.end()));

        // The successor must be unconditional.
        const Successor& successor = successors.back();
        CHECK_EQ(Successor::kConditionTrue, successor.condition());

        // If the successor is synthesized, then flow is from this basic-block
        // to the next adjacent one.
        if (successors.back().instruction_offset() == -1) {
          RangeMapConstIter next(it);
          ++next;
          CHECK(next != basic_block_address_space.end());
          CHECK_EQ(successor.branch_target().basic_block(), next->second);
        }
        break;
      }

      case 2: {
        // There should be no control flow instructions in the entire sequence.
        CHECK(!HasControlFlow(instructions.begin(), instructions.end()));

        // The conditions on the successors should be inverses of one another.
        CHECK_EQ(successors.front().condition(),
                 Successor::InvertCondition(successors.back().condition()));

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
        CHECK(next != basic_block_address_space.end());
        CHECK_EQ(synthesized.branch_target().basic_block(), next->second);
        break;
      }

      default:
        NOTREACHED();
    }
  }
}

bool BasicBlockDecomposer::InsertBasicBlockRange(AbsoluteAddress addr,
                                                 size_t size,
                                                 BasicBlockType type) {
  DCHECK(type == BasicBlock::BASIC_CODE_BLOCK || current_instructions_.empty());
  DCHECK(type == BasicBlock::BASIC_CODE_BLOCK || current_successors_.empty());

  BasicBlock::Offset offset = addr - code_addr_;
  DCHECK_LE(0, offset);

  // Find or create a name for this basic block.
  BlockGraph::Label label;
  std::string basic_block_name;
  if (block_->GetLabel(offset, &label)) {
    basic_block_name = label.ToString();
  } else {
    basic_block_name = base::StringPrintf(
        "<anonymous-%s>", BasicBlock::BasicBlockTypeToString(type));
  }

  BasicBlock* new_basic_block = subgraph_->AddBasicBlock(
      basic_block_name, type, offset, size, code_ + offset);
  if (new_basic_block == NULL)
    return false;

  if (type == BasicBlock::BASIC_CODE_BLOCK) {
    new_basic_block->instructions().swap(current_instructions_);
    new_basic_block->successors().swap(current_successors_);
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
  BBAddressSpace& basic_block_address_space =
      subgraph_->original_address_space();

  // Add an initial interstitial if needed.
  size_t interstitial_size = basic_block_address_space.empty() ?
      code_size_ : basic_block_address_space.begin()->first.start();
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
  RangeMapConstIter curr_range = basic_block_address_space.begin();
  for (; curr_range != basic_block_address_space.end(); ++curr_range) {
    RangeMapConstIter next_range = curr_range;
    ++next_range;
    AbsoluteAddress curr_range_end =
        code_addr_ + curr_range->first.start() + curr_range->first.size();

    interstitial_size = 0;
    if (next_range == basic_block_address_space.end()) {
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

bool BasicBlockDecomposer::PopulateBasicBlockReferrers() {
  BBAddressSpace& basic_block_address_space =
      subgraph_->original_address_space();

  const BlockGraph::Block::ReferrerSet& referrers = block_->referrers();
  BlockGraph::Block::ReferrerSet::const_iterator iter = referrers.begin();
  for (; iter != referrers.end(); ++iter) {
    // Find the reference this referrer record describes.
    const BlockGraph::Block* referrer = iter->first;
    DCHECK(referrer != NULL);
    Offset source_offset = iter->second;
    BlockGraph::Reference reference;
    bool found = referrer->GetReference(source_offset, &reference);
    DCHECK(found);

    // Find the basic block the reference refers to.
    Offset target_base = reference.base();
    RangeMapIter bb_iter = basic_block_address_space.FindFirstIntersection(
        Range(target_base, 1));

    // We have complete coverage of the block; there must be an intersection.
    // And, we break up the basic blocks by code references, so the target
    // offset must coincide with the start of the target block.
    DCHECK(bb_iter != basic_block_address_space.end());
    BasicBlock* target_bb = bb_iter->second;
    DCHECK_EQ(target_base, bb_iter->first.start());
    DCHECK(target_base == reference.offset() ||
           target_bb->type() != BasicBlock::BASIC_CODE_BLOCK);

    // Add the referrer to the basic block.
    if (referrer != block_) {
      // This is an inter-block reference.
      bool inserted = target_bb->referrers().insert(
          BasicBlockReferrer(referrer, source_offset)).second;
      DCHECK(inserted);
    } else {
      // This is an intra-block reference. The referrer is a basic block.
      RangeMapIter src_bb_iter =
          basic_block_address_space.FindFirstIntersection(
              Range(source_offset, 1));
      // The reference came from this block and we have complete coverage,
      // so we must be able to find the source basic block.
      DCHECK(src_bb_iter != basic_block_address_space.end());

      // Convert the offset to one that's local to the basic block.
      BasicBlock* source_bb = src_bb_iter->second;
      Offset local_offset = source_offset - source_bb->offset();
      DCHECK_LE(0, local_offset);
      DCHECK_LE(local_offset + reference.size(), source_bb->size());

      // Insert the referrer.
      bool inserted = target_bb->referrers().insert(
          BasicBlockReferrer(source_bb, local_offset)).second;
      DCHECK(inserted);
    }
  }

  return true;
}

template<typename ItemType>
bool BasicBlockDecomposer::CopyReferences(ItemType* item) {
  DCHECK(item != NULL);

  BBAddressSpace& basic_block_address_space =
      subgraph_->original_address_space();

  // Figure out the bounds of item.
  BlockGraph::Offset start_offset = item->offset();
  BlockGraph::Offset end_offset = start_offset + item->size();

  // Get iterators encompassing all references within the bounds of item.
  BlockGraph::Block::ReferenceMap::const_iterator ref_iter =
     block_->references().lower_bound(start_offset);
  BlockGraph::Block::ReferenceMap::const_iterator end_iter =
     block_->references().upper_bound(end_offset);

  for (; ref_iter != end_iter; ++ref_iter) {
    // Calculate the local offset of this reference within item.
    BlockGraph::Offset local_offset = ref_iter->first - start_offset;
    const BlockGraph::Reference& reference = ref_iter->second;

    if (reference.referenced() == block_) {
      // For intra block_ references, find the corresponding basic block in
      // the basic block address space.
      Offset target_base = reference.base();
      RangeMapIter bb_iter = basic_block_address_space.FindFirstIntersection(
          Range(target_base, 1));

      // We have complete coverage of the block; there must be an intersection.
      // And, we break up the basic blocks by code references, so the target
      // offset must coincide with the start of the target block.
      DCHECK(bb_iter != basic_block_address_space.end());
      BasicBlock* target_bb = bb_iter->second;
      DCHECK_EQ(target_base, bb_iter->first.start());

      // Create target basic-block relative values for the base and offset.
      Offset target_offset = reference.offset() - target_base;
      target_base = 0;

      // Insert a reference to the target basic block.
      bool inserted = item->references().insert(
          std::make_pair(local_offset,
                         BasicBlockReference(reference.type(),
                                             reference.size(),
                                             target_bb,
                                             target_offset,
                                             target_base))).second;
      DCHECK(inserted);
    } else {
      // For external references, we can directly reference the other block.
      bool inserted = item->references().insert(
          std::make_pair(local_offset,
                         BasicBlockReference(reference.type(),
                                             reference.size(),
                                             reference.referenced(),
                                             reference.offset(),
                                             reference.base()))).second;
      DCHECK(inserted);
    }
  }

  return true;
}

bool BasicBlockDecomposer::PopulateBasicBlockReferences() {
  BBAddressSpace& basic_block_address_space =
      subgraph_->original_address_space();

  // Copy the references for the source range of each basic-block (by
  // instruction for code basic-blocks). The referrers and successors are
  // handled in a separate pass.
  RangeMapIter bb_iter = basic_block_address_space.begin();
  for (; bb_iter != basic_block_address_space.end(); ++bb_iter) {
    BasicBlock* bb = bb_iter->second;
    if (bb->type() == BasicBlock::BASIC_CODE_BLOCK) {
      BasicBlock::Instructions::iterator inst_iter = bb->instructions().begin();
      for (; inst_iter != bb->instructions().end(); ++inst_iter) {
        if (!CopyReferences(&(*inst_iter)))
          return false;
      }
    } else {
      if (!CopyReferences(bb_iter->second))
        return false;
    }
  }
  return true;
}

bool BasicBlockDecomposer::ResolveSuccessors() {
  BBAddressSpace& basic_block_address_space =
      subgraph_->original_address_space();

  RangeMapIter bb_iter = basic_block_address_space.begin();
  for (; bb_iter != basic_block_address_space.end(); ++bb_iter) {
    // Only code basic-blocks have successors and instructions.
    BasicBlock* bb = bb_iter->second;
    if (bb->type() != BasicBlock::BASIC_CODE_BLOCK) {
      DCHECK(bb->successors().empty());
      DCHECK(bb->instructions().empty());
      continue;
    }

    BasicBlock::Successors::iterator succ_iter = bb->successors().begin();
    BasicBlock::Successors::iterator succ_iter_end = bb->successors().end();
    for (; succ_iter != succ_iter_end; ++succ_iter) {
      if (succ_iter->branch_target().IsValid()) {
        // The branch target is already resolved; it must have been inter-block.
        DCHECK(succ_iter->branch_target().block() != block_);
        DCHECK(succ_iter->branch_target().block() != NULL);
        continue;
      }

      // Find the basic block the successor references.
      RangeMapIter bb_iter = basic_block_address_space.FindFirstIntersection(
          Range(succ_iter->bb_target_offset(), 1));
      DCHECK(bb_iter != basic_block_address_space.end());
      BasicBlock* target_bb = bb_iter->second;
      DCHECK_EQ(succ_iter->bb_target_offset(), bb_iter->first.start());

      // TODO(rogerm): It's not clear to me that BasicBlockReference objects
      //     need to track the reference type and size. We'll be re-synthesizing
      //     them later anyway, without regard for these initial values.
      succ_iter->set_branch_target(
          BasicBlockReference(BlockGraph::ABSOLUTE_REF, 4, target_bb, 0, 0));
      DCHECK(succ_iter->branch_target().IsValid());

      // TODO(rogerm): This is awkward. We want the offset of the reference if
      //     this came from a real instruction but -1 as a special sentinel if
      //     this is a synthesized branch-not-taken. But the resulting offset
      //     will actually be variable depending on how we re-synthesize the
      //     branch. For now, successors are special case in that referrers
      //     will point to the offset where the instruction would start.
      bool inserted = target_bb->referrers().insert(
          BasicBlockReferrer(bb, succ_iter->instruction_offset())).second;
      DCHECK(inserted);
    }
  }

  return true;
}

}  // namespace pe
