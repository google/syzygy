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
// Implementation of basic block disassembler.

#include "syzygy/block_graph/basic_block_disassembler.h"

#include <algorithm>
#include <vector>

#include "base/logging.h"
#include "base/stringprintf.h"
#include "syzygy/block_graph/basic_block.h"
#include "syzygy/block_graph/block_graph.h"

#include "mnemonics.h"  // NOLINT

namespace block_graph {

using core::Disassembler;

namespace {

Instruction ImplicitUnconditionalBranch(core::AbsoluteAddress target) {
  Instruction::Representation implicit_branch = {};
  implicit_branch.addr = 0;
  implicit_branch.opcode = I_JMP;
  implicit_branch.ops[0].type = O_IMM;
  implicit_branch.ops[0].size = 32;
  implicit_branch.size = sizeof(implicit_branch.opcode) + sizeof(void*);
  implicit_branch.imm.addr = target.value();
  implicit_branch.meta = FC_UNC_BRANCH;
  META_SET_ISC(&implicit_branch, ISC_INTEGER);
  return Instruction(implicit_branch, Instruction::SourceRange());
}

}  // namespace

BasicBlockDisassembler::BasicBlockDisassembler(
    const uint8* code,
    size_t code_size,
    AbsoluteAddress code_addr,
    const AddressSet& entry_points,
    const char* containing_block_name,
    InstructionCallback on_instruction) :
        Disassembler(code,
                     code_size,
                     code_addr,
                     entry_points,
                     on_instruction),
        containing_block_name_(containing_block_name),
        next_block_id_(0),
        current_block_start_(0) {
  // Initialize our jump_targets_ to our set of entry points. This will ensure
  // that any externally referenced labels are considered as basic-block
  // start points (which might be overly aggressive, but ought to ensure no
  // misses).
  AddressSet::const_iterator entry_point_iter = entry_points.begin();
  for (; entry_point_iter != entry_points.end(); ++entry_point_iter) {
    jump_targets_.insert(*entry_point_iter);
  }
}

Disassembler::CallbackDirective BasicBlockDisassembler::OnInstruction(
    AbsoluteAddress addr, const _DInst& inst) {
  current_instructions_.push_back(
      Instruction(inst, Instruction::SourceRange(addr, inst.size)));
  return kDirectiveContinue;
}

Disassembler::CallbackDirective BasicBlockDisassembler::OnBranchInstruction(
    AbsoluteAddress addr, const _DInst& inst, AbsoluteAddress dest) {
  if (dest != AbsoluteAddress(0)) {
    if (IsInBlock(dest)) {
      // If dest is inside the current macro block, then add it to the list of
      // jump sites discovered so far. At the end, if any of these jump sites
      // are into a basic block and don't correspond to the beginning of said
      // basic block, we cut the block in twain. Note that if the jump target is
      // into another block, we assume that it can only be to a label and those
      // will already be tracked.
      jump_targets_.insert(dest);
    }
  }

  CallbackDirective result = kDirectiveContinue;

  // Move the branch instruction out of the instruction list and into the
  // successor list. Then append the implicit unconditional branch to the
  // successor list.
  DCHECK(memcmp(&current_instructions_.back().representation(),
                &inst,
                sizeof(inst)) == 0);
  current_successors_.push_back(current_instructions_.back());
  current_instructions_.pop_back();


  // If this is not an unconditional branch  create an implicit unconditional
  // branch to represent the fall-through.
  if (META_GET_FC(inst.meta) != FC_UNC_BRANCH) {
    current_successors_.push_back(
        ImplicitUnconditionalBranch(addr + inst.size));
  }

  // Create the basic block. This will grab the instructions and successors.
  size_t basic_block_size = addr - current_block_start_ + inst.size;
  if (InsertBlockRange(current_block_start_,
                       basic_block_size,
                       BlockGraph::BASIC_CODE_BLOCK)) {
    current_block_start_ += basic_block_size;
  } else {
    result = kDirectiveAbort;
  }

  return result;
}

// Called every time disassembly is started from a new address. Will be
// called for at least every address in unvisited_.
Disassembler::CallbackDirective BasicBlockDisassembler::OnStartInstructionRun(
    AbsoluteAddress start_address) {
  // The address of the beginning of the current basic block.
  current_block_start_ = start_address;
  return kDirectiveContinue;
}

// Called when a walk from a given entry point has terminated or when
// a conditional branch has been found.
Disassembler::CallbackDirective BasicBlockDisassembler::OnEndInstructionRun(
    AbsoluteAddress addr, const _DInst& inst) {
  CallbackDirective result = kDirectiveContinue;

  // We've reached the end of the current walk or we handled a conditional
  // branch. Let's mark this as the end of a basic block.
  size_t basic_block_size = addr - current_block_start_ + inst.size;
  if (basic_block_size > 0) {
    // We may get an end-of-run notification on a branch instruction in which
    // case we will already have closed the block. Only close one here if we're
    // actually in a new run.
    if (InsertBlockRange(current_block_start_,
                         basic_block_size,
                         BlockGraph::BASIC_CODE_BLOCK)) {
      current_block_start_ += basic_block_size;
    } else {
      result = kDirectiveAbort;
    }
  }
  return result;
}

// Called when disassembly is complete and no further entry points remain
// to disassemble from.
Disassembler::CallbackDirective
BasicBlockDisassembler::OnDisassemblyComplete() {
  // When we get here, we should have carved out basic blocks for all visited
  // code. There are two fixups we now need to do:
  // 1) We may not have covered some ranges of the macro block. For all such
  //    ranges, build basic blocks and mark them as data. This might be wrong.
  // 2) Some basic blocks may have jump targets into them somewhere in the
  //    middle. These blocks must be broken up such that all jump targets only
  //    hit the beginning of a basic block.
  CallbackDirective result = kDirectiveContinue;

  if (!basic_block_address_space_.empty()) {
    // Fill in all the interstitials with data basic blocks, then break up the
    // basic blocks that are jumped into.
    if (!FillInGapBlocks() ||
        !SplitBlockOnJumpTargets(jump_targets_)) {
      LOG(ERROR) << "Failed to fix up basic block ranges.";
      result = kDirectiveAbort;
    }
  } else {
    // Huh, no code blocks. Add one giant "basic" block, let's call it data.
    if (!InsertBlockRange(code_addr_,
                          code_size_,
                          BlockGraph::BASIC_DATA_BLOCK)) {
      result = kDirectiveAbort;
    }
  }

#ifndef NDEBUG
  // We should now have contiguous block ranges that cover every byte in the
  // macro block. Verify that this is so.
  if (!ValidateBasicBlockCoverage()) {
    NOTREACHED() << "Incomplete basic block coverage during disassembly.";
    result = kDirectiveAbort;
  }
#endif

  return result;
}

bool BasicBlockDisassembler::ValidateBasicBlockCoverage() const {
  bool valid = true;
  AbsoluteAddress next_start(code_addr_);
  RangeMapConstIter verify_range(basic_block_address_space_.begin());
  for (; verify_range != basic_block_address_space_.end() && valid;
       ++verify_range) {
    valid = (verify_range->first.start() == next_start);
    next_start += verify_range->first.size();
  }

  if (valid) {
    valid = (next_start == code_addr_ + code_size_);
  }

  return valid;
}

bool BasicBlockDisassembler::InsertBlockRange(
    AbsoluteAddress addr, size_t size, BlockGraph::BlockType type) {
  Range range(addr, size);
  bool success = true;
  DCHECK(type == BlockGraph::BASIC_CODE_BLOCK ||
         current_instructions_.empty());
  DCHECK(type == BlockGraph::BASIC_CODE_BLOCK ||
         current_successors_.empty());
  BasicBlock new_basic_block(next_block_id_++,
                             type,
                             code_ + (addr - code_addr_),
                             size,
                             containing_block_name_.c_str());
  if (type == BlockGraph::BASIC_CODE_BLOCK) {
    new_basic_block.instructions().swap(current_instructions_);
    new_basic_block.successors().swap(current_successors_);
  }
  if (!basic_block_address_space_.Insert(range, new_basic_block)) {
    LOG(DFATAL) << "Attempted to insert overlapping basic block.";
    success = false;
  }
  return success;
}

// TODO(robertshield): This currently marks every non-walked block as data. It
// could be smarter and mark some as padding blocks as well. Fix this.
bool BasicBlockDisassembler::FillInGapBlocks() {
  bool success = true;

  // Fill in the interstitial ranges.
  RangeMapConstIter curr_range(basic_block_address_space_.begin());

  // Make sure we didn't run under.
  DCHECK(curr_range->first.start() >= code_addr_);

  // Add an initial interstitial if needed.
  if (curr_range->first.start() > code_addr_) {
    size_t interstitial_size =
        curr_range->first.start() - code_addr_;
    if (!InsertBlockRange(code_addr_,
                          interstitial_size,
                          BlockGraph::BASIC_DATA_BLOCK)) {
      LOG(ERROR) << "Failed to insert initial gap block at "
                 << code_addr_.value();
      success = false;
    }
  }

  // Handle all remaining gaps, including the end.
  for (; success && curr_range != basic_block_address_space_.end();
       ++curr_range) {
    RangeMapConstIter next_range = curr_range;
    ++next_range;
    AbsoluteAddress curr_range_end = curr_range->first.start() +
                                     curr_range->first.size();

    size_t interstitial_size = 0;
    if (next_range == basic_block_address_space_.end()) {
      DCHECK(curr_range_end <= code_addr_ + code_size_);
      interstitial_size = code_addr_ + code_size_ - curr_range_end;
    } else {
      DCHECK(curr_range_end <= next_range->first.start());
      interstitial_size = next_range->first.start() - curr_range_end;
    }

    if (interstitial_size > 0) {
      if (!InsertBlockRange(curr_range_end,
                            interstitial_size,
                            BlockGraph::BASIC_DATA_BLOCK)) {
        LOG(ERROR) << "Failed to insert gap block at "
                   << curr_range_end.value();
        success = false;
      }
    }
  }

  return success;
}

bool BasicBlockDisassembler::SplitBlockOnJumpTargets(
    const AddressSet& jump_targets) {
  bool success = true;
  AddressSet::const_iterator jump_target_iter(jump_targets_.begin());
  for (; success && jump_target_iter != jump_targets_.end();
       ++jump_target_iter) {
    Range find_range(*jump_target_iter, 1);
    RangeMapIter containing_range_iter(
        basic_block_address_space_.FindFirstIntersection(find_range));

    if (containing_range_iter == basic_block_address_space_.end()) {
      LOG(ERROR) << "Found out of bounds jump target.";
      return false;
    }

    // Two possible cases:
    //  1) We found a range that starts at the jump target.
    //  2) We found a range containing the jump target.
    if (*jump_target_iter == containing_range_iter->first.start()) {
      // If we're jumping to the start of a basic block, there isn't any work
      // to do.
    } else {
      DCHECK(*jump_target_iter >= containing_range_iter->first.start());
      DCHECK(*jump_target_iter <= containing_range_iter->first.start() +
                                  containing_range_iter->first.size());

      // Now we split up containing_range into two new ranges and replace
      // containing_range with the two new entries.
      size_t left_split_size =
          *jump_target_iter - containing_range_iter->first.start();
      BlockGraph::BlockType original_type =
          containing_range_iter->second.type();

      Range containing_range(containing_range_iter->first);
      BasicBlock original_bb(containing_range_iter->second);
      basic_block_address_space_.Remove(containing_range_iter);

      // Setup the first "half" of the basic block.
      DCHECK(current_instructions_.size() == 0);
      DCHECK(current_successors_.size() == 0);
      while (!original_bb.instructions().empty() &&
             original_bb.instructions().front().source_range().start() <
                 *jump_target_iter) {
        current_instructions_.push_back(original_bb.instructions().front());
        original_bb.instructions().pop_front();
      }

#ifndef NDEBUG
      if (!original_bb.instructions().empty()) {
        DCHECK_EQ(*jump_target_iter,
                  original_bb.instructions().front().source_range().start());
      } else {
        DCHECK(!original_bb.successors().empty());
        DCHECK_EQ(*jump_target_iter,
                  original_bb.successors().front().source_range().start());
      }
#endif
      current_successors_.push_back(
          ImplicitUnconditionalBranch(*jump_target_iter));

      if (!InsertBlockRange(containing_range.start(),
                            left_split_size,
                            original_type)) {
        LOG(ERROR) << "Failed to insert first half of split block.";
        return false;
      }

      DCHECK(current_instructions_.size() == 0);
      DCHECK(current_successors_.size() == 0);
      current_instructions_.swap(original_bb.instructions());
      current_successors_.swap(original_bb.successors());
      if (!InsertBlockRange(*jump_target_iter,
                            containing_range.size() - left_split_size,
                            original_type)) {
        LOG(ERROR) << "Failed to insert second half of split block.";
        return false;
      }
    }
  }

  return success;
}

}  // namespace block_graph
