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
// A class that attempts to disassemble a function into basic blocks.
//
// Given a function block (dubbed macro block), this disassembler attempts to
// cut it up into sequences of contiguous instruction runs and data blocks. A
// contiguous instruction run is defined as a set of instructions that under
// normal operation will always run from start to end. This class requires that
// all external references to addresses within a function block have an
// associated label.

#ifndef SYZYGY_PE_BASIC_BLOCK_DECOMPOSER_H_
#define SYZYGY_PE_BASIC_BLOCK_DECOMPOSER_H_

#include <set>
#include <string>

#include "base/basictypes.h"
#include "base/callback.h"
#include "base/string_piece.h"
#include "syzygy/block_graph/basic_block.h"
#include "syzygy/block_graph/block_graph.h"
#include "syzygy/core/address.h"
#include "syzygy/core/disassembler.h"
#include "distorm.h"  // NOLINT

namespace pe {

// This class re-disassembles an already-processed code block (referred to
// herein as a macro block) and breaks it up into basic blocks.
//
// A basic block is defined here as one of:
//
// 1) A series of code instructions that will be executed contiguously.
// 2) A chunk of data (as determined by it being labeled as such).
// 3) Padding (or unreachable code)
//
// The break-down into basic blocks happens in six passes:
//
// 1) Code disassembly starting from the block's inbound code references. This
//    carves all of the basic code blocks and creates control flow (successor)
//    relationships. While the basic blocks are being created, intra-block
//    successors cannot be resolved and are instead referenced by block offset;
//    inter-block successors are immediately resolved.
// 2) Data block construction to carve out statically embedded data.
// 3) Padding block construction to fill any gaps.
// 4) Copying all inbound references (referrers) to their corresponding
//    basic block.
// 5) Copying all references originating in the block to their corresponding
//    basic block.
// 6) Wiring up all unresolved intra-block successors.
//
// The block to be decomposed must have been produced by a successful
// PE decomposition (or some facsimile thereof).
//
// TODO(rogerm): Refactor the Disassembler interface to expose more callbacks.
//     The BasicBlockDecomposer doesn't really have an IS-A relationship with
//     the Disassembler, but inherits so as to over-ride the various event
//     handlers the Disassembler exposes to itself. Private inheritance would
//     fit nicely here, but is not allowed by the style guide. We could also
//     create an adapter class that forwards the events, but that's about the
//     same as fixing the Disassembler properly, hence this TODO.
class BasicBlockDecomposer : public core::Disassembler {
 public:
  typedef core::AbsoluteAddress AbsoluteAddress;
  typedef block_graph::BasicBlock BasicBlock;
  typedef BasicBlock::BasicBlockType BasicBlockType;
  typedef block_graph::BlockGraph BlockGraph;
  typedef BlockGraph::Offset Offset;
  typedef core::AddressSpace<Offset, size_t, BasicBlock> BBAddressSpace;

  // Creates and sets up a BasicBlockDecomposer that decomposes a function
  // macro block into basic blocks.
  // @param block The block to be disassembled
  explicit BasicBlockDecomposer(const BlockGraph::Block* block);

  // Creates and sets up a BasicBlockDecomposer that decomposes a function
  // macro block into basic blocks.
  // @param block The block to be disassembled
  // @param on_instruction Pointer to a callback routine called during
  //     disassembly.
  BasicBlockDecomposer(const BlockGraph::Block* block,
                       Disassembler::InstructionCallback on_instruction);

  bool Decompose();

  // Returns a RangeMap mapping ranges that each cover a single basic block
  // to BlockGraph::Block instances that contain some information about that
  // basic block.
  const BBAddressSpace& GetBasicBlockRanges() const {
    return basic_block_address_space_;
  }

 protected:
  // Set up the queue of addresses to disassemble from as well as the set of
  // internal jump targets. Called from the constructors.
  void InitUnvisitedAndJumpTargets();

  // Overrides from Disassembler. See syzygy/core/disassembler.h for comments.
  // @{
  virtual CallbackDirective OnInstruction(AbsoluteAddress addr,
                                          const _DInst& inst) OVERRIDE;
  virtual CallbackDirective OnBranchInstruction(AbsoluteAddress addr,
                                                const _DInst& inst,
                                                AbsoluteAddress dest) OVERRIDE;
  virtual CallbackDirective OnStartInstructionRun(
      AbsoluteAddress start_address) OVERRIDE;
  virtual CallbackDirective OnEndInstructionRun(
      AbsoluteAddress addr,
      const _DInst& inst,
      ControlFlowFlag control_flow) OVERRIDE;
  virtual CallbackDirective OnDisassemblyComplete() OVERRIDE;
  // @}

  // @name Validation functions.
  // @{

  // Verifies that basic_block_address_space_ fully covers the macro block
  // with no gaps or overlap. This is protected for unit-testing purposes.
  // This is a NOP if check_decomposition_constraints_ is false.
  void CheckHasCompleteBasicBlockCoverage() const;

  // Verifies that every identified jump target in the code resolves to the
  // start of a basic code block. This is protected for unit-testing purposes.
  // This is a NOP if check_decomposition_constraints_ is false.
  void CheckAllJumpTargetsStartABasicCodeBlock() const;

  // Verifies that all basic blocks have valid successors or end in an
  // instruction that does not yield successors. This is a NOP if
  // check_decomposition_constraints_ is false.
  void CheckAllControlFlowIsValid() const;

  // @}

  // Creates basic blocks for all known data symbols in the block.
  // @returns true on success.
  bool FillInDataBlocks();

  // Fills in all gaps in the range
  // [code_addr_, code_addr_ + code_size_[ with padding basic blocks.
  // @returns true on success.
  bool FillInPaddingBlocks();

  // Propagate the referrers from the original block into the basic blocks
  // so that referrers can be tracked as the basic blocks are manipulated.
  bool PopulateBasicBlockReferrers();

  // Helper function to populate @p item with the set of references to
  // originating from its source range in the original block. I.e., if item is
  // an instruction that occupied bytes j through k in the original block, then
  // all references found between bytes j through k of the original block will
  // be copied to the set of references tracked by @p item.
  template<typename Item>
  bool CopyReferences(Item* item);

  // Propagate the references from the original block into the basic blocks
  // so that they can be tracked as the basic blocks are manipulated.
  bool PopulateBasicBlockReferences();

  // Resolve intra-block control flow references and referrers.
  bool ResolveSuccessors();

  // Inserts a range and associated block into @p basic_block_ranges.
  bool InsertBlockRange(AbsoluteAddress addr,
                        size_t size,
                        BasicBlockType type);

  // An address space that keeps the basic block range mapping.
  BBAddressSpace basic_block_address_space_;

  // Tracks locations our conditional branches jump to. Used to fix up basic
  // blocks by breaking up those that have a jump target in the middle.
  AddressSet jump_targets_;

  // An incrementing counter used to number the temporary basic blocks as
  // they are constructed.
  int next_basic_block_id_;

  // The block being disassembled.
  const BlockGraph::Block* const block_;

  // The start of the current basic block during a walk.
  AbsoluteAddress current_block_start_;

  // The list of instructions in the current basic block.
  BasicBlock::Instructions current_instructions_;

  // The set of successors for the current basic block.
  BasicBlock::Successors current_successors_;

  // A debugging flag indicating whether the decomposition results should be
  // CHECKed.
  bool check_decomposition_results_;
};

}  // namespace pe

#endif  // SYZYGY_PE_BASIC_BLOCK_DECOMPOSER_H_
