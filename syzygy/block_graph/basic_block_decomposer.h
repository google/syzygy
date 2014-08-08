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
// A class that attempts to disassemble a function into basic blocks.
//
// Given a function block (dubbed macro block), this disassembler attempts to
// cut it up into sequences of contiguous instruction runs and data blocks. A
// contiguous instruction run is defined as a set of instructions that under
// normal operation will always run from start to end. This class requires that
// all external references to addresses within a function block have an
// associated label.

#ifndef SYZYGY_BLOCK_GRAPH_BASIC_BLOCK_DECOMPOSER_H_
#define SYZYGY_BLOCK_GRAPH_BASIC_BLOCK_DECOMPOSER_H_

#include <set>
#include <string>

#include "base/basictypes.h"
#include "base/callback.h"
#include "base/strings/string_piece.h"
#include "syzygy/block_graph/basic_block.h"
#include "syzygy/block_graph/basic_block_subgraph.h"
#include "syzygy/block_graph/block_graph.h"
#include "syzygy/core/address.h"
#include "syzygy/core/disassembler.h"
#include "distorm.h"  // NOLINT

namespace block_graph {

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
class BasicBlockDecomposer {
 public:
  typedef core::AbsoluteAddress AbsoluteAddress;
  typedef block_graph::BasicBlock BasicBlock;
  typedef BasicBlock::BasicBlockType BasicBlockType;
  typedef block_graph::BlockGraph BlockGraph;
  typedef BlockGraph::Offset Offset;
  typedef block_graph::BasicBlockSubGraph BasicBlockSubGraph;

  // Initialize the BasicBlockDecomposer instance.
  // @param block The block to be decomposed
  // @param subgraph The basic-block sub-graph data structure to populate.
  //     This can be NULL if the results of the decomposition aren't
  //     necessary.
  BasicBlockDecomposer(const BlockGraph::Block* block,
                       BasicBlockSubGraph* subgraph);

  // Decomposes a function macro block into its constituent basic blocks.
  //
  // Immediately following a successful decomposition of a block to
  // basic-blocks, subgraph will contain all the basic-blocks found in the
  // source block and exactly one block description: that of the source block.
  //
  // Following decomposition, additional block descriptions can be created,
  // new basic blocks added, and basic blocks shuffled between the descriptions.
  // The subgraph can then be coalesced back into the BlockGraph from
  // which the original block came.
  bool Decompose();

 protected:
  typedef std::map<Offset, BasicBlockReference> BasicBlockReferenceMap;
  typedef core::AddressSpace<Offset, size_t, BasicBlock*> BBAddressSpace;
  typedef BlockGraph::Block::SourceRange SourceRange;
  typedef BlockGraph::Size Size;
  typedef std::set<Offset> JumpTargets;

  // Returns the source range that coincides with the data range
  // [@p offset, [@p offset + @p size) in the original block.
  SourceRange GetSourceRange(Offset offset, Size size) const;

  // Find the basic block, and corresponding byte-range, that contains the
  // given offset.
  // @param offset the starting offset you with the returned basic-block/range
  //     to contain.
  // @param basic_block the basic-block containing @p offset.
  // @param range the byte-range in which @p basic_offset resides, which
  //     contains @p offset.
  bool FindBasicBlock(Offset offset,
                      BasicBlock** basic_block,
                      BBAddressSpace::Range* range) const;

  // Find the basic block that begins at the given offset.
  // @param offset The starting offset of the basic block you want to find.
  // @pre The basic block subgraph is derived from an original block (and
  //     thus has an address space) and has been broken down into all of its
  //     constituent basic blocks (i.e., post disassembly and basic-block
  //     splitting).
  BasicBlock* GetBasicBlockAt(Offset offset) const;

  // Helper function to end the current basic block and begin a new one
  // at @p offset. This is only to be used during disassembly.
  bool EndCurrentBasicBlock(Offset end_offset);

  // Walk the function's code in a linear fashion, decomposing the block into
  // code and data basic blocks forming an original address space.
  bool Disassemble();

  // Determines the code range of the block, and creates any data blocks. This
  // will return false if an invalid block layout is encountered.
  // @param end Will be filled in with the end of the code range.
  bool GetCodeRangeAndCreateDataBasicBlocks(Offset* end);

  // Performs an initial linear pass at disassembling the code bytes of the
  // block into rudimentary basic blocks. The initial set of basic blocks are
  // each terminated at branch points. A subsequent pass will further split
  // basic blocks at branch destinations, see SplitCodeBlocksAtBranchTargets().
  bool ParseInstructions();

  // @name Helpers for ParseInstructions().
  // @{

  // Initializes jump_targets_ to the set of referenced code locations.
  // This covers all locations which are externally referenced, as well as
  // those that are internally referenced via jump tables. These jump targets
  // may be otherwise un-discoverable through disassembly.
  // @param code_end_offset the first offset above @p code_begin_offset at
  //     which the bytes are no longer code.
  void InitJumpTargets(Offset code_end_offset);

  // Decode the bytes at @p offset into @p instruction. This function takes
  // into consideration the range of offsets which denote code.
  // @param offset The offset of into block_ at which to start decoding.
  // @param code_end_offset The offset at which the bytes cease to be code.
  // @param instruction this value will be populated on success.
  // @returns true on success; false otherwise.
  // @note Used by ParseInstructions().
  bool DecodeInstruction(Offset offset,
                         Offset code_end_offset,
                         Instruction* instruction) const;

  // Called for each instruction, this creates the Instruction object
  // corresponding to @p instruction, or terminates the current basic block
  // if @p instruction is a branch point.
  // @param instruction the decoded instruction.
  // @param offset the offset at which @p instruction occurs in the block.
  // @returns true on success; false otherwise.
  // @note Used by ParseInstructions().
  bool HandleInstruction(const Instruction& instruction, Offset offset);

  // @}

  // @name Validation functions.
  // @{
  // Verifies that every identified jump target in the original code block
  // resolves to the start of a basic code block in the original code blocks
  // basic-block address space. This is protected for unit-testing purposes.
  void CheckAllJumpTargetsStartABasicCodeBlock() const;

  // Verifies that the address space derived from the original code block
  // fully covers the original code block. This is protected for unit-testing
  // purposes.
  void CheckHasCompleteBasicBlockCoverage() const;

  // Verifies that all basic blocks in the address space derived from the
  // original code block have valid successors or end in an instruction that
  // does not yield successors.  This is protected for unit-testing purposes.
  void CheckAllControlFlowIsValid() const;

  // Verifies that all labels in the original block are present in the
  // decomposed basic-block subgraph.
  void CheckAllLabelsArePreserved() const;
  // @}

  // Split code basic-blocks at branch targets such that no basic-block
  // has a reference that it not to its head.
  void SplitCodeBlocksAtBranchTargets();

  // Propagate the referrers from the original block into the basic blocks
  // so that referrers can be tracked as the basic blocks are manipulated.
  void CopyExternalReferrers();

  // Helper function to populate @p refs with the set of references originating
  // from its source range in the original block.
  void CopyReferences(Offset item_offset,
                      Size item_size,
                      BasicBlockReferenceMap* refs);

  // Propagate the references from the original block into the basic blocks
  // so that they can be tracked as the basic blocks are manipulated.
  void CopyReferences();

  // Resolve intra-block control flow references and referrers.
  void ResolveSuccessors();

  // Convert any unreachable code basic block into padding basic blocks.
  void MarkUnreachableCodeAsPadding();

  // Inserts a basic block range into the decomposition.
  bool InsertBasicBlockRange(Offset offset,
                             size_t size,
                             BasicBlockType type);

  // The block being disassembled.
  const BlockGraph::Block* const block_;

  // The basic-block sub-graph to which the block will be decomposed.
  BasicBlockSubGraph* subgraph_;

  // The layout of the original block into basic blocks in subgraph_.
  BBAddressSpace original_address_space_;

  // Tracks locations our conditional branches jump to. Used to fix up basic
  // blocks by breaking up those that have a jump target in the middle.
  JumpTargets jump_targets_;

  // The start offset of the current basic block during a walk.
  Offset current_block_start_;

  // The list of instructions in the current basic block.
  BasicBlock::Instructions current_instructions_;

  // The set of successors for the current basic block.
  BasicBlock::Successors current_successors_;

  // A debugging flag indicating whether the decomposition results should be
  // CHECKed.
  bool check_decomposition_results_;

  // If no explicit subgraph was provided then we need to use one as scratch
  // space in order to do some work.
  scoped_ptr<BasicBlockSubGraph> scratch_subgraph_;
};

}  // namespace block_graph

#endif  // SYZYGY_BLOCK_GRAPH_BASIC_BLOCK_DECOMPOSER_H_
