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
// Implementation of the BlockBuilder class.
//
// TODO(rogerm): Revisit the BasicBlockDecomposer/BlockBuilder interface
//     via the BasicBlockSubgraph. Consider copying out the block data into
//     the subgraph instead of having it reference the original block.

#include "syzygy/block_graph/block_builder.h"

#include <limits>
#include <map>
#include <utility>
#include <vector>

#include "syzygy/block_graph/basic_block.h"
#include "syzygy/block_graph/basic_block_assembler.h"
#include "syzygy/block_graph/basic_block_subgraph.h"
#include "syzygy/block_graph/block_graph.h"
#include "syzygy/common/align.h"
#include "syzygy/core/assembler.h"

namespace block_graph {

namespace {

// A bunch of handy typedefs for some verbose types.
typedef BlockGraph::Block Block;
typedef BlockGraph::Offset Offset;
typedef BlockGraph::Size Size;
typedef BasicBlockSubGraph::BlockDescription BlockDescription;
typedef BasicBlockSubGraph::BlockDescriptionList BlockDescriptionList;
typedef BasicBlockSubGraph::BasicBlockOrdering BasicBlockOrdering;
typedef BasicBlockOrdering::const_iterator BasicBlockOrderingConstIter;
typedef BlockDescriptionList::const_iterator BlockDescriptionConstIter;
typedef BasicBlock::Instructions::const_iterator InstructionConstIter;
typedef BasicBlock::Successors::const_iterator SuccessorConstIter;

// Definitions of various length NOP codes for 32-bit X86. We use the same
// ones that are typically used by MSVC and recommended by Intel.

// NOP (XCHG EAX, EAX)
const uint8 kNop1[1] = { 0x90 };
// 66 NOP
const uint8 kNop2[2] = { 0x66, 0x90 };
// LEA REG, 0 (REG) (8-bit displacement)
const uint8 kNop3[3] = { 0x66, 0x66, 0x90 };
// NOP DWORD PTR [EAX + 0] (8-bit displacement)
const uint8 kNop4[4] = { 0x0F, 0x1F, 0x40, 0x00 };
// NOP DWORD PTR [EAX + EAX*1 + 0] (8-bit displacement)
const uint8 kNop5[5] = { 0x0F, 0x1F, 0x44, 0x00, 0x00 };
// LEA REG, 0 (REG) (32-bit displacement)
const uint8 kNop6[6] = { 0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00 };
// LEA REG, 0 (REG) (32-bit displacement)
const uint8 kNop7[7] = { 0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00 };
// NOP DWORD PTR [EAX + EAX*1 + 0] (32-bit displacement)
const uint8 kNop8[8] = { 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00 };
// NOP WORD  PTR [EAX + EAX*1 + 0] (32-bit displacement)
const uint8 kNop9[9] = { 0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00 };

// Collect all of the various NOPs in an array indexable by their length.
const uint8* kNops[] = { NULL, kNop1, kNop2, kNop3, kNop4, kNop5, kNop6,
    kNop7, kNop8, kNop9 };

const size_t kInvalidSize = -1;

// Updates the tag info map for the given taggable object.
void UpdateTagInfoMap(const TagSet& tag_set,
                      TaggedObjectType type,
                      BlockGraph::Block* block,
                      BlockGraph::Offset offset,
                      BlockGraph::Size size,
                      TagInfoMap* tag_info_map) {
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), block);
  DCHECK_NE(reinterpret_cast<TagInfoMap*>(NULL), tag_info_map);
  TagInfo tag_info(type, block, offset, size);
  TagSet::const_iterator tag_it = tag_set.begin();
  for (; tag_it != tag_set.end(); ++tag_it)
    (*tag_info_map)[*tag_it].push_back(tag_info);
}

// Checks that any BasicEndBlocks are at the end of their associated
// basic-block order.
bool EndBlocksAreWellPlaced(BasicBlockSubGraph* subgraph) {
  DCHECK_NE(reinterpret_cast<BasicBlockSubGraph*>(NULL), subgraph);

  BasicBlockSubGraph::BlockDescriptionList::iterator bd_it =
      subgraph->block_descriptions().begin();
  for (; bd_it != subgraph->block_descriptions().end(); ++bd_it) {
    BasicBlockSubGraph::BasicBlockOrdering& bbs = bd_it->basic_block_order;
    BasicBlockSubGraph::BasicBlockOrdering::iterator bb_it = bbs.begin();
    BasicBlockSubGraph::BasicBlockOrdering::iterator bb_it_end = bbs.end();
    bool end_block_seen = false;
    for (; bb_it != bb_it_end; ++bb_it) {
      if ((*bb_it)->type() == BasicBlock::BASIC_END_BLOCK) {
        end_block_seen = true;
      } else {
        // If we've already seen a basic end block and now we've encountered
        // a basic block of another type then the BB order is invalid.
        if (end_block_seen) {
          LOG(ERROR) << "Basic-block order has end-block in invalid location!";
          return false;
        }
      }
    }
  }

  return true;
}

// Adds a new label to a block, or merges a label with an existing one. This is
// used because labels may collide when creating a new block, as BasicEndBlocks
// have zero size.
void AddOrMergeLabel(BlockGraph::Offset offset,
                     const BlockGraph::Label& label,
                     BlockGraph::Block* block) {
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), block);

  BlockGraph::Label previous_label;
  if (block->GetLabel(offset, &previous_label)) {
    std::string new_name = previous_label.name() + ", " + label.name();
    BlockGraph::LabelAttributes new_attr = previous_label.attributes() |
        label.attributes();
    CHECK(block->RemoveLabel(offset));
    CHECK(block->SetLabel(offset, new_name, new_attr));
  } else {
    CHECK(block->SetLabel(offset, label));
  }
}

// A utility class to package up the context in which new blocks are generated.
class MergeContext {
 public:
  // Initialize a MergeContext with the block graph and original block.
  MergeContext(BlockGraph* bg, const Block* ob, TagInfoMap* tag_info_map)
      : sub_graph_(NULL), block_graph_(bg), original_block_(ob),
        tag_info_map_(tag_info_map) {
    DCHECK_NE(reinterpret_cast<BlockGraph*>(NULL), bg);
    DCHECK_NE(reinterpret_cast<TagInfoMap*>(NULL), tag_info_map);
  }

  // Accessor.
  const BlockVector& new_blocks() const { return new_blocks_; }

  // Generate all of the blocks described in @p subgraph.
  // @param subgraph Defines the block properties and basic blocks to use
  //     for each of the blocks to be created.
  bool GenerateBlocks(const BasicBlockSubGraph& subgraph);

  // Transfers incoming references from the original block to the
  // newly generated block or blocks.
  // @param subgraph The subgraph.
  void TransferReferrers(const BasicBlockSubGraph* subgraph) const;

  // A clean-up function to remove the original block from which @p subgraph
  // is derived (if any) from the block graph. This must only be performed
  // after having updated the block graph with the new blocks and transferred
  // all references to the new block(s).
  // @param subgraph The subgraph.
  void RemoveOriginalBlock(BasicBlockSubGraph* subgraph);

 private:
  typedef BlockGraph::Block::SourceRange SourceRange;

  // Temporary data structures used during layouting.
  // This can effectively have 3 states:
  // condition == Successor::kInvalidCondition && successor == NULL.
  //   The successor is unused.
  // condition == Successor::kInvalidCondition && successor != NULL.
  //   The successor is elided (has no representation in the block).
  // condition != Successor::kInvalidCondition && successor != NULL.
  //   The successor will have an explicit representation in the block.
  struct SuccessorLayoutInfo {
    // The condition flags for this successor.
    // Set to Successor::kInvalidCondition if unused or elided.
    Successor::Condition condition;
    // The reference this condition refers to.
    BasicBlockReference reference;
    // The size of this successor's manifestation.
    Size size;
    // A pointer to the original successor. This is used for propagating tags.
    // This is set to NULL if the successor isn't used at all.
    const Successor* successor;
  };
  struct BasicBlockLayoutInfo {
    // The basic block this layout info concerns. Useful for debugging.
    const BasicBlock* basic_block;

    // Stores the block that basic_block will be manifested in.
    Block* block;

    // Current start offset for basic_block in block.
    Offset start_offset;

    // Size of basic_block.
    Size basic_block_size;

    // The label to assign our successor(s), if any.
    BlockGraph::Label successor_label;

    // The source range this successor originally occupied, if any.
    SourceRange successor_source_range;

    // Layout info for this block's successors.
    SuccessorLayoutInfo successors[2];
  };
  typedef std::map<const BasicBlock*, BasicBlockLayoutInfo>
      BasicBlockLayoutInfoMap;

  // Update the new block with the source range for the bytes in the
  // range [new_offset, new_offset + new_size).
  // @param source_range The source range (if any) to assign.
  // @param new_offset The offset in the new block where the original bytes
  //     will now live.
  // @param new_size The number of bytes the new range occupies.
  // @param new_block The block to change.
  void CopySourceRange(const SourceRange& source_range,
                       Offset new_offset,
                       Size new_size,
                       Block* new_block);

  // Copy @p references to @p new_block, starting at @p offset.
  // @param references The references to copy.
  // @param offset The starting offset in @p new_block to copy to.
  // @param new_block The block to copy the references to.
  // @pre Layouting has been done for all referred basic blocks.
  void CopyReferences(const BasicBlock::BasicBlockReferenceMap& references,
                      Offset offset,
                      Block* new_block);

  // Assemble the instruction(s) to implement the successors in @p info.
  // @param info The layout info for the basic block in question.
  bool AssembleSuccessors(const BasicBlockLayoutInfo& info);

  // Insert NOPs into the given byte range.
  // @param offset the offset at which to insert NOPs.
  // @param bytes the number of NOP bytes to insert.
  // @param new_block the block in which to insert the NOPs.
  bool InsertNops(Offset offset, Size bytes, Block* new_block);

  // Copy the given @p instructions to the current working block.
  // @param instructions The instructions to copy.
  // @param offset The offset where the @p instructions should be inserted.
  // @param new_block the block in which to insert the instructions.
  bool CopyInstructions(const BasicBlock::Instructions& instructions,
                        Offset offset,
                        Block* new_block);

  // Copy the data (or padding bytes) in @p basic_block into new working block.
  // @param basic_block The basic_block to copy.
  // @param offset The offset where the @p basic_block should be inserted.
  // @param new_block the block in which to insert the data.
  bool CopyData(const BasicDataBlock* basic_block,
                Offset offset,
                Block* new_block);

  // Initializes layout information for @p order and stores it in layout_info_.
  // @param order The basic block ordering to process.
  // @param block The destination block for this ordering.
  bool InitializeBlockLayout(const BasicBlockOrdering& order, Block* block);

  // Generates a layout for @p order. This layout will arrange each basic block
  // in the ordering back-to-back with minimal reach encodings on each
  // successor, while respecting basic block alignments.
  // @param order The basic block ordering to process.
  bool GenerateBlockLayout(const BasicBlockOrdering& order);

  // Generates a layout for @p subgraph and stores it in layout_info_.
  // @param subgraph The subgraph to process.
  bool GenerateLayout(const BasicBlockSubGraph& subgraph);

  // Populate a new block with data and/or instructions per
  // its corresponding layout.
  // @param order their ordering.
  bool PopulateBlock(const BasicBlockOrdering& order);

  // Populate all new blocks with data and/or instructions per layout_info_.
  // @param subgraph The subgraph to process.
  bool PopulateBlocks(const BasicBlockSubGraph& subgraph);

  // Transfer all external referrers that refer to @p bb to point to
  // bb's new location instead of to the original block.
  // @param bb The basic block.
  void UpdateReferrers(const BasicBlock* bb) const;

  // Returns the minimal successor size for @p condition.
  static Size GetShortSuccessorSize(Successor::Condition condition);
  // Returns the maximal successor size for @p condition.
  static Size GetLongSuccessorSize(Successor::Condition condition);

  // Computes and returns the required successor size for @p successor.
  // @param info The layout info for the basic block.
  // @param start_offset Offset from the start of @p info.basic_block to
  //     the first byte of the successor.
  // @param successor The successor to size.
  Size ComputeRequiredSuccessorSize(const BasicBlockLayoutInfo& info,
                                    Offset start_offset,
                                    const SuccessorLayoutInfo& successor);

  // Finds the layout info for a given basic block.
  // @param bb The basic block whose layout info is desired.
  BasicBlockLayoutInfo& FindLayoutInfo(const BasicBlock* bb);
  const BasicBlockLayoutInfo& FindLayoutInfo(const BasicBlock* bb) const;

  // Resolves a basic block reference to a block reference.
  // @param type The desired type of the returned reference.
  // @param size The desired size of the returned reference.
  // @param ref The basic block reference to resolve.
  // @pre GenerateLayout has succeeded.
  BlockGraph::Reference ResolveReference(BlockGraph::ReferenceType type,
                                         Size size,
                                         const BasicBlockReference& ref) const;

  // Resolves a basic block reference to a block reference.
  // @param ref The basic block reference to resolve.
  // @pre GenerateLayout has succeeded.
  BlockGraph::Reference ResolveReference(const BasicBlockReference& ref) const;

 private:
  // The subgraph we're layouting.
  const BasicBlockSubGraph* sub_graph_;

  // Layout info.
  BasicBlockLayoutInfoMap layout_info_;

  // The block graph in which the new blocks are generated.
  BlockGraph* const block_graph_;

  // The original block from which the new blocks are derived.
  const Block* original_block_;

  // The tag info map tracking all user data in the subgraph.
  TagInfoMap* tag_info_map_;

  // The set of blocks generated in this context so far.
  BlockVector new_blocks_;

  DISALLOW_COPY_AND_ASSIGN(MergeContext);
};

bool MergeContext::GenerateBlocks(const BasicBlockSubGraph& subgraph) {
  sub_graph_ = &subgraph;

  if (!GenerateLayout(subgraph) || !PopulateBlocks(subgraph)) {
    // Remove generated blocks (this is safe as they're all disconnected)
    // and return false.
    BlockVector::iterator it = new_blocks_.begin();
    for (; it != new_blocks_.end(); ++it) {
      DCHECK((*it)->referrers().empty());
      DCHECK((*it)->references().empty());
      block_graph_->RemoveBlock(*it);
    }
    new_blocks_.clear();

    sub_graph_ = NULL;
    return false;
  }

  sub_graph_ = NULL;
  return true;
}

void MergeContext::TransferReferrers(const BasicBlockSubGraph* subgraph) const {
  // Iterate through the layout info, and update each referenced BB.
  BasicBlockLayoutInfoMap::const_iterator it = layout_info_.begin();
  for (; it != layout_info_.end(); ++it)
    UpdateReferrers(it->second.basic_block);
}

void MergeContext::CopySourceRange(const SourceRange& source_range,
                                   Offset new_offset,
                                   Size new_size,
                                   Block* new_block) {
  DCHECK_LE(0, new_offset);
  DCHECK_NE(0U, new_size);

  // If the range is empty, there's nothing to do.
  if (source_range.size() == 0)
    return;

  // Insert the new source range mapping into the new block.
  bool inserted = new_block->source_ranges().Insert(
      Block::DataRange(new_offset, new_size), source_range);
  DCHECK(inserted);
}

bool MergeContext::AssembleSuccessors(const BasicBlockLayoutInfo& info) {
  BasicBlock::Instructions instructions;
  BasicBlockAssembler assm(info.start_offset + info.basic_block_size,
                           instructions.begin(), &instructions);

  // Copy the successor label, if any, to where it belongs.
  if (info.successor_label.IsValid()) {
    AddOrMergeLabel(info.start_offset + info.basic_block_size,
                    info.successor_label,
                    info.block);
  }

  Offset successor_start = info.start_offset + info.basic_block_size;
  for (size_t i = 0; i < arraysize(info.successors); ++i) {
    const SuccessorLayoutInfo& successor = info.successors[i];

    // Exit loop early if appropriate.
    if (successor.condition == Successor::kInvalidCondition &&
        successor.successor == NULL) {
      break;
    }

    // A pointer to the original successor should always be set for any
    // manifested or elided successor.
    DCHECK_NE(reinterpret_cast<Successor*>(NULL), successor.successor);

    // If this represents an elided successor then simply emit tag information
    // and continue.
    if (successor.condition == Successor::kInvalidCondition) {
      // Update the tag-info map for the successor.
      UpdateTagInfoMap(successor.successor->tags(), kSuccessorTag, info.block,
                       successor_start, 0, tag_info_map_);
      UpdateTagInfoMap(successor.successor->reference().tags(),
                       kReferenceTag, info.block, successor_start, 0,
                       tag_info_map_);
      continue;
    }

    // Default to a short reference.
    ValueSize reference_size = core::kSize8Bit;
    if (successor.size != GetShortSuccessorSize(successor.condition))
      reference_size = core::kSize32Bit;

    // Construct the reference we're going to deposit into the instruction
    // list first.
    UntypedReference untyped_ref(successor.reference);

    // For debugging, we stomp the correct offset into the re-generated block
    // for block-internal references.
    BlockGraph::Reference resolved_ref = ResolveReference(successor.reference);

    // Default to the offset immediately following the successor, which
    // will translate to a zero pc-relative offset.
    Offset ref_offset = successor_start + successor.size;
    if (resolved_ref.referenced() == info.block)
      ref_offset = resolved_ref.offset();
    Immediate dest(ref_offset, reference_size, untyped_ref);

    // Assemble the instruction.
    switch (successor.condition) {
      case Successor::kConditionAbove:
      case Successor::kConditionAboveOrEqual:
      case Successor::kConditionBelow:
      case Successor::kConditionBelowOrEqual:
      case Successor::kConditionEqual:
      case Successor::kConditionGreater:
      case Successor::kConditionGreaterOrEqual:
      case Successor::kConditionLess:
      case Successor::kConditionLessOrEqual:
      case Successor::kConditionNotEqual:
      case Successor::kConditionNotOverflow:
      case Successor::kConditionNotParity:
      case Successor::kConditionNotSigned:
      case Successor::kConditionOverflow:
      case Successor::kConditionParity:
      case Successor::kConditionSigned:
        assm.j(static_cast<core::ConditionCode>(successor.condition), dest);
        break;

      case Successor::kConditionTrue:
        assm.jmp(dest);
        break;

      default:
        NOTREACHED();
        return false;
    }

    // Make sure the assembler produced what we expected.
    DCHECK_EQ(successor.size, instructions.back().size());
    DCHECK_EQ(1u, instructions.back().references().size());

    // Copy the tags that are associated with the successor reference to the
    // appropriately sized instruction reference. CopyInstructions will then
    // take care of updating the tag info map.
    instructions.back().references().begin()->second.tags() =
        successor.reference.tags();

    // Update the tag-info map for the successor.
    UpdateTagInfoMap(successor.successor->tags(), kSuccessorTag, info.block,
                     successor_start, successor.size, tag_info_map_);

    // Walk our start address forwards.
    successor_start += successor.size;

    if (info.successor_source_range.size() != 0) {
      Instruction& instr = instructions.back();

      // Attribute this instruction to the original successor's source range.
      instr.set_source_range(info.successor_source_range);
    }
  }

  if (!instructions.empty()) {
    Offset start_offset = info.start_offset + info.basic_block_size;
    return CopyInstructions(instructions, start_offset, info.block);
  }

  return true;
}

bool MergeContext::InsertNops(Offset offset, Size bytes, Block* new_block) {
  DCHECK_NE(reinterpret_cast<Block*>(NULL), new_block);

  uint8* buffer = new_block->GetMutableData();
  DCHECK_NE(reinterpret_cast<uint8*>(NULL), buffer);

  size_t kMaxNopLength = arraysize(kNops) - 1;
  buffer += offset;
  while (bytes >= kMaxNopLength) {
    ::memcpy(buffer, kNops[kMaxNopLength], kMaxNopLength);
    buffer += kMaxNopLength;
    bytes -= kMaxNopLength;
  }

  if (bytes > 0) {
    DCHECK_GT(kMaxNopLength, bytes);
    ::memcpy(buffer, kNops[bytes], bytes);
  }

  return true;
}

bool MergeContext::CopyInstructions(
    const BasicBlock::Instructions& instructions,
    Offset offset, Block* new_block) {
  DCHECK_NE(reinterpret_cast<Block*>(NULL), new_block);
  DCHECK_EQ(BasicBlock::BASIC_CODE_BLOCK, new_block->type());
  // Get the target buffer.
  uint8* buffer = new_block->GetMutableData();
  DCHECK_NE(reinterpret_cast<uint8*>(NULL), buffer);

  // Copy the instruction data and assign each instruction an offset.
  InstructionConstIter it = instructions.begin();
  for (; it != instructions.end(); ++it) {
    const Instruction& instruction = *it;

    // Update the tag-info map for the instruction.
    UpdateTagInfoMap(instruction.tags(), kInstructionTag, new_block,
                     offset, instruction.size(), tag_info_map_);

    // Copy the instruction bytes.
    ::memcpy(buffer + offset, instruction.data(), instruction.size());

    // Preserve the label on the instruction, if any.
    if (instruction.has_label())
      AddOrMergeLabel(offset, instruction.label(), new_block);

    // Record the source range.
    CopySourceRange(instruction.source_range(),
                    offset, instruction.size(),
                    new_block);

    // Copy references.
    CopyReferences(instruction.references(), offset, new_block);

    // Update the offset/bytes_written.
    offset += instruction.size();
  }

  return true;
}

void MergeContext::CopyReferences(
    const BasicBlock::BasicBlockReferenceMap& references,
    Offset offset, Block* new_block) {
  BasicBlock::BasicBlockReferenceMap::const_iterator it = references.begin();
  for (; it != references.end(); ++it) {
    BlockGraph::Reference resolved = ResolveReference(it->second);

    Offset ref_offset = offset + it->first;
    CHECK(new_block->SetReference(ref_offset, resolved));

    // Update the tag-info map for this reference.
    UpdateTagInfoMap(it->second.tags(), kReferenceTag, new_block, ref_offset,
                     resolved.size(), tag_info_map_);
  }
}

bool MergeContext::CopyData(const BasicDataBlock* data_block,
                            Offset offset,
                            Block* new_block) {
  DCHECK_NE(reinterpret_cast<BasicDataBlock*>(NULL), data_block);
  DCHECK_EQ(BasicBlock::BASIC_DATA_BLOCK, data_block->type());

  // Get the target buffer.
  uint8* buffer = new_block->GetMutableData();
  DCHECK_NE(reinterpret_cast<uint8*>(NULL), buffer);

  // Copy the basic-new_block_'s data bytes.
  ::memcpy(buffer + offset, data_block->data(), data_block->size());

  // Record the source range.
  CopySourceRange(data_block->source_range(),
                  offset, data_block->size(),
                  new_block);

  CopyReferences(data_block->references(), offset, new_block);
  return true;
}

bool MergeContext::InitializeBlockLayout(const BasicBlockOrdering& order,
                                         Block* new_block) {
  // Populate the initial layout info.
  BasicBlockOrderingConstIter it = order.begin();
  for (; it != order.end(); ++it) {
    const BasicBlock* bb = *it;

    // Propagate BB alignment to the parent block.
    if (bb->alignment() > new_block->alignment())
      new_block->set_alignment(bb->alignment());

    // Create and initialize the layout info for this block.
    DCHECK(layout_info_.find(bb) == layout_info_.end());

    BasicBlockLayoutInfo& info = layout_info_[bb];
    info.basic_block = bb;
    info.block = new_block;
    info.start_offset = 0;
    info.basic_block_size = kInvalidSize;

    const BasicCodeBlock* code_block = BasicCodeBlock::Cast(bb);
    if (code_block != NULL)
      info.basic_block_size = code_block->GetInstructionSize();

    const BasicDataBlock* data_block = BasicDataBlock::Cast(bb);
    if (data_block != NULL)
      info.basic_block_size = data_block->size();

    const BasicEndBlock* end_block = BasicEndBlock::Cast(bb);
    if (end_block != NULL)
      info.basic_block_size = end_block->size();

    // The size must have been set.
    DCHECK_NE(kInvalidSize, info.basic_block_size);

    for (size_t i = 0; i < arraysize(info.successors); ++i) {
      info.successors[i].condition = Successor::kInvalidCondition;
      info.successors[i].size = 0;
      info.successors[i].successor = NULL;
    }

    // Find the next basic block, if any.
    BasicBlockOrderingConstIter next_it(it);
    ++next_it;
    const BasicBlock* next_bb = NULL;
    if (next_it != order.end())
      next_bb = *(next_it);

    if (code_block == NULL)
      continue;

    // Go through and decide how to manifest the successors for the current
    // basic block. A basic block has zero, one or two successors, and any
    // successor that refers to the next basic block in sequence is elided, as
    // it's most efficient for execution to simply fall through. We do this in
    // two nearly-identical code blocks, as the handling is only near-identical
    // for each of two possible successors.
    DCHECK_GE(2U, code_block->successors().size());
    SuccessorConstIter succ_it = code_block->successors().begin();
    SuccessorConstIter succ_end = code_block->successors().end();

    // Process the first successor, if any.
    size_t manifested_successors = 0;
    size_t elided_successors = 0;
    if (succ_it != succ_end) {
      const BasicBlock* destination_bb = succ_it->reference().basic_block();

      // Record the source range of the original successor.
      if (succ_it->source_range().size() != 0) {
        DCHECK_EQ(0U, info.successor_source_range.size());
        info.successor_source_range = succ_it->source_range();
      }
      // Record the label of the original successor.
      if (succ_it->has_label())
        info.successor_label = succ_it->label();

      // Only manifest this successor if it's not referencing the next block.
      SuccessorLayoutInfo& successor =
          info.successors[manifested_successors + elided_successors];
      successor.successor = &(*succ_it);
      if (destination_bb == NULL || destination_bb != next_bb) {
        ++manifested_successors;
        successor.condition = succ_it->condition();
        successor.reference = succ_it->reference();
      } else {
        ++elided_successors;
      }

      // Go to the next successor, if any.
      ++succ_it;
    }

    // Process the second successor, if any.
    if (succ_it != succ_end) {
      const BasicBlock* destination_bb = succ_it->reference().basic_block();

      // Record the source range of the original successor.
      if (succ_it->source_range().size() != 0) {
        DCHECK_EQ(0U, info.successor_source_range.size());
        info.successor_source_range = succ_it->source_range();
      }
      // Record the label of the original successor.
      if (succ_it->has_label()) {
        DCHECK(!info.successor_label.IsValid());
        info.successor_label = succ_it->label();
      }

      // Only manifest this successor if it's not referencing the next block.
      SuccessorLayoutInfo& successor =
          info.successors[manifested_successors + elided_successors];
      successor.successor = &(*succ_it);
      if (destination_bb == NULL || destination_bb != next_bb) {
        Successor::Condition condition = succ_it->condition();

        // If we've already manifested a successor above, it'll be for the
        // complementary condition to ours. While it's correct to manifest it
        // as a conditional branch, it's more efficient to manifest as an
        // unconditional jump.
        if (manifested_successors != 0) {
          DCHECK_EQ(Successor::InvertCondition(info.successors[0].condition),
                    succ_it->condition());

          condition = Successor::kConditionTrue;
        }

        ++manifested_successors;

        successor.condition = condition;
        successor.reference = succ_it->reference();
      } else {
        ++elided_successors;
      }
    }

    // A basic-block can have at most 2 successors by definition. Since we emit
    // a successor layout struct for each one (whether or not its elided), we
    // expect there to have been as many successors emitted as there are
    // successors in the basic block itself.
    DCHECK_GE(arraysize(info.successors),
              manifested_successors + elided_successors);
    DCHECK_EQ(code_block->successors().size(),
              manifested_successors + elided_successors);
  }

  return true;
}

bool MergeContext::GenerateBlockLayout(const BasicBlockOrdering& order) {
  BasicBlockOrderingConstIter it = order.begin();

  // Loop over the layout, expanding successors until stable.
  while (true) {
    bool expanded_successor = false;

    // Update the start offset for each of the BBs, respecting the BB alignment
    // constraints.
    it = order.begin();
    Offset next_block_start = 0;
    Block* new_block = NULL;
    for (; it != order.end(); ++it) {
      BasicBlockLayoutInfo& info = FindLayoutInfo(*it);
      next_block_start = common::AlignUp(next_block_start,
                                         info.basic_block->alignment());
      info.start_offset = next_block_start;

      if (new_block == NULL)
        new_block = info.block;
      DCHECK(new_block == info.block);

      next_block_start += info.basic_block_size +
                          info.successors[0].size +
                          info.successors[1].size;
    }

    // See whether there's a need to expand the successor sizes.
    it = order.begin();
    for (; it != order.end(); ++it) {
      const BasicBlock* bb = *it;
      BasicBlockLayoutInfo& info = FindLayoutInfo(bb);

      // Compute the start offset for this block's first successor.
      Offset start_offset = info.start_offset + info.basic_block_size;
      for (size_t i = 0; i < arraysize(info.successors); ++i) {
        SuccessorLayoutInfo& successor = info.successors[i];

        // Exit the loop if this (and possibly the subsequent) successor
        // is un-manifested.
        if (successor.condition == Successor::kInvalidCondition &&
            successor.successor == NULL) {
          break;
        }

        // Skip over elided successors.
        DCHECK_NE(reinterpret_cast<Successor*>(NULL), successor.successor);
        if (successor.condition == Successor::kInvalidCondition)
          continue;

        // Compute the new size and update the start offset for the next
        // successor (if any).
        Size new_size =
            ComputeRequiredSuccessorSize(info, start_offset, successor);
        start_offset += new_size;

        // Keep the biggest offset used by this jump. A jump may temporarily
        // appear shorter when the start offset of this basic block has moved
        // but the offset of the target basic block still needs to be updated
        // within this iteration.
        new_size = std::max(successor.size, new_size);

        // Check whether we're expanding this successor.
        if (new_size != successor.size) {
          successor.size = new_size;
          expanded_successor = true;
        }
      }
    }

    if (!expanded_successor) {
      // We've achieved a stable layout and we know that next_block_start
      // is the size of the new block, so resize it and allocate the data now.
      new_block->set_size(next_block_start);
      new_block->AllocateData(next_block_start);

      return true;
    }
  }
}

bool MergeContext::GenerateLayout(const BasicBlockSubGraph& subgraph) {
  // Create each new block and initialize a layout for it.
  BlockDescriptionConstIter it = subgraph.block_descriptions().begin();
  for (; it != subgraph.block_descriptions().end(); ++it) {
    const BlockDescription& description = *it;

    // Skip the block if it's empty.
    if (description.basic_block_order.empty())
      continue;

    Block* new_block = block_graph_->AddBlock(
        description.type, 0, description.name);
    if (new_block == NULL) {
      LOG(ERROR) << "Failed to create block '" << description.name << "'.";
      return false;
    }

    // Save this block in the set of newly generated blocks. On failure, this
    // list will be used by GenerateBlocks() to clean up after itself.
    new_blocks_.push_back(new_block);

    // Initialize the new block's properties.
    new_block->set_alignment(description.alignment);
    new_block->set_section(description.section);
    new_block->set_attributes(description.attributes);

    // Initialize the layout for this block.
    if (!InitializeBlockLayout(description.basic_block_order, new_block)) {
      LOG(ERROR) << "Failed to initialize layout for basic block '" <<
          description.name << "'";
      return false;
    }
  }

  // Now generate a layout for each ordering.
  it = subgraph.block_descriptions().begin();
  for (; it != subgraph.block_descriptions().end(); ++it) {
    const BlockDescription& description = *it;

    // Skip the block if it's empty.
    if (description.basic_block_order.empty())
      continue;

    // Generate the layout for this block.
    if (!GenerateBlockLayout(description.basic_block_order)) {
      LOG(ERROR) << "Failed to generate a layout for basic block '" <<
          description.name << "'";
      return false;
    }
  }

  return true;
}

bool MergeContext::PopulateBlock(const BasicBlockOrdering& order) {
  // Populate the new block with basic blocks.
  BasicBlockOrderingConstIter bb_iter = order.begin();
  BasicBlockOrderingConstIter bb_end = order.end();

  BlockGraph::Offset prev_offset = 0;

  for (; bb_iter != bb_end; ++bb_iter) {
    const BasicBlock* bb = *bb_iter;
    const BasicBlockLayoutInfo& info = FindLayoutInfo(bb);

    // Determine the tag type and size associated with this basic block.
    TaggedObjectType tag_type = kBasicDataBlockTag;
    size_t tag_size = info.basic_block_size;
    if (bb->type() == BasicBlock::BASIC_CODE_BLOCK) {
      // We include the size of the successors if its a basic code block.
      tag_type = kBasicCodeBlockTag;
      for (size_t i = 0; i < arraysize(info.successors); ++i) {
        if (info.successors[i].condition != Successor::kInvalidCondition)
          tag_size += info.successors[i].size;
      }
    }

    // Update the tag-info map for the basic block.
    UpdateTagInfoMap(bb->tags(), tag_type, info.block, info.start_offset,
                     tag_size, tag_info_map_);

    // Handle any padding for alignment.
    if (info.start_offset > prev_offset) {
      if (!InsertNops(prev_offset, info.start_offset - prev_offset,
                      info.block)) {
        LOG(ERROR) << "Failed to insert NOPs for '" << bb->name() << "'.";
        return false;
      }
    }
    prev_offset = info.start_offset + info.basic_block_size +
        info.successors[0].size + info.successors[1].size;

    // Handle data basic blocks.
    const BasicDataBlock* data_block = BasicDataBlock::Cast(bb);
    if (data_block != NULL) {
      // If the basic-block is labeled, copy the label.
      if (data_block->has_label())
        AddOrMergeLabel(info.start_offset, data_block->label(), info.block);

      // Copy its data.
      if (!CopyData(data_block, info.start_offset, info.block)) {
        LOG(ERROR) << "Failed to copy data for '" << bb->name() << "'.";
        return false;
      }
    }

    // Handle code basic blocks.
    const BasicCodeBlock* code_block = BasicCodeBlock::Cast(bb);
    if (code_block != NULL) {
      // Copy the instructions.
      if (!CopyInstructions(code_block->instructions(),
                            info.start_offset,
                            info.block)) {
        LOG(ERROR) << "Failed to copy instructions for '" << bb->name() << "'.";
        return false;
      }

      // Synthesize the successor instructions and assign each to an offset.
      if (!AssembleSuccessors(info)) {
        LOG(ERROR) << "Failed to create successors for '" << bb->name() << "'.";
        return false;
      }
    }

    const BasicEndBlock* end_block = BasicEndBlock::Cast(bb);
    if (end_block != NULL) {
      // If the end block is labeled, copy the label.
      if (end_block->has_label())
        AddOrMergeLabel(info.start_offset, end_block->label(), info.block);
    }

    // We must have handled the basic block as at least one of the fundamental
    // types.
    DCHECK(code_block != NULL || data_block != NULL || end_block != NULL);
  }

  return true;
}

bool MergeContext::PopulateBlocks(const BasicBlockSubGraph& subgraph) {
  // Create each new block and generate a layout for it.
  BlockDescriptionConstIter it = subgraph.block_descriptions().begin();
  for (; it != subgraph.block_descriptions().end(); ++it) {
    const BasicBlockOrdering& order = it->basic_block_order;

    // Skip the block if it's empty.
    if (order.empty())
      continue;

    if (!PopulateBlock(order))
      return false;
  }

  return true;
}

void MergeContext::UpdateReferrers(const BasicBlock* bb) const {
  DCHECK_NE(reinterpret_cast<BasicBlock*>(NULL), bb);

  // Find the current location of this basic block.
  BasicBlockLayoutInfoMap::const_iterator layout_it = layout_info_.find(bb);
  DCHECK(layout_it != layout_info_.end());
  const BasicBlockLayoutInfo& info = layout_it->second;
  DCHECK_EQ(bb, info.basic_block);

  // Update all external referrers to point to the new location.
  const BasicBlock::BasicBlockReferrerSet& referrers = bb->referrers();
  BasicBlock::BasicBlockReferrerSet::const_iterator it = referrers.begin();
  for (; it != referrers.end(); ++it) {
    // Get a non-const pointer to the referring block. Note that we don't
    // modify the set property on referrers as we update the block's references.
    const BasicBlockReferrer& referrer = *it;
    Block* referring_block = const_cast<Block*>(referrer.block());
    BlockGraph::Reference old_ref;
    bool found = referring_block->GetReference(referrer.offset(), &old_ref);
    DCHECK(found);

    // The base of the reference is directed to the corresponding BB's
    // start address in the new block.
    BlockGraph::Reference new_ref(old_ref.type(),
                                  old_ref.size(),
                                  info.block,
                                  info.start_offset,
                                  info.start_offset);

    bool is_new = referring_block->SetReference(referrer.offset(), new_ref);
    DCHECK(!is_new);  // TODO(rogerm): Is this a valid DCHECK?
  }
}

void MergeContext::RemoveOriginalBlock(BasicBlockSubGraph* subgraph) {
  DCHECK_NE(reinterpret_cast<BasicBlockSubGraph*>(NULL), subgraph);
  DCHECK_EQ(original_block_, subgraph->original_block());

  Block* original_block = const_cast<Block*>(this->original_block_);
  if (original_block == NULL)
    return;

  DCHECK(!original_block->HasExternalReferrers());

  bool removed = original_block->RemoveAllReferences();
  DCHECK(removed);

  removed = block_graph_->RemoveBlock(original_block);
  DCHECK(removed);

  subgraph->set_original_block(NULL);
  original_block_ = NULL;
}

Size MergeContext::GetShortSuccessorSize(Successor::Condition condition) {
  switch (condition) {
    case Successor::kConditionAbove:
    case Successor::kConditionAboveOrEqual:
    case Successor::kConditionBelow:
    case Successor::kConditionBelowOrEqual:
    case Successor::kConditionEqual:
    case Successor::kConditionGreater:
    case Successor::kConditionGreaterOrEqual:
    case Successor::kConditionLess:
    case Successor::kConditionLessOrEqual:
    case Successor::kConditionNotEqual:
    case Successor::kConditionNotOverflow:
    case Successor::kConditionNotParity:
    case Successor::kConditionNotSigned:
    case Successor::kConditionOverflow:
    case Successor::kConditionParity:
    case Successor::kConditionSigned:
      // Translates to a conditional branch.
      return core::AssemblerImpl::kShortBranchSize;

    case Successor::kConditionTrue:
      // Translates to a jump.
      return core::AssemblerImpl::kShortJumpSize;

    default:
      NOTREACHED() << "Unsupported successor type.";
      return 0;
  }
}

Size MergeContext::GetLongSuccessorSize(Successor::Condition condition) {
  switch (condition) {
    case Successor::kConditionAbove:
    case Successor::kConditionAboveOrEqual:
    case Successor::kConditionBelow:
    case Successor::kConditionBelowOrEqual:
    case Successor::kConditionEqual:
    case Successor::kConditionGreater:
    case Successor::kConditionGreaterOrEqual:
    case Successor::kConditionLess:
    case Successor::kConditionLessOrEqual:
    case Successor::kConditionNotEqual:
    case Successor::kConditionNotOverflow:
    case Successor::kConditionNotParity:
    case Successor::kConditionNotSigned:
    case Successor::kConditionOverflow:
    case Successor::kConditionParity:
    case Successor::kConditionSigned:
      // Translates to a conditional branch.
      return core::AssemblerImpl::kLongBranchSize;

    case Successor::kConditionTrue:
      // Translates to a jump.
      return core::AssemblerImpl::kLongJumpSize;

    default:
      NOTREACHED() << "Unsupported successor type.";
      return 0;
  }
}

Size MergeContext::ComputeRequiredSuccessorSize(
    const BasicBlockLayoutInfo& info,
    Offset start_offset,
    const SuccessorLayoutInfo& successor) {
  switch (successor.reference.referred_type()) {
    case BasicBlockReference::REFERRED_TYPE_BLOCK:
      return GetLongSuccessorSize(successor.condition);

    case BasicBlockReference::REFERRED_TYPE_BASIC_BLOCK: {
      Size short_size = GetShortSuccessorSize(successor.condition);
      const BasicBlock* dest_bb = successor.reference.basic_block();
      DCHECK_NE(reinterpret_cast<BasicBlock*>(NULL), dest_bb);
      const BasicBlockLayoutInfo& dest = FindLayoutInfo(dest_bb);

      // If the destination is within the same destination block,
      // let's see if we can use a short reach here.
      if (info.block == dest.block) {
        Offset destination_offset =
            dest.start_offset - (start_offset + short_size);

        // Are we in-bounds for a short reference?
        if (destination_offset <= std::numeric_limits<int8>::max() &&
            destination_offset >= std::numeric_limits<int8>::min()) {
          return short_size;
        }
      }

      return GetLongSuccessorSize(successor.condition);
    }

    default:
      NOTREACHED() << "Impossible Successor reference type.";
      return 0;
  }
}

MergeContext::BasicBlockLayoutInfo& MergeContext::FindLayoutInfo(
    const BasicBlock* bb) {
  BasicBlockLayoutInfoMap::iterator it = layout_info_.find(bb);
  DCHECK(it != layout_info_.end());
  DCHECK_EQ(bb, it->second.basic_block);

  return it->second;
}

const MergeContext::BasicBlockLayoutInfo& MergeContext::FindLayoutInfo(
    const BasicBlock* bb) const {
  BasicBlockLayoutInfoMap::const_iterator it = layout_info_.find(bb);
  DCHECK(it != layout_info_.end());
  DCHECK_EQ(bb, it->second.basic_block);

  return it->second;
}

BlockGraph::Reference MergeContext::ResolveReference(
    BlockGraph::ReferenceType type, Size size,
    const BasicBlockReference& ref) const {
  if (ref.referred_type() == BasicBlockReference::REFERRED_TYPE_BASIC_BLOCK) {
    // It's a basic block reference, we need to resolve it to a
    // block reference.
    const BasicBlockLayoutInfo& info = FindLayoutInfo(ref.basic_block());

    return BlockGraph::Reference(type,
                                 size,
                                 info.block,
                                 info.start_offset,
                                 info.start_offset);
  } else {
    DCHECK_EQ(BasicBlockReference::REFERRED_TYPE_BLOCK, ref.referred_type());
    DCHECK_NE(ref.block(), original_block_);

    return BlockGraph::Reference(type,
                                 size,
                                 const_cast<Block*>(ref.block()),
                                 ref.offset(),
                                 ref.base());
  }
}

BlockGraph::Reference MergeContext::ResolveReference(
    const BasicBlockReference& ref) const {
  return ResolveReference(ref.reference_type(), ref.size(), ref);
}

}  // namespace

BlockBuilder::BlockBuilder(BlockGraph* bg) : block_graph_(bg) {
}

bool BlockBuilder::Merge(BasicBlockSubGraph* subgraph) {
  DCHECK_NE(reinterpret_cast<BasicBlockSubGraph*>(NULL), subgraph);

  // Before starting the layout ensure any BasicEndBlocks are at the end of/
  // their respective basic-block orderings.
  if (!EndBlocksAreWellPlaced(subgraph))
    return false;

  MergeContext context(block_graph_,
                       subgraph->original_block(),
                       &tag_info_map_);

  if (!context.GenerateBlocks(*subgraph))
    return false;

  context.TransferReferrers(subgraph);
  context.RemoveOriginalBlock(subgraph);

  // Track the newly created blocks.
  new_blocks_.reserve(new_blocks_.size() + context.new_blocks().size());
  new_blocks_.insert(new_blocks_.end(),
                     context.new_blocks().begin(),
                     context.new_blocks().end());

  // And we're done.
  return true;
}

}  // namespace block_graph
