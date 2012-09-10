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

#include <map>
#include <utility>
#include <vector>

#include "syzygy/block_graph/basic_block.h"
#include "syzygy/block_graph/basic_block_subgraph.h"
#include "syzygy/block_graph/block_graph.h"
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

// A helper class to track the location to which a block element (a basic-block,
// instruction, or successor reference) has been mapped.
class LocationMap {
 public:
  // Remember the location of the given @p obj in the current context.
  // @param obj The object to remember.
  // @param b The block in which @p obj was placed.
  // @param n The offset in @p b at which @p obj was placed.
  // Returns false if the @p obj has already been assigned a location.
  bool Add(const void* obj, Block* b, Offset n) {
    DCHECK(obj != NULL);
    DCHECK(b != NULL);
    DCHECK_LE(0, n);
    return map_.insert(std::make_pair(obj, std::make_pair(b, n))).second;
  }

  // Find the location of the given @p object in the current context.
  // @param obj The object to find.
  // @param b The block in which @p object was place is returned here.
  // @param n The offset in @p b at which @p obj was placed is returned here.
  // Returns false if the object is not found.
  bool Find(const void* obj, Block** b, Offset* n) const {
    DCHECK(obj != NULL);
    DCHECK(b != NULL);
    DCHECK(n != NULL);
    Map::const_iterator loc_iter = map_.find(obj);
    if (loc_iter == map_.end())
      return false;
    *b = loc_iter->second.first;
    *n = loc_iter->second.second;
    return true;
  }

  // Returns the final block reference corresponding to a basic-block reference.
  BlockGraph::Reference Resolve(const BasicBlockReference& bb_ref) const {
    if (bb_ref.block() != NULL) {
      return BlockGraph::Reference(bb_ref.reference_type(), bb_ref.size(),
                                   const_cast<Block*>(bb_ref.block()),
                                   bb_ref.offset(),
                                   bb_ref.base());
    }

    DCHECK(bb_ref.basic_block() != NULL);
    DCHECK_EQ(0, bb_ref.base());

    Block* block = NULL;
    Offset base = 0;
    bool found = Find(bb_ref.basic_block(), &block, &base);
    DCHECK(found);

    return BlockGraph::Reference(bb_ref.reference_type(), bb_ref.size(), block,
                                 base + bb_ref.offset(), base);
  }

 private:
  // The underlying data structures.
  typedef std::pair<Block*, Offset> Location;
  typedef std::map<const void*, Location> Map;
  Map map_;
};

// A utility structure to package up the context in which a new block is
// generated. This reduces the amount of context parameters being passed
// around from call to call.
class MergeContext {
 public:
  // Initialize a MergeContext with the block graph and original block.
  MergeContext(BlockGraph* bg, const Block* ob)
      : block_graph_(bg), original_block_(ob), new_block_(NULL), offset_(0) {
    DCHECK(bg != NULL);
  }

  // Accessor.
  const BlockVector& new_blocks() const { return new_blocks_; }

  // Generate all of the blocks described in @p subgraph.
  // @param subgraph Defines the block properties and basic blocks to use
  //     for each of the blocks to be created.
  bool GenerateBlocks(const BasicBlockSubGraph* subgraph);

  // A wrapper function to resolve all of the references in the merged subgraph
  // to point to their final locations in the block graph.
  // @param subgraph The subgraph.
  void TransferReferences(const BasicBlockSubGraph* subgraph) const;

  // A clean-up function to remove the original block from which @p subgraph
  // is derived (if any) from the block graph. This must only be performed
  // after having updated the block graph with the new blocks and transfered
  // all references to the new block(s).
  // @param subgraph The subgraph.
  void RemoveOriginalBlock(BasicBlockSubGraph* subgraph);

 private:
  // Update the new working block with the source range for the bytes in the
  // range [new_offset, new_offset + new_size).
  // @param original_offset The offset in the original block corresponding to
  //     the bytes in the new block. This may be BlockGraphh::kNoOffset, if
  //     the source range in question is for synthesized bytes (for example,
  //     a flow-through successor that will be synthesized as a branch).
  // @param original_size The number of bytes in the original range.
  // @param new_offset The offset in the new block where the original bytes
  //     will now live.
  // @param new_size The number of bytes the new range occupies.
  void UpdateSourceRange(Offset original_offset,
                         Size original_size,
                         Offset new_offset,
                         Size new_size);

  // Synthesize the instruction(s) to implement the given @p successor.
  // @param successor The successor to synthesize.
  // @param condition The condition to synthesize (overrides that of successor).
  bool SynthesizeSuccessor(const Successor& successor,
                           Successor::Condition condition);

  // Generate the byte sequence for the given @p successors. This function
  // handles the elision of successors that would naturally flow through to
  // the @p next_bb_in_ordering.
  // @param successors The successors to synthesize.
  // @param next_bb_in_ordering The next basic block in the basic block
  //     ordering. If a successor refers to the next basic-block in the
  //     ordering it does not have to be synthesized into a branch instruction
  //     as control flow will naturally continue into it.
  bool SynthesizeSuccessors(const BasicBlock::Successors& successors,
                            const BasicBlock* next_bb_in_ordering);

  // Copy the given @p instructions to the current working block.
  // @param instructions The instructions to copy.
  bool CopyInstructions(const BasicBlock::Instructions& instructions);

  // Copy the data (or padding bytes) in @p basic_block into new working block.
  // @param basic_block The basic_block to copy.
  bool CopyData(const BasicBlock* basic_block);

  // Generate a new block based on the given block @p description.
  // @param description Defines the block properties and basic blocks to use
  //     when creating the @p new_block_.
  bool GenerateBlock(const BlockDescription& description);

  // Transfer all external referrers that refer to @p bb to point to
  // bb's new location instead of to the original block.
  // @param bb The basic block.
  void UpdateReferrers(const BasicBlock* bb) const;

  // Resolves all of @p object's references (where object is a basic-block,
  // or instruction) to point to their final locations in the block graph.
  // @param object The referring object.
  // @param references The references made from object.
  void UpdateReferences(
      const void* object,
      const BasicBlock::BasicBlockReferenceMap& references) const;

  // Update all of references in the given basic-block's instructions to
  // point to their final locations in the block graph.
  // @param basic_block The basic block.
  void UpdateInstructionReferences(const BasicBlock* basic_block) const;

  // Update all of references for the given basic-block's successors to
  // point to their final locations in the block graph.
  // @param basic_block The basic block.
  void UpdateSuccessorReferences(const BasicBlock* basic_block) const;

 private:
  // The mapped locations of the block elements.
  LocationMap locations_;

  // The block graph in which the new blocks are generated.
  BlockGraph* const block_graph_;

  // The original block from which the new blocks are derived.
  const Block* original_block_;

  // The set of blocks generated in this context.
  BlockVector new_blocks_;

  // The current new block being generated.
  Block* new_block_;

  // The current write offset into the new block.
  Offset offset_;

  DISALLOW_COPY_AND_ASSIGN(MergeContext);
};

// Serializes instruction bytes to a target buffer.
// TODO(siggi, rogerm): Reconsider this approach when there's a BlockAssembler.
class Serializer : public core::AssemblerImpl::InstructionSerializer {
 public:
  explicit Serializer(uint8* buffer) : buffer_(buffer) {
    DCHECK(buffer != NULL);
  }

  virtual void AppendInstruction(uint32 location,
                                 const uint8* bytes,
                                 size_t num_bytes,
                                 const size_t* /* ref_locations */,
                                 const void* const* /* refs */,
                                 size_t /* num_refs */) OVERRIDE {
    DCHECK(bytes != NULL);
    ::memcpy(buffer_ + location, bytes, num_bytes);
  }

 protected:
  uint8* const buffer_;
};

void MergeContext::UpdateSourceRange(Offset original_offset,
                                     Size original_size,
                                     Offset new_offset,
                                     Size new_size) {
  DCHECK_LE(0, new_offset);
  DCHECK_NE(0U, new_size);
  DCHECK(new_block_ != NULL);

  // If the entire block is synthesized or just this new byte range is
  // synthesized, there's nothing to do.
  if (original_block_ == NULL || original_offset == BasicBlock::kNoOffset) {
    return;
  }

  // Find the source range for the original bytes. We may not have source
  // data for bytes that were synthesized in other transformations.
  // TODO(rogerm): During decomposition the basic-block decomposer should
  //     incorporate the source ranges for each subgraph element (data/padding
  //     basic-blocks, instructions and successors) into each element itself.
  const Block::SourceRanges::RangePair* range_pair =
      original_block_->source_ranges().FindRangePair(original_offset,
                                                         original_size);
  if (range_pair == NULL)
    return;

  core::RelativeAddress source_addr;
  Size source_size = 0;

  if (original_offset != range_pair->first.start() ||
      original_size != range_pair->first.size()) {
    // It must be that the mapping is one-to-one, that is, the source and
    // destination ranges must be the same size.
    CHECK_EQ(range_pair->first.size(), range_pair->second.size());
    Offset source_offset = original_offset - range_pair->first.start();
    source_addr = range_pair->second.start() + source_offset;
    source_size = original_size;
  } else {
    // Otherwise, we must have that the range_pair matches exactly the original
    // offset and size, in which case we want to use the whole of the second
    // part of the pair.
    CHECK_EQ(original_offset, range_pair->first.start());
    CHECK_EQ(original_size, range_pair->first.size());
    source_addr = range_pair->second.start();
    source_size = range_pair->second.size();
  }

  // Insert the new source range mapping into the new block.
  bool inserted = new_block_->source_ranges().Insert(
      Block::DataRange(new_offset, new_size),
      Block::SourceRange(source_addr, source_size));
  DCHECK(inserted);
}

bool MergeContext::SynthesizeSuccessor(const Successor& successor,
                                       Successor::Condition condition) {
  DCHECK_LT(Successor::kInvalidCondition, condition);
  DCHECK(new_block_ != NULL);

  // We use a temporary target location when assembling only to satisfy the
  // assembler interface. We will actually synthesize references that will
  // be responsible for filling in the correct values.
  // TODO(siggi, rogerm): Revisit once the BlockAssembler becomes available.
  static const core::ImmediateImpl kTempTarget(0, core::kSize32Bit);
  static const size_t k32BitsInBytes = 4;

  // Create the assembler.
  Serializer serializer(new_block_->GetMutableData());
  core::AssemblerImpl asm_(offset_, &serializer);

  // Synthesize the instruction(s) corresponding to the condition.
  if (condition <= Successor::kMaxConditionalBranch) {
    asm_.j(static_cast<core::ConditionCode>(condition), kTempTarget);
  } else {
    switch (condition) {
      case Successor::kConditionTrue:
        asm_.jmp(kTempTarget);
        break;
      case Successor::kCounterIsZero:
        asm_.jecxz(kTempTarget);
        break;
      case Successor::kLoopTrue:
        asm_.loop(kTempTarget);
        break;
      case Successor::kLoopIfEqual:
        asm_.loope(kTempTarget);
        break;
      case Successor::kLoopIfNotEqual:
        asm_.loopne(kTempTarget);
        break;
      case Successor::kInverseCounterIsZero:
      case Successor::kInverseLoopTrue:
      case Successor::kInverseLoopIfEqual:
      case Successor::kInverseLoopIfNotEqual:
        LOG(ERROR) << "Synthesis of inverse loop and counter branches is "
                   << "not supported yet.";
        return false;

      default:
        NOTREACHED();
        return false;
    }
  }

  // Remember where the reference for this successor has been placed. In each
  // of the above synthesized cases, it is the last thing written to the buffer.
  Offset ref_offset = asm_.location() - k32BitsInBytes;
  bool inserted = locations_.Add(&successor, new_block_, ref_offset);
  DCHECK(inserted);

  // Calculate the number of bytes written.
  size_t bytes_written = asm_.location() - offset_;

  // Update the source range.
  UpdateSourceRange(successor.instruction_offset(),
                    successor.instruction_size(),
                    offset_,  // This is where we started writing.
                    bytes_written);

  // Update the write location.
  offset_ = asm_.location();

  // And we're done.
  return true;
}

bool MergeContext::SynthesizeSuccessors(
    const BasicBlock::Successors& successors,
    const BasicBlock* next_bb_in_ordering) {
  size_t num_successors = successors.size();
  DCHECK_GE(2U, num_successors);

  // If there are no successors then we have nothing to do.
  if (num_successors == 0)
    return true;

  // If a successor is labeled, preserve it. Note that we expect at most one
  // successor to be labeled. We apply the label before synthesis because it
  // is possible that the labeled successor may be elided if control flow is
  // straightened.
  if (successors.front().has_label()) {
    new_block_->SetLabel(offset_, successors.front().label());
  } else if (num_successors == 2 && successors.back().has_label()) {
    new_block_->SetLabel(offset_, successors.back().label());
  }

  // Track whether we have already generated a successor. We can use this to
  // optimize the branch not taken case in the event both successors are
  // generated (the next_bb_in_ordering does not match any of the successors).
  // Since we have at most 2 successors (and they'll have inverse conditions
  // if there are two) then the second successor (if generated) can be modified
  // to be an unconditional branch. Note that if we generalize to an arbitrary
  // set of successors this optimization must be removed.
  bool branch_has_already_been_generated = false;

  // If there is no next_bb_in_ordering or the first successor does not refer
  // to next_bb_in_ordering, then we must generate the instruction for it, as
  // it cannot be a fall-through or branch-not-taken successor.
  const Successor& successor_a = successors.front();
  if (next_bb_in_ordering == NULL ||
      successor_a.reference().basic_block() != next_bb_in_ordering) {
    if (!SynthesizeSuccessor(successor_a, successor_a.condition()))
      return false;
    branch_has_already_been_generated = true;
  }

  // If there is only one successor, then we have nothing further to do.
  if (num_successors == 1) {
    DCHECK_EQ(Successor::kConditionTrue, successor_a.condition());
    return true;
  }

  // If there is no next_bb_in_ordering or the second successor does not refer
  // to next_bb_in_ordering, then we must generate the instruction for it, as
  // it cannot be the branch-not-taken fall-through successor.
  const Successor& successor_b = successors.back();
  DCHECK_EQ(successor_a.condition(),
            Successor::InvertCondition(successor_b.condition()));
  if (next_bb_in_ordering == NULL ||
      successor_b.reference().basic_block() != next_bb_in_ordering) {
    Successor::Condition condition = successor_b.condition();
    if (branch_has_already_been_generated)
      condition = Successor::kConditionTrue;
    if (!SynthesizeSuccessor(successor_b, condition))
      return false;
  }

  return true;
}

bool MergeContext::CopyInstructions(
    const BasicBlock::Instructions& instructions) {
  DCHECK_EQ(BasicBlock::BASIC_CODE_BLOCK, new_block_->type());
  // Get the target buffer.
  uint8* buffer = new_block_->GetMutableData();
  DCHECK(buffer != NULL);

  // Copy the instruction data and assign each instruction an offset.
  InstructionConstIter it = instructions.begin();
  for (; it != instructions.end(); ++it) {
    const Instruction& instruction = *it;
    Offset offset = offset_;

    // Remember where this instruction begins.
    bool inserted = locations_.Add(&instruction, new_block_, offset);
    DCHECK(inserted);

    // Copy the instruction bytes.
    ::memcpy(buffer + offset,
             instruction.data(),
             instruction.size());

    // Preserve the label on the instruction, if any.
    if (instruction.has_label())
      new_block_->SetLabel(offset, instruction.label());

    // Update the offset/bytes_written.
    offset_ += instruction.size();

    // Record the source range.
    UpdateSourceRange(instruction.offset(), instruction.size(),
                      offset, instruction.size());
  }

  return true;
}

bool MergeContext::CopyData(const BasicBlock* basic_block) {
  DCHECK(basic_block != NULL);
  DCHECK(basic_block->type() == BasicBlock::BASIC_DATA_BLOCK ||
         basic_block->type() == BasicBlock::BASIC_PADDING_BLOCK);

  // Get the target buffer.
  uint8* buffer = new_block_->GetMutableData();
  DCHECK(buffer != NULL);

  // Copy the basic-new_block_'s data bytes.
  Offset offset = offset_;
  ::memcpy(buffer + offset_, basic_block->data(), basic_block->size());
  offset_ += basic_block->size();

  // Record the source range.
  UpdateSourceRange(basic_block->offset(), basic_block->size(),
                    offset, basic_block->size());

  return true;
}

bool MergeContext::GenerateBlock(const BlockDescription& description) {
  // Remember the max size of the described block.
  size_t max_size = description.GetMaxSize();

  // Allocate a new block for this description.
  offset_ = 0;
  new_block_ = block_graph_->AddBlock(
      description.type, max_size, description.name);
  if (new_block_ == NULL) {
    LOG(ERROR) << "Failed to create block '" << description.name << "'.";
    return false;
  }

  // Save this block in the set of newly generated blocks. On failure, this
  // list will be used by GenerateBlocks() to clean up after itself.
  new_blocks_.push_back(new_block_);

  // Allocate the data buffer for the new block.
  if (new_block_->AllocateData(max_size) == NULL) {
    LOG(ERROR) << "Failed to allocate block data '" << description.name << "'.";
    return false;
  }

  // Initialize the new block's properties.
  new_block_->set_alignment(description.alignment);
  new_block_->set_section(description.section);
  new_block_->set_attributes(description.attributes);

  // Populate the new block with basic blocks.
  BasicBlockOrderingConstIter bb_iter = description.basic_block_order.begin();
  BasicBlockOrderingConstIter bb_end = description.basic_block_order.end();
  for (; bb_iter != bb_end; ++bb_iter) {
    const BasicBlock* bb = *bb_iter;

    // Remember where this basic block begins.
    bool inserted = locations_.Add(bb, new_block_, offset_);
    DCHECK(inserted);

    // If the basic-block is labeled, copy the label.
    if (bb->has_label())
      new_block_->SetLabel(offset_, bb->label());

    // Copy the contents of the basic block into the new block.
    if (bb->type() != BasicBlock::BASIC_CODE_BLOCK) {
      // If it's not a code basic-block then all we need to do is copy its data.
      if (!CopyData(bb)) {
        LOG(ERROR) << "Failed to copy data for '" << bb->name() << "'.";
        return false;
      }
    } else {
      // Copy the instructions.
      if (!CopyInstructions(bb->instructions())) {
        LOG(ERROR) << "Failed to copy instructions for '" << bb->name() << "'.";
        return false;
      }

      // Calculate the next basic block in the ordering.
      BasicBlockOrderingConstIter next_bb_iter = bb_iter;
      ++next_bb_iter;
      const BasicBlock* next_bb = NULL;
      if (next_bb_iter != bb_end)
        next_bb = *next_bb_iter;

      // Synthesize the successor instructions and assign each to an offset.
      if (!SynthesizeSuccessors(bb->successors(), next_bb)) {
        LOG(ERROR) << "Failed to create successors for '" << bb->name() << "'.";
        return false;
      }
    }
  }

  DCHECK_LT(0, offset_);
  DCHECK_LE(static_cast<BlockGraph::Size>(offset_), max_size);

  // Truncate the block to the number of bytes actually written.
  new_block_->ResizeData(offset_);
  new_block_->set_size(offset_);

  // Reset the current working block.
  new_block_ = NULL;
  offset_ = 0;

  // And we're done.
  return true;
}

bool MergeContext::GenerateBlocks(const BasicBlockSubGraph* subgraph) {
  DCHECK(subgraph != NULL);

  // Create a new block for each block description and remember the association.
  BlockDescriptionConstIter bd_iter = subgraph->block_descriptions().begin();
  for (; bd_iter != subgraph->block_descriptions().end(); ++bd_iter) {
    const BlockDescription& description = *bd_iter;

    // Skip the block if it's empty.
    if (description.basic_block_order.empty())
      continue;

    if (!GenerateBlock(description)) {
      // Remove generated blocks (this is safe as they're all disconnected)
      // and return false.
      BlockVector::iterator it = new_blocks_.begin();
      for (; it != new_blocks_.end(); ++it) {
        DCHECK((*it)->referrers().empty());
        DCHECK((*it)->references().empty());
        block_graph_->RemoveBlock(*it);
      }
      new_blocks_.clear();
      new_block_ = NULL;
      offset_ = 0;
      return false;
    }
  }

  return true;
}

void MergeContext::UpdateReferrers(const BasicBlock* bb) const {
  DCHECK(bb != NULL);

  // Find the current location of this basic block.
  Block* new_block_ = NULL;
  Offset new_base = 0;
  bool found = locations_.Find(bb, &new_block_, &new_base);
  DCHECK(found);

  // Update all external referrers to point to the new location.
  const BasicBlock::BasicBlockReferrerSet& referrers = bb->referrers();
  BasicBlock::BasicBlockReferrerSet::const_iterator it = referrers.begin();
  for (; it != referrers.end(); ++it) {
    // Get a non-const pointer to the referring block. Note that we don't
    // modify the set property on referrers as we update the block's references.
    const BasicBlockReferrer& referrer = *it;
    Block* referring_block = const_cast<Block*>(referrer.block());

    // We only care about references from other blocks.
    if (referring_block == NULL)
      continue;

    BlockGraph::Reference old_ref;
    bool found = referring_block->GetReference(referrer.offset(), &old_ref);
    DCHECK(found);
    DCHECK_EQ(BlockGraph::Reference::kMaximumSize, old_ref.size());

    BlockGraph::Reference new_ref(old_ref.type(),
                                  old_ref.size(),
                                  new_block_,
                                  old_ref.offset(),
                                  new_base);

    bool is_new = referring_block->SetReference(referrer.offset(), new_ref);
    DCHECK(!is_new);  // TODO(rogerm): Is this a valid DCHECK?
  }
}

void MergeContext::UpdateReferences(
    const void* object,
    const BasicBlock::BasicBlockReferenceMap& references) const {
  DCHECK(object != NULL);

  // Find the location of the object in the new block_graph.
  Block* block = NULL;
  Offset offset = 0;
  bool found = locations_.Find(object, &block, &offset);
  DCHECK(found);

  // Transfer all of this basic-block's references to the new block.
  BasicBlock::BasicBlockReferenceMap::const_iterator it = references.begin();
  for (; it != references.end(); ++it) {
    bool inserted = block->SetReference(offset + it->first,
                                        locations_.Resolve(it->second));
    DCHECK(inserted);
  }
}

void MergeContext::UpdateInstructionReferences(
    const BasicBlock* basic_block) const {
  DCHECK(basic_block != NULL);
  DCHECK_EQ(BasicBlock::BASIC_CODE_BLOCK, basic_block->type());
  InstructionConstIter inst_iter = basic_block->instructions().begin();
  for (; inst_iter != basic_block->instructions().end(); ++inst_iter)
    UpdateReferences(&(*inst_iter), inst_iter->references());
}

void MergeContext::UpdateSuccessorReferences(
    const BasicBlock* basic_block) const {
  DCHECK(basic_block != NULL);
  DCHECK_EQ(BasicBlock::BASIC_CODE_BLOCK, basic_block->type());
  SuccessorConstIter succ_iter = basic_block->successors().begin();
  for (; succ_iter != basic_block->successors().end(); ++succ_iter) {
    Block* block = NULL;
    Offset offset = 0;
    bool found = locations_.Find(&(*succ_iter), &block, &offset);
    if (!found)
      continue;  // This successor didn't generate any instructions.

    // Note that for successors, the (block, offset) points directly to
    // the location at which the target reference should live (as opposed
    // to the start of the instruction sequence).
    bool inserted = block->SetReference(
        offset, locations_.Resolve(succ_iter->reference()));
    DCHECK(inserted);
  }
}

void MergeContext::TransferReferences(
    const BasicBlockSubGraph* subgraph) const {
  // Transfer references to and from the original source block to the
  // corresponding new block.
  BlockDescriptionConstIter bd_iter = subgraph->block_descriptions().begin();
  for (; bd_iter != subgraph->block_descriptions().end(); ++bd_iter) {
    const BlockDescription& description = *bd_iter;
    const BasicBlockOrdering& basic_block_order = description.basic_block_order;

    // Skip the block description if it's empty.
    if (basic_block_order.empty())
      continue;

    BasicBlockOrderingConstIter bb_iter = basic_block_order.begin();
    for (; bb_iter != basic_block_order.end(); ++bb_iter) {
      const BasicBlock* basic_block = *bb_iter;
      // All referrers are stored at the basic block level.
      UpdateReferrers(basic_block);

      // Either this is a basic code block, which stores all of its outbound
      // references at the instruction and successor levels, or it's a basic
      // data or padding block (which includes unreachable code) and stores
      // all of its references at the basic block level.
      if (basic_block->type() == BasicBlock::BASIC_CODE_BLOCK) {
        DCHECK_EQ(0U, basic_block->references().size());
        UpdateInstructionReferences(basic_block);
        UpdateSuccessorReferences(basic_block);
      } else {
        UpdateReferences(basic_block, basic_block->references());
      }
    }
  }
}

void MergeContext::RemoveOriginalBlock(BasicBlockSubGraph* subgraph) {
  DCHECK(subgraph != NULL);
  DCHECK_EQ(original_block_, subgraph->original_block());

  Block* original_block_ = const_cast<Block*>(this->original_block_);
  if (original_block_ == NULL)
    return;

  DCHECK(!original_block_->HasExternalReferrers());

  bool removed = original_block_->RemoveAllReferences();
  DCHECK(removed);

  removed = block_graph_->RemoveBlock(original_block_);
  DCHECK(removed);

  subgraph->set_original_block(NULL);
  original_block_ = NULL;
}

}  // namespace

BlockBuilder::BlockBuilder(BlockGraph* bg) : block_graph_(bg) {
}

bool BlockBuilder::Merge(BasicBlockSubGraph* subgraph) {
  DCHECK(subgraph != NULL);

  MergeContext context(block_graph_, subgraph->original_block());

  if (!context.GenerateBlocks(subgraph))
    return false;

  context.TransferReferences(subgraph);
  context.RemoveOriginalBlock(subgraph);

  // Track the newly created blocks.
  new_blocks_.reserve(new_blocks_.size() + context.new_blocks().size());
  new_blocks_.insert(new_blocks_.end(),
                     context.new_blocks().begin(),
                     context.new_blocks().end());

  // And we're done.
  return true;
}

}  // namespace pe
