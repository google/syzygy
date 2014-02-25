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

#include "syzygy/reorder/basic_block_optimizer.h"

#include <algorithm>
#include <deque>
#include <set>

#include "syzygy/block_graph/basic_block.h"
#include "syzygy/block_graph/basic_block_decomposer.h"
#include "syzygy/block_graph/basic_block_subgraph.h"
#include "syzygy/pe/find.h"
#include "syzygy/pe/pe_utils.h"

#include "mnemonics.h"  // NOLINT

namespace reorder {

namespace {

using block_graph::BlockGraph;
using block_graph::ConstBlockVector;
using block_graph::BasicBlock;
using block_graph::BasicCodeBlock;
using block_graph::BasicDataBlock;
using block_graph::BasicEndBlock;
using block_graph::BasicBlockDecomposer;
using block_graph::BasicBlockSubGraph;
using block_graph::Successor;
using grinder::basic_block_util::EntryCountType;
using grinder::basic_block_util::IndexedFrequencyInformation;
using grinder::basic_block_util::IndexedFrequencyOffset;
using grinder::basic_block_util::IndexedFrequencyMap;
using grinder::basic_block_util::ModuleInformation;
using grinder::basic_block_util::RelativeAddress;
using grinder::basic_block_util::RelativeAddressRange;
using grinder::basic_block_util::RelativeAddressRangeVector;
using pe::PEFile;
using pe::ImageLayout;

typedef Reorderer::Order Order;
typedef BlockGraph::Offset Offset;
typedef BlockGraph::Size Size;
typedef BlockGraph::AddressSpace::RangeMapConstIter RangeMapConstIter;
typedef BlockGraph::AddressSpace::RangeMapConstIterPair RangeMapConstIterPair;

const char kDefaultColdSectionName[] = ".ctext";

// A helper to fill in (retaining relative ordering) any sections that are in
// the original @p image_layout which are not mentioned in @p order.
void PopulateMissingSections(
    const ImageLayout& image_layout, Order* order) {
  DCHECK(order != NULL);

  // Remember all of the sections mentioned by id.
  std::set<BlockGraph::SectionId> mentioned;
  for (size_t i = 0; i < order->sections.size(); ++i) {
    if (order->sections[i].id != Order::SectionSpec::kNewSectionId) {
      bool inserted = mentioned.insert(order->sections[i].id).second;
      DCHECK(inserted);
    }
  }

  // Iterate over all of the sections and append those not mentioned by ID.
  for (BlockGraph::SectionId id = 0; id < image_layout.sections.size(); ++id) {
    const ImageLayout::SectionInfo& info = image_layout.sections[id];
    if (mentioned.count(id) == 0) {
      order->sections.push_back(Order::SectionSpec());
      order->sections.back().id = id;
      order->sections.back().name = info.name;
      order->sections.back().characteristics = info.characteristics;
    }
  }
}

// Initialize a collection of blocks which are explicitly mentioned by the
// given @p order.
bool InitExplicitBlocks(const Order* order, ConstBlockVector* explicit_blocks) {
  DCHECK(order != NULL);
  DCHECK(explicit_blocks != NULL);
  explicit_blocks->clear();

  // Put all of the explicitly referenced blocks into explicit_blocks.
  for (size_t i = 0; i < order->sections.size(); ++i) {
    const Order::SectionSpec& section = order->sections[i];
    for (size_t k = 0; k < section.blocks.size(); ++k) {
      if (!section.blocks[k].basic_block_offsets.empty()) {
        LOG(ERROR) << "Expected a block-only ordering.";
        return false;
      }
      explicit_blocks->push_back(section.blocks[k].block);
    }
  }

  // If there are no explicit blocks then we are finished.
  if (explicit_blocks->empty())
    return true;

  // Sort the set of explicitly placed blocks. This lets us quickly check if
  // a block is in explicit_blocks using binary search.
  std::sort(explicit_blocks->begin(), explicit_blocks->end());

  // Verify that no block has been mentioned more than once.
  ConstBlockVector::const_iterator next_iter = explicit_blocks->begin();
  ConstBlockVector::const_iterator end_iter = --explicit_blocks->end();
  while (next_iter != end_iter) {
    ConstBlockVector::const_iterator curr_iter = next_iter++;
    if (*curr_iter == *next_iter) {
      LOG(ERROR) << "Ordering references a block multiple times.";
      return false;
    }
  }

  // And we're done.
  return true;
}

// Check if @p block is in @p explicit_blocks.
bool IsExplicitBlock(const ConstBlockVector& explicit_blocks,
                     const BlockGraph::Block* block) {
  return std::binary_search(explicit_blocks.begin(),
                            explicit_blocks.end(),
                            block);
}

// A helper to "cast" the given successor as a BasicCodeBlock.
const BasicCodeBlock* GetSuccessorBB(const Successor& successor) {
  const BasicBlock* bb = successor.reference().basic_block();

  // This might be in inter block reference (i.e., refers to a block not
  // a basic-block).
  if (bb == NULL)
    return NULL;

  // If it's a basic-block then it must be a code basic-block.
  const BasicCodeBlock* code_bb = BasicCodeBlock::Cast(bb);
  DCHECK(code_bb != NULL);
  return code_bb;
}

typedef std::pair<EntryCountType, const BasicCodeBlock*> CountForBasicBlock;

bool HasHigherEntryCount(const CountForBasicBlock& lhs,
                         const CountForBasicBlock& rhs) {
  return lhs.first > rhs.first;
}

bool GetEntryCountByOffset(const IndexedFrequencyInformation& entry_counts,
                           const RelativeAddress& base_rva,
                           Offset offset,
                           EntryCountType* entry_count) {
  DCHECK_LE(0, offset);
  DCHECK(entry_count != NULL);

  *entry_count = 0;
  IndexedFrequencyOffset key = std::make_pair(base_rva + offset, 0);
  IndexedFrequencyMap::const_iterator it =
      entry_counts.frequency_map.find(key);
  if (it != entry_counts.frequency_map.end())
    *entry_count = it->second;
  return true;
}

}  // namespace

BasicBlockOptimizer::BasicBlockOrderer::BasicBlockOrderer(
    const BasicBlockSubGraph& subgraph,
    const RelativeAddress& addr,
    Size size,
    const IndexedFrequencyInformation& entry_counts)
        : subgraph_(subgraph),
          addr_(addr),
          size_(size),
          entry_counts_(entry_counts) {
  DCHECK_LT(0U, size);
}

bool BasicBlockOptimizer::BasicBlockOrderer::GetBlockEntryCount(
    EntryCountType* entry_count) const {
  DCHECK(entry_count != NULL);

  if (!GetEntryCountByOffset(entry_counts_, addr_, 0, entry_count))
    return false;

  return true;
}

// TODO(rogerm): There are better longest path based orderings in the
//     literature, but they require more than just entry-count ordering.
bool BasicBlockOptimizer::BasicBlockOrderer::GetBasicBlockOrderings(
    Order::OffsetVector* warm_basic_blocks,
    Order::OffsetVector* cold_basic_blocks) const {
  DCHECK(warm_basic_blocks != NULL);
  DCHECK(cold_basic_blocks != NULL);

  // TODO(rogerm): Create weighted paths by entry-count following the successor
  //     and predecessor links.
  //
  // Here's an outline for a potential improvement:
  //     1. Set the first bb aside.
  //     2. Find the bb with the largest entry_count, then expand out from
  //        there by surrounding it with its largest predecessor and
  //        successor. Continuing expanding on both ends until there are no
  //        more successor/predecessor links to follow.
  //     3. If there are unplaced basic blocks, goto 2. This will create as
  //        many chains as required to represent all of the bbs.
  //     4. The resulting ordering should be the first bb followed by each
  //        path found above.

  warm_basic_blocks->clear();
  cold_basic_blocks->clear();

  // Place the basic-blocks in order such that each block is followed by its
  // successor having the greatest number of entries. We start with the bb
  // having offset 0.
  DCHECK_EQ(1U, subgraph_.block_descriptions().size());
  const BasicBlockSubGraph::BasicBlockOrdering& original_order =
      subgraph_.block_descriptions().front().basic_block_order;

  // Create a copy of the original ordering to serve as a queue. Henceforth
  // known as the BB Queue or bbq. Muahhahaha!
  std::deque<const BasicBlock*> bbq(original_order.begin(),
                                    original_order.end());
  DCHECK(!bbq.empty());
  DCHECK_EQ(0, bbq.front()->offset());

  // The set of basic blocks that we have already placed. Warm basic blocks
  // may jump the queue if they were the most common successor of a previously
  // seen basic block.
  BasicBlockSet placed_bbs;

  // The set of data basic-blocks referenced from an instruction in any
  // warm basic-block. This is used to determine where to place data blocks.
  BasicBlockSet warm_references;

  // Consume the bbq.
  bool have_seen_data_basic_block = false;
  while (!bbq.empty()) {
    // Get the next basic block.
    const BasicBlock* bb = bbq.front();
    bbq.pop_front();
    DCHECK(bb != NULL);

    // Insert it into the set of basic-blocks that have already been placed. If
    // the insertion is not a new element, then we've already handled this bb.
    bool already_handled = placed_bbs.insert(bb).second == false;
    if (already_handled)
      continue;

    // If it's a code basic block then we send it to the warm or cold list
    // based on whether or not its entry count is zero. We also push its
    // most common successor to the head of bbq to let it be the next placed
    // basic-block. We should not see any more code basic blocks once we
    // have encountered a data basic block.
    const BasicCodeBlock* code_bb = BasicCodeBlock::Cast(bb);
    if (code_bb != NULL) {
      DCHECK(!have_seen_data_basic_block);

      EntryCountType entry_count = 0;
      if (!GetBasicBlockEntryCount(code_bb, &entry_count)) {
        LOG(ERROR) << "Failed to get entry count for " << code_bb->name()
                   << " (offset=" << code_bb->offset() << ").";
        return false;
      }

      if (entry_count == 0) {
        // This is a cold basic-block. We simply add it to the cold
        // basic-block ordering.
        // TODO(rogerm): Sort cold blocks for minimal encoding size.
        cold_basic_blocks->push_back(code_bb->offset());
      } else {
        // This is a warm basic-block. Add it to the warm basic-block ordering.
        warm_basic_blocks->push_back(code_bb->offset());

        // Remember the data blocks referenced from its instructions.
        if (!AddWarmDataReferences(code_bb, &warm_references))
          return false;

        // If the basic-block has one or more successors, schedule the warmest
        // not-yet-placed successor (if any) to be next. Otherwise, if the
        // basic-block ended with an indirect jump through a jump table, queue
        // up the destinations in decreasing entry count order.
        if (!code_bb->successors().empty()) {
          const BasicBlock* successor = NULL;
          if (!GetWarmestSuccessor(code_bb, placed_bbs, &successor))
            return false;
          if (successor != NULL)
            bbq.push_front(successor);
        } else {
          // If the instruction is a jump, look for a jump table reference and
          // (if one is found) enqueue its referenced basic blocks in sorted
          // (by decreasing entry count) order.
          DCHECK(!code_bb->instructions().empty());
          const block_graph::Instruction& inst = code_bb->instructions().back();
          if (inst.representation().opcode == I_JMP) {
            std::vector<const BasicCodeBlock*> targets;
            if (!GetSortedJumpTargets(inst, &targets))
              return false;
            bbq.insert(bbq.begin(), targets.begin(), targets.end());
          }
        }
      }
    }

    // If it's a data basic block then we send it to the warm or cold list
    // depending on whether or not it was referenced by something in the warm
    // list. Note that the data basic-blocks are at the end of the basic-
    // block layout so we will have already seen all of the warm referrers
    // by the time this case succeeds.
    const BasicDataBlock* data_bb = BasicDataBlock::Cast(bb);
    if (data_bb != NULL) {
      have_seen_data_basic_block = true;
      if (warm_references.count(bb) != 0)
        warm_basic_blocks->push_back(data_bb->offset());
      else
        cold_basic_blocks->push_back(data_bb->offset());
    }

    // If it's an end basic-block we simply ignore it.
    const BasicEndBlock* end_bb = BasicEndBlock::Cast(bb);

    DCHECK(code_bb != NULL || data_bb != NULL || end_bb != NULL);
  }

  // TODO(rogerm): If we find that we haven't perturbed the basic-block
  //     ordering then we could clear both lists and let the block simply
  //     be copied/moved as is.

  DCHECK_EQ(subgraph_.basic_blocks().size(),
            warm_basic_blocks->size() + cold_basic_blocks->size() + 1);
  return true;
}

bool BasicBlockOptimizer::BasicBlockOrderer::GetBasicBlockEntryCount(
    const BasicCodeBlock* code_bb, EntryCountType* entry_count) const {
  DCHECK(code_bb != NULL);
  DCHECK(entry_count != NULL);

  if (!GetEntryCountByOffset(
          entry_counts_, addr_, code_bb->offset(), entry_count)) {
    return false;
  }

  return true;
}

bool BasicBlockOptimizer::BasicBlockOrderer::GetWarmestSuccessor(
    const BasicCodeBlock* code_bb,
    const BasicBlockSet& placed_bbs,
    const BasicBlock** succ_bb) const {
  DCHECK(code_bb != NULL);
  DCHECK(succ_bb != NULL);

  *succ_bb = NULL;

  // If there are no successors then there certainly isn't a warmest one.
  if (code_bb->successors().empty())
    return true;

  // If the first successor is a basic-block but it has already been seen,
  // then it is not a candidate for the warmest.
  const BasicCodeBlock* succ1 = GetSuccessorBB(code_bb->successors().front());
  if (succ1 != NULL && placed_bbs.count(succ1) != 0)
    succ1 = NULL;

  // If that was the only successor, then return whatever we have thus far.
  if (code_bb->successors().size() == 1) {
    *succ_bb = succ1;
    return true;
  }

  DCHECK_EQ(2U, code_bb->successors().size());

  // If the second successor is a basic-block but it has already been seen,
  // then it is not a candidate for the warmest.
  const BasicCodeBlock* succ2 = GetSuccessorBB(code_bb->successors().back());
  if (succ2 != NULL && placed_bbs.count(succ2) != 0)
    succ2 = NULL;

  // If the first successor is not a candidate, then we can return whatever we
  // have for the second successor.
  if (succ1 == NULL) {
    *succ_bb = succ2;
    return true;
  }

  DCHECK(succ1 != NULL);

  // If the second successor is not a candidate, then we can return whatever we
  // have for the first successor.
  if (succ2 == NULL) {
    *succ_bb = succ1;
    return true;
  }

  // Both successors are valid candidates. We choose the one with the highest
  // entry count. Note that we keep the successors in the same order if the
  // entry counts are the same. By default we know that succ2 represents the
  // fall-through (branch-not-taken) path that immediately follows the
  // conditional.
  DCHECK(succ1 != NULL);
  DCHECK(succ2 != NULL);

  EntryCountType succ1_entry_count = 0;
  if (!GetBasicBlockEntryCount(succ1, &succ1_entry_count)) {
    LOG(ERROR) << "Failed to get entry count for " << succ1->name()
               << " (offset=" << succ1->offset() << ").";
    return false;
  }

  EntryCountType succ2_entry_count = 0;
  if (!GetBasicBlockEntryCount(succ2, &succ2_entry_count)) {
    LOG(ERROR) << "Failed to get entry count for " << succ2->name()
               << " (offset=" << succ2->offset() << ").";
    return false;
  }

  if (succ1_entry_count > succ2_entry_count)
    *succ_bb = succ1;
  else
    *succ_bb = succ2;

  return true;
}

bool BasicBlockOptimizer::BasicBlockOrderer::GetSortedJumpTargets(
    const block_graph::Instruction& jmp_inst,
    std::vector<const BasicCodeBlock*>* targets) const {
  DCHECK_EQ(I_JMP, jmp_inst.representation().opcode);
  DCHECK(targets != NULL);

  targets->clear();

  // We store the targets and their entry counts in a temporary vector that
  // we can sort by entry counts.
  typedef std::vector<CountForBasicBlock> TempTargets;
  TempTargets temp_targets;
  temp_targets.reserve(jmp_inst.references().size());

  // Find the jump-table reference.
  BasicBlock::BasicBlockReferenceMap::const_iterator ref_iter =
      jmp_inst.references().begin();
  for (; ref_iter != jmp_inst.references().end(); ++ref_iter) {
    // We're only interested in referred data basic blocks that are marked
    // as being a jump table.
    const BasicDataBlock* ref_bb =
        BasicDataBlock::Cast(ref_iter->second.basic_block());
    if (ref_bb == NULL ||
        !ref_bb->label().IsValid() ||
        !ref_bb->label().has_attributes(BlockGraph::JUMP_TABLE_LABEL)) {
      continue;
    }

    DCHECK(ref_bb != NULL);
    DCHECK(ref_bb->label().IsValid());
    DCHECK(ref_bb->label().has_attributes(BlockGraph::JUMP_TABLE_LABEL));

    // Populate temp_targets with each target and it's entry count.
    BasicBlock::BasicBlockReferenceMap::const_iterator target_iter =
        ref_bb->references().begin();
    for (; target_iter != ref_bb->references().end(); ++target_iter) {
      const BasicCodeBlock* target_bb =
          BasicCodeBlock::Cast(target_iter->second.basic_block());
      if (target_bb == NULL) {
        LOG(ERROR) << "Found non-code-basic-block reference in a jump table.";
        return false;
      }
      // Get the entry count.
      EntryCountType entry_count = 0;
      if (!GetBasicBlockEntryCount(target_bb, &entry_count))
        return false;

      // Append the entry count and the target into the temp target vector.
      temp_targets.push_back(std::make_pair(entry_count, target_bb));
    }
  }

  // Perform a stable sort of the temp target vector by decreasing entry count.
  std::stable_sort(
      temp_targets.begin(), temp_targets.end(), &HasHigherEntryCount);

  // Copy the resulting basic block ordering into the target vector.
  targets->reserve(temp_targets.size());
  TempTargets::const_iterator temp_target_iter = temp_targets.begin();
  for (; temp_target_iter != temp_targets.end(); ++temp_target_iter) {
    if (temp_target_iter->first > 0)
      targets->push_back(temp_target_iter->second);
  }

  return true;
}

bool BasicBlockOptimizer::BasicBlockOrderer::AddWarmDataReferences(
    const BasicCodeBlock* code_bb, BasicBlockSet* warm_references) const {
  DCHECK(code_bb != NULL);
  DCHECK(warm_references != NULL);

  // Iterate over all of the instructions.
  BasicBlock::Instructions::const_iterator inst_iter =
      code_bb->instructions().begin();
  for (; inst_iter != code_bb->instructions().end(); ++inst_iter) {
    // For each instruction, iterate over all references it makes.
    BasicBlock::BasicBlockReferenceMap::const_iterator ref_iter =
        inst_iter->references().begin();
    for (; ref_iter != inst_iter->references().end(); ++ref_iter) {
      // We're only interested in references that refer to basic-blocks.
      const BasicBlock* bb = ref_iter->second.basic_block();
      if (bb == NULL)
        continue;

      // We tolerate code->code references only for the special case of
      // self-recursive functions.
      const BasicCodeBlock* code_bb = BasicCodeBlock::Cast(bb);
      if (code_bb != NULL) {
        if (code_bb->offset() == 0) {
          continue;
        }

        DCHECK_NE(0, code_bb->offset());
        LOG(ERROR) << "Invalid code to code reference from instruction.";
        return false;
      }

      // For each data reference we recursively add all
      // basic data blocks reachable.
      const BasicDataBlock* data_bb = BasicDataBlock::Cast(bb);
      DCHECK(data_bb != NULL);

      AddRecursiveDataReferences(data_bb, warm_references);
    }
  }
  return true;
}

void BasicBlockOptimizer::BasicBlockOrderer::AddRecursiveDataReferences(
    const BasicDataBlock* data_bb, BasicBlockSet* warm_references) const {
  DCHECK(data_bb != NULL);
  DCHECK(warm_references != NULL);

  // Mark the current data basic-block as a warm reference. If this basic-
  // block is already in the warm references set, then we don't need to
  // recurse its references.
  bool is_new_insertion = !warm_references->insert(data_bb).second;
  if (!is_new_insertion)
    return;

  // Otherwise, iterate over all of the references made from this data
  // basic-block. Note that the reference might point to code (a jump
  // table, for example). If the reference is to another data basic-block,
  // then recursively add its data references.
  BasicBlock::BasicBlockReferenceMap::const_iterator ref_iter =
      data_bb->references().begin();
  for (; ref_iter != data_bb->references().end(); ++ref_iter) {
    // We're only interested in references that refer to basic-blocks.
    const BasicBlock* bb = ref_iter->second.basic_block();
    if (bb == NULL)
      continue;
    // We recurse into data basic-blocks.
    const BasicDataBlock* referred_data_bb = BasicDataBlock::Cast(bb);
    if (referred_data_bb != NULL)
      AddRecursiveDataReferences(referred_data_bb, warm_references);
  }
}

BasicBlockOptimizer::BasicBlockOptimizer()
    : cold_section_name_(kDefaultColdSectionName) {
}

bool BasicBlockOptimizer::Optimize(
    const ImageLayout& image_layout,
    const IndexedFrequencyInformation& entry_counts,
    Order* order) {
  DCHECK(order != NULL);

  if (entry_counts.data_type !=
          ::common::IndexedFrequencyData::BASIC_BLOCK_ENTRY &&
      entry_counts.data_type !=
          ::common::IndexedFrequencyData::BRANCH) {
    LOG(ERROR) << "Invalid frequency data type.";
    return false;
  }

  // Keep track of which blocks have been explicitly ordered. This will be used
  // when implicitly placing blocks.
  ConstBlockVector explicit_blocks;
  if (!InitExplicitBlocks(order, &explicit_blocks))
    return false;

  // Fill in any sections which were not mentioned by the ordering.
  PopulateMissingSections(image_layout, order);

  // Remember how many sections we started with.
  size_t num_sections = order->sections.size();

  // Add a new section in which to put the cold blocks and basic-blocks.
  order->sections.push_back(Order::SectionSpec());
  Order::SectionSpec* cold_section_spec = &order->sections.back();
  cold_section_spec->name = cold_section_name_;
  cold_section_spec->id = Order::SectionSpec::kNewSectionId;
  cold_section_spec->characteristics = pe::kCodeCharacteristics;

  pe::PETransformPolicy policy;

  // Iterate over the sections in the original order and update their basic-
  // block orderings.
  for (size_t i = 0; i < num_sections; ++i) {
    Order::SectionSpec* section_spec = &order->sections[i];
    Order::BlockSpecVector warm_block_specs;
    Order::BlockSpecVector cold_block_specs;

    // Get the collection of warm and cold block spec for this section.
    if (!OptimizeSection(policy,
                         image_layout,
                         entry_counts,
                         explicit_blocks,
                         section_spec,
                         &warm_block_specs,
                         &cold_block_specs)) {
      return false;
    }

    // Replace the block specs in the original section with those found to
    // be warm, and append the cold blocks to the end of the cold section.
    section_spec->blocks.swap(warm_block_specs);
    cold_section_spec->blocks.insert(cold_section_spec->blocks.end(),
                                     cold_block_specs.begin(),
                                     cold_block_specs.end());
  }

  return true;
}

// Get an ordered list of warm and cold basic blocks for the given @p block.
bool BasicBlockOptimizer::OptimizeBlock(
    const pe::PETransformPolicy& policy,
    const BlockGraph::Block* block,
    const ImageLayout& image_layout,
    const IndexedFrequencyInformation& entry_counts,
    Order::BlockSpecVector* warm_block_specs,
    Order::BlockSpecVector* cold_block_specs) {
  DCHECK(block != NULL);
  DCHECK(warm_block_specs != NULL);
  DCHECK(cold_block_specs != NULL);

  // Leave data blocks untouched.
  if (block->type() != BlockGraph::CODE_BLOCK) {
    warm_block_specs->push_back(Order::BlockSpec(block));
    return true;
  }

  // Find the start address of the block.
  RelativeAddress addr;
  if (!image_layout.blocks.GetAddressOf(block, &addr)) {
    LOG(ERROR) << "Failed to find " << block->name() << " in image layout.";
    return false;
  }

  // Determine the number of times the block has been entered. We use the
  // start of the block (with a zero offset) to find it's entry count.
  EntryCountType entry_count = 0;
  if (!GetEntryCountByOffset(entry_counts, addr, 0, &entry_count)) {
    LOG(ERROR) << "Failed to find entry count for '" << block->name() << "'.";
    return false;
  }

  // If the function was never invoked, we just move it as is to the cold set.
  // We have no information on which to base a basic-block optimization.
  if (entry_count == 0) {
    cold_block_specs->push_back(Order::BlockSpec(block));
    return true;
  }

  // Handle non-decomposable code blocks as large opaque basic-blocks. We've
  // already established that the block is warm, so just place it as is.
  if (!policy.BlockIsSafeToBasicBlockDecompose(block)) {
    warm_block_specs->push_back(Order::BlockSpec(block));
    return true;
  }

  // The function was called at least once and is basic-block decomposable.
  // Let's decompose and optimize it.
  BasicBlockSubGraph subgraph;
  BasicBlockDecomposer decomposer(block, &subgraph);
  if (!decomposer.Decompose())
    return false;

  // Create the basic-block orderer.
  BasicBlockOrderer orderer(subgraph, addr, block->size(), entry_counts);
  Order::OffsetVector warm_basic_blocks;
  Order::OffsetVector cold_basic_blocks;
  if (!orderer.GetBasicBlockOrderings(&warm_basic_blocks,
                                      &cold_basic_blocks)) {
    return false;
  }

  // Note that we allow the ordering function to return an empty set of
  // warm basic-blocks. This denotes that the block should be placed into
  // the warm block specs without modification and also implies that there
  // should be no cold basic-blocks.
  //
  // Therefore the following should be true:
  //     * If there are cold basic-blocks returned then there are also
  //       warm basic-blocks returned.
  //     * Either both returned sets are empty or the sum of the warm and
  //       cold basic-blocks and an end-block equals the total number of
  //       basic-blocks in the subgraph.
  DCHECK(cold_basic_blocks.empty() || !warm_basic_blocks.empty());
  DCHECK((warm_basic_blocks.empty() && cold_basic_blocks.empty()) ||
         (warm_basic_blocks.size() + cold_basic_blocks.size() + 1 ==
              subgraph.basic_blocks().size()));

  // We know the function was called at least once. Some part of it should
  // be into warm_block_specs.
  warm_block_specs->push_back(Order::BlockSpec(block));
  warm_block_specs->back().basic_block_offsets.swap(warm_basic_blocks);

  // But, there may or may not be a cold part.
  if (!cold_basic_blocks.empty()) {
    cold_block_specs->push_back(Order::BlockSpec(block));
    cold_block_specs->back().basic_block_offsets.swap(cold_basic_blocks);
  }

  return true;
}

bool BasicBlockOptimizer::OptimizeSection(
    const pe::PETransformPolicy& policy,
    const ImageLayout& image_layout,
    const IndexedFrequencyInformation& entry_counts,
    const ConstBlockVector& explicit_blocks,
    Order::SectionSpec* orig_section_spec,
    Order::BlockSpecVector* warm_block_specs,
    Order::BlockSpecVector* cold_block_specs) {
  DCHECK(orig_section_spec != NULL);
  DCHECK(warm_block_specs != NULL);
  DCHECK(cold_block_specs != NULL);

  // Place all of the explicitly ordered blocks.
  for (size_t i = 0; i < orig_section_spec->blocks.size(); ++i) {
    Order::BlockSpec* block_spec = &orig_section_spec->blocks[i];
    DCHECK(block_spec->block != NULL);
    DCHECK(block_spec->basic_block_offsets.empty());
    DCHECK(IsExplicitBlock(explicit_blocks, block_spec->block));

    if (!OptimizeBlock(policy,
                       block_spec->block,
                       image_layout,
                       entry_counts,
                       warm_block_specs,
                       cold_block_specs)) {
      return false;
    }
  }

  // If we are updating a preexisting section, then account for the rest of
  // the blocks in the section. We leave these in their original relative
  // ordering.
  if (orig_section_spec->id != Order::SectionSpec::kNewSectionId) {
    DCHECK_GT(image_layout.sections.size(), orig_section_spec->id);
    const ImageLayout::SectionInfo& section_info =
        image_layout.sections[orig_section_spec->id];

    // Get an iterator pair denoting all of the blocks in the section.
    RangeMapConstIterPair iter_pair(
        image_layout.blocks.GetIntersectingBlocks(
            RelativeAddress(section_info.addr), section_info.size));
    for (RangeMapConstIter it = iter_pair.first; it != iter_pair.second; ++it) {
      // If the block is explicitly mentioned in the ordering then we don't
      // have to handle it here. Note that explicit_blocks is populated
      // before placing any blocks, so it already accounts for blocks that
      // move between sections.
      if (IsExplicitBlock(explicit_blocks, it->second))
        continue;

      // We apply the same optimization as for explicitly placed blocks.
      if (!OptimizeBlock(policy,
                         it->second,
                         image_layout,
                         entry_counts,
                         warm_block_specs,
                         cold_block_specs)) {
        return false;
      }
    }
  }

  return true;
}

}  // namespace reorder
