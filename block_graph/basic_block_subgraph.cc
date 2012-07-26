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
// Implementation of BasicBlockSubGraph class.

#include "syzygy/block_graph/basic_block_subgraph.h"

#include <algorithm>

namespace block_graph {

namespace {

// Returns true if any of the instructions in the range [@p start, @p end) is
// a, for the purposes of basic-block decompsition, control flow instruction.
bool HasControlFlow(BasicBlock::Instructions::const_iterator start,
                    BasicBlock::Instructions::const_iterator end) {
  for (; start != end; ++start) {
    if (start->IsControlFlow())
      return true;
  }
  return false;
}

}  // namespace

size_t BasicBlockSubGraph::BlockDescription::GetMaxSize() const {
  size_t max_size = 0;
  BasicBlockOrdering::const_iterator it = basic_block_order.begin();
  for (; it != basic_block_order.end(); ++it) {
    max_size += (*it)->GetMaxSize();
  }
  return max_size;
}

BasicBlockSubGraph::BasicBlockSubGraph()
    : original_block_(NULL), next_basic_block_id_(0) {
}

BasicBlockSubGraph::BlockDescription* BasicBlockSubGraph::AddBlockDescription(
    const base::StringPiece& name,
    BlockType type,
    SectionId section,
    Size alignment,
    BlockAttributes attributes) {
  block_descriptions_.push_back(BlockDescription());
  BlockDescription* desc = &block_descriptions_.back();
  desc->name.assign(name.begin(), name.end());
  desc->type = type;
  desc->section = section;
  desc->alignment = alignment;
  desc->attributes = attributes;
  return desc;
}

block_graph::BasicBlock* BasicBlockSubGraph::AddBasicBlock(
    const base::StringPiece& name,
    BasicBlockType type,
    Offset offset,
    Size size,
    const uint8* data) {
  DCHECK(!name.empty());

  typedef BBAddressSpace::Range Range;

  std::pair<BBCollection::iterator, bool> insert_result =
      basic_blocks_.insert(std::make_pair(
          next_basic_block_id_,
          BasicBlock(next_basic_block_id_, name, type, offset, size, data)));
  DCHECK(insert_result.second);

  block_graph::BasicBlock* new_basic_block = &insert_result.first->second;

  if (offset >= 0) {
    DCHECK(original_block_ != NULL);
    BBAddressSpace::Range byte_range(offset, size);
    if (!original_address_space_.Insert(byte_range, new_basic_block)) {
      LOG(ERROR) << "Attempted to insert overlapping basic block.";
      basic_blocks_.erase(insert_result.first);  // Undo bb insertion.
      return NULL;
    }
  }

  ++next_basic_block_id_;

  return new_basic_block;
}

bool BasicBlockSubGraph::IsValid() const {
  return MapsBasicBlocksToAtMostOneDescription() &&
      HasValidSuccessors() &&
      HasValidReferrers();
}

BasicBlock* BasicBlockSubGraph::FindBasicBlock(Offset base) const {
  DCHECK_LE(0, base);
  DCHECK(original_block_ != NULL);
  DCHECK_GT(original_block_->size(), static_cast<size_t>(base));

  BBAddressSpace::RangeMapConstIter bb_iter =
      original_address_space_.FindFirstIntersection(
          BBAddressSpace::Range(base, 1));

  // We have complete coverage of the block; there must be an intersection.
  // And, we break up the basic blocks by code references, so the target
  // base must coincide with the start of the target block.
  DCHECK(bb_iter != original_address_space_.end());
  BasicBlock* bb = bb_iter->second;
  DCHECK_EQ(base, bb_iter->first.start());

  return bb;
}

bool BasicBlockSubGraph::MapsBasicBlocksToAtMostOneDescription() const {
  std::set<BasicBlock*> bb_set;
  BlockDescriptionList::const_iterator desc_iter = block_descriptions_.begin();
  for (; desc_iter != block_descriptions_.end(); ++desc_iter) {
    BasicBlockOrdering::const_iterator bb_iter =
        desc_iter->basic_block_order.begin();
    for (; bb_iter != desc_iter->basic_block_order.end(); ++bb_iter) {
      if (!bb_set.insert(*bb_iter).second) {
        LOG(ERROR) << "Basic-block '" << (*bb_iter)->name() << "' appears "
                   << " in more than one block description.";
        return false;
      }
    }
  }
  return true;
}

bool BasicBlockSubGraph::HasValidSuccessors() const {
  BlockDescriptionList::const_iterator desc_iter = block_descriptions_.begin();
  for (; desc_iter != block_descriptions_.end(); ++desc_iter) {
    BasicBlockOrdering::const_iterator bb_iter =
        desc_iter->basic_block_order.begin();
    for (; bb_iter != desc_iter->basic_block_order.end(); ++bb_iter) {
      const BasicBlock* bb = *bb_iter;
      if (bb->type() != BasicBlock::BASIC_CODE_BLOCK)
        continue;

      const BasicBlock::Instructions& instructions = bb->instructions();
      const BasicBlock::Successors& successors = bb->successors();

      // There may be at most 2 successors.
      size_t num_successors = successors.size();
      switch (num_successors) {
        case 0: {
          // If there are no successors, then there must be some instructions
          // in the basic block.
          if (instructions.empty())
            return false;

          // There should be no control flow instructions except the last one.
          if (HasControlFlow(instructions.begin(), --instructions.end()))
            return false;

          // Either there is an implicit control flow instruction at the end
          // or this basic block calls a non-returning function. Otherwise, it
          // should have been flagged by the decomposer as unsafe to basic-
          // block decompose.
          if (!instructions.back().IsImplicitControlFlow() &&
              !instructions.back().CallsNonReturningFunction()) {
            return false;
          }
          break;
        }

        case 1: {
          // There should be no control flow instructions.
          if (HasControlFlow(instructions.begin(), instructions.end()))
            return false;

          // The successor must be unconditional.
          if (successors.back().condition() != Successor::kConditionTrue)
            return false;

          break;
        }

        case 2: {
          // There should be no control flow instructions.
          if (HasControlFlow(instructions.begin(), instructions.end()))
            return false;

          // The conditions on the successors should be inverses of one another.
          if (successors.front().condition() !=
                  Successor::InvertCondition(successors.back().condition())) {
            return false;
          }

          break;
        }

        default:
          NOTREACHED();
          return false;
      }
    }
  }

  // If we get here then everything was OK.
  return true;
}

bool BasicBlockSubGraph::HasValidReferrers() const {
  if (original_block_ == NULL)
    return true;

  using block_graph::BasicBlockReferrer;
  typedef std::map<BasicBlockReferrer,
                   size_t,
                   BasicBlockReferrer::CompareAsLess> ReferrerCountMap;
  ReferrerCountMap external_referrers;

  // Copy the external referrers into the count map, initializing their
  // counter to zero. These must all be incremented to 1 as we visit each
  // referrer in the basic-block graph.
  Block::ReferrerSet::const_iterator orig_iter =
      original_block_->referrers().begin();
  for (; orig_iter != original_block_->referrers().end(); ++orig_iter) {
    if (orig_iter->first != original_block_) {
      BasicBlockReferrer temp_referrer(orig_iter->first, orig_iter->second);
      external_referrers.insert(std::make_pair(temp_referrer, 0));
    }
  }

  // For each referrer to each basic block, add or increment the count for the
  // number of times it will be set to point to something. This will increment
  // the values initialized above (accounting for all the external referrers)
  // and will create a record for each internal referrer.
  BBCollection::const_iterator bb_iter = basic_blocks_.begin();
  for (; bb_iter != basic_blocks_.end(); ++bb_iter) {
    typedef BasicBlock::BasicBlockReferrerSet BasicBlockReferrerSet;
    const BasicBlockReferrerSet& bb_referrers = bb_iter->second.referrers();
    BasicBlockReferrerSet::const_iterator ref_iter = bb_referrers.begin();
    for (; ref_iter != bb_referrers.end(); ++ref_iter) {
      size_t count = ++external_referrers[*ref_iter];
      if (count != 1) {
        LOG(ERROR) << "Basic-block composition updates a referrer with "
                   << "multiple destinations.";
        return false;
      }
    }
  }

  // Make sure all of the referrers were incremented to 1. If we missed any
  // they will still be 0.
  ReferrerCountMap::const_iterator count_iter = external_referrers.begin();
  for (;count_iter != external_referrers.end(); ++count_iter) {
    if (count_iter->second != 1) {
      LOG(ERROR) << "Basic-block composition does not properly update a "
                 << "referrer.";
      return false;
    }
  }

  return true;
}

}  // namespace block_graph
