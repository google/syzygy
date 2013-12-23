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
// Implementation of BasicBlockSubGraph class.

#include "syzygy/block_graph/basic_block_subgraph.h"

#include <algorithm>

#include "base/memory/scoped_ptr.h"

namespace block_graph {

namespace {

// Returns true if any of the instructions in the range [@p start, @p end) is
// a, for the purposes of basic-block decomposition, control flow instruction.
bool HasControlFlow(BasicBlock::Instructions::const_iterator start,
                    BasicBlock::Instructions::const_iterator end) {
  for (; start != end; ++start) {
    if (start->IsControlFlow())
      return true;
  }
  return false;
}

}  // namespace

BasicBlockSubGraph::BasicBlockSubGraph()
    : original_block_(NULL), next_block_id_(0U) {
}

BasicBlockSubGraph::~BasicBlockSubGraph() {
  // Delete all the BB's we've been entrusted with.
  BBCollection::iterator it = basic_blocks_.begin();
  for (; it != basic_blocks_.end(); ++it)
    delete *it;

  // And wipe the collection.
  basic_blocks_.clear();
}

BasicBlockSubGraph::BlockDescription* BasicBlockSubGraph::AddBlockDescription(
    const base::StringPiece& name,
    const base::StringPiece& compiland,
    BlockType type,
    SectionId section,
    Size alignment,
    BlockAttributes attributes) {
  block_descriptions_.push_back(BlockDescription());
  BlockDescription* desc = &block_descriptions_.back();
  desc->name.assign(name.begin(), name.end());
  desc->compiland_name.assign(compiland.begin(), compiland.end());
  desc->type = type;
  desc->section = section;
  desc->alignment = alignment;
  desc->attributes = attributes;
  return desc;
}

block_graph::BasicCodeBlock* BasicBlockSubGraph::AddBasicCodeBlock(
    const base::StringPiece& name) {
  DCHECK(!name.empty());

  BlockId id = next_block_id_++;
  scoped_ptr<BasicCodeBlock> new_code_block(new BasicCodeBlock(this, name, id));
  bool inserted = basic_blocks_.insert(new_code_block.get()).second;
  DCHECK(inserted);

  return new_code_block.release();
}

block_graph::BasicDataBlock* BasicBlockSubGraph::AddBasicDataBlock(
    const base::StringPiece& name,
    Size size,
    const uint8* data) {
  DCHECK(!name.empty());

  BlockId id = next_block_id_++;
  scoped_ptr<BasicDataBlock> new_data_block(
      new BasicDataBlock(this, name, id, data, size));
  bool inserted = basic_blocks_.insert(new_data_block.get()).second;
  DCHECK(inserted);

  return new_data_block.release();
}

void BasicBlockSubGraph::Remove(BasicBlock* bb) {
  DCHECK(basic_blocks_.find(bb) != basic_blocks_.end());

  basic_blocks_.erase(bb);
}

bool BasicBlockSubGraph::IsValid() const {
  if (!MapsBasicBlocksToAtMostOneDescription())
    return false;

  if (!HasValidSuccessors())
    return false;

  if (!HasValidReferrers())
    return false;

  return true;
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
  ReachabilityMap rm;
  GetReachabilityMap(&rm);

  BlockDescriptionList::const_iterator desc_iter = block_descriptions_.begin();
  for (; desc_iter != block_descriptions_.end(); ++desc_iter) {
    BasicBlockOrdering::const_iterator bb_iter =
        desc_iter->basic_block_order.begin();
    for (; bb_iter != desc_iter->basic_block_order.end(); ++bb_iter) {
      const BasicCodeBlock* bb = BasicCodeBlock::Cast(*bb_iter);
      if (bb == NULL)
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

          // If this basic block is reachable then either there is an implicit
          // control flow instruction at the end or this basic block calls a
          // non-returning function. Otherwise, it should have been flagged by
          // the decomposer as unsafe to basic-block decompose.
          if (IsReachable(rm, bb) &&
              !instructions.back().IsImplicitControlFlow() &&
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
    const BasicBlockReferrerSet& bb_referrers =
        (*bb_iter)->referrers();
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
  for (; count_iter != external_referrers.end(); ++count_iter) {
    if (count_iter->second != 1) {
      LOG(ERROR) << "Basic-block composition does not properly update a "
                 << "referrer.";
      return false;
    }
  }

  return true;
}

void BasicBlockSubGraph::GetReachabilityMap(ReachabilityMap* rm) const {
  DCHECK(rm != NULL);
  DCHECK(rm->empty());
  std::set<const BasicBlock*> reachability_queue;

  // Mark all basic-blocks as unreachable and put all externally referenced
  // basic-blocks into the reachability queue.
  BBCollection::const_iterator  bb_iter = basic_blocks_.begin();
  for (; bb_iter != basic_blocks_.end(); ++bb_iter) {
    const BasicBlock* bb = *bb_iter;
    rm->insert(std::make_pair(bb, false));
    BasicBlock::BasicBlockReferrerSet::const_iterator ref_iter =
        bb->referrers().begin();
    for (; ref_iter != bb->referrers().end(); ++ref_iter)
      reachability_queue.insert(bb);
  }

  // Traverse the reachability queue marking basic blocks as reachable.
  while (!reachability_queue.empty()) {
    const BasicBlock* bb = *reachability_queue.begin();
    reachability_queue.erase(reachability_queue.begin());
    (*rm)[bb] = true;

    const BasicDataBlock* data_block = BasicDataBlock::Cast(bb);
    if (data_block != NULL) {
      // Put all bb-to-bb references into the reachability queue.
      BasicBlock::BasicBlockReferenceMap::const_iterator ref_iter =
          data_block->references().begin();
      for (; ref_iter != data_block->references().end(); ++ref_iter) {
        if (ref_iter->second.basic_block() != NULL &&
            !IsReachable(*rm, ref_iter->second.basic_block())) {
          reachability_queue.insert(ref_iter->second.basic_block());
        }
      }
    }

    const BasicCodeBlock* code_block = BasicCodeBlock::Cast(bb);
    if (code_block != NULL) {
      // Put all instruction-to-code_block references into the
      // reachability queue.
      BasicBlock::Instructions::const_iterator inst_iter =
          code_block->instructions().begin();
      for (; inst_iter != code_block->instructions().end(); ++inst_iter) {
        BasicBlock::BasicBlockReferenceMap::const_iterator ref_iter =
            inst_iter->references().begin();
        for (; ref_iter != inst_iter->references().end(); ++ref_iter) {
          if (ref_iter->second.basic_block() != NULL &&
              !IsReachable(*rm, ref_iter->second.basic_block())) {
            reachability_queue.insert(ref_iter->second.basic_block());
          }
        }
      }

      // Put all successor-to-code_block references into the reachability queue.
      BasicBlock::Successors::const_iterator succ_iter =
          code_block->successors().begin();
      for (; succ_iter != code_block->successors().end(); ++succ_iter) {
        if (succ_iter->reference().basic_block() != NULL &&
            !IsReachable(*rm, succ_iter->reference().basic_block())) {
          reachability_queue.insert(succ_iter->reference().basic_block());
        }
      }
    }
  }
}

bool BasicBlockSubGraph::IsReachable(const ReachabilityMap& rm,
                                     const BasicBlock* bb) {
  DCHECK(bb != NULL);
  BasicBlockSubGraph::ReachabilityMap::const_iterator it = rm.find(bb);
  DCHECK(it != rm.end());
  return it->second;
}

bool BasicBlockSubGraph::ToString(std::string* buf) const {
  DCHECK(buf != NULL);

  std::stringstream out;

  // Output block information.
  out << "BLOCK";
  if (original_block_ != NULL)
    out << " " << original_block_->name();
  out << std::endl;

  const BasicBlockSubGraph::BasicBlockOrdering& original_order =
      block_descriptions().front().basic_block_order;
  BasicBlockSubGraph::BasicBlockOrdering::const_iterator bb_iter =
      original_order.begin();
  for (; bb_iter != original_order.end(); ++bb_iter) {
    const BasicCodeBlock* bb = BasicCodeBlock::Cast(*bb_iter);
    if (bb == NULL)
      continue;

    out << "bb" << bb->id() << ":" << std::endl;

    // Output instructions.
    BasicCodeBlock::Instructions::const_iterator it =
      bb->instructions().begin();
    for (; it != bb->instructions().end(); ++it) {
      std::string instruction_string;
      if (!it->ToString(&instruction_string))
        return false;
      out << "  " << instruction_string;

      // Output references.
      const Instruction::BasicBlockReferenceMap& references = it->references();
      Instruction::BasicBlockReferenceMap::const_iterator reference_it =
          references.begin();
      for (; reference_it != references.end(); ++reference_it) {
        const BasicBlockReference& reference = reference_it->second;
        if (reference.block() != NULL)
          out << "  block(" << reference.block()->name() << ")";
        if (reference.basic_block() != NULL)
          out << "  basic_block(" << reference.basic_block()->id() << ")";
      }

      out << std::endl;
    }

    // Output successors.
    if (bb->successors().empty())
      continue;

    out << "                 ";
    BasicCodeBlock::Successors::const_iterator succ = bb->successors().begin();
    for (; succ != bb->successors().end(); ++succ) {
      if (succ->reference().basic_block()) {
        out << succ->ToString()
            << " bb" << succ->reference().basic_block()->id()
            << "  ";
      } else if (succ->reference().block()) {
        out << succ->ToString()
            << " <" << succ->reference().block()->name() << ">  ";
      } else {
        out << "<*>  ";
      }
    }
    out << std::endl;
  }

  // Commit the result.
  *buf = out.str();

  return true;
}

}  // namespace block_graph
