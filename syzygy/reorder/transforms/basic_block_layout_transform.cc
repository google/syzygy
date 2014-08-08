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

#include "syzygy/reorder/transforms/basic_block_layout_transform.h"

#include "base/strings/stringprintf.h"

namespace reorder {
namespace transforms {

namespace {

using block_graph::BlockGraph;
using block_graph::BlockVector;

typedef BasicBlockLayoutTransform::BlockInfo BlockInfo;
typedef BasicBlockLayoutTransform::BlockInfos BlockInfos;
typedef BasicBlockLayoutTransform::Order Order;
typedef BasicBlockSubGraphLayoutTransform::BlockPositionPair BlockPositionPair;
typedef BasicBlockSubGraphLayoutTransform::BasicBlockMap BasicBlockMap;

// Build the basic-block map for the given collection of block specifications.
// Returns true if the specifications are consistent, false otherwise.
bool BuildBasicBlockMap(BlockInfos::const_iterator begin,
                        BlockInfos::const_iterator end,
                        BasicBlockMap* basic_block_map,
                        size_t* block_count) {
  DCHECK(basic_block_map != NULL);
  DCHECK(block_count != NULL);

  basic_block_map->clear();
  *block_count = 0;
  bool empty_bloc_spec_seen = false;

  // Iterate over the block specifications.
  BlockInfos::const_iterator it = begin;
  for (; it != end; ++it, ++(*block_count)) {
    if (it->block_spec->basic_block_offsets.empty())
      empty_bloc_spec_seen = true;

    // For each one, iterate over the collection of basic blocks and update
    // the basic block map. While doing this we make sure that each basic
    // block is only specified once.
    const Order::OffsetVector& offsets(it->block_spec->basic_block_offsets);
    for (size_t i = 0; i < offsets.size(); ++i) {
      BlockPositionPair block_position(*block_count, i);
      bool inserted = basic_block_map->insert(
          std::make_pair(offsets[i], block_position)).second;
      if (!inserted) {
        LOG(ERROR) << "Basic block at offset " << offsets[i] << " of block \""
                   << it->block_spec->block->name() << "\" with ID "
                   << it->block_spec->block->id() << " is specified multiple "
                   << "times.";
        return false;
      }
    }
  }

  // This must have been called with non-empty input.
  DCHECK_LT(0u, *block_count);

  // An empty block specification means that ALL of the basic-blocks belong
  // to that block. This is only valid if there is a single block specification.
  if (*block_count != 1 && empty_bloc_spec_seen) {
    LOG(ERROR) << "Have an empty block specification amongst multiple block "
               << "specifications.";
    return false;
  }

  return true;
}

// Compares BlockInfos based on the original block pointer from the block_spec.
// Allows comparing BlockInfos to each other, and Block pointers to BlockInfos.
struct BlockInfoComparator {
  bool operator()(const BlockInfo& bi1,
                  const BlockInfo& bi2) const {
    return bi1.original_block < bi2.original_block;
  }
  bool operator()(const BlockGraph::Block* block,
                  const BlockInfo& bi) const {
    return block < bi.original_block;
  }
  bool operator()(const BlockInfo& bi,
                  const BlockGraph::Block* block) const {
    return bi.original_block < block;
  }
};

}  // namespace

const char BasicBlockLayoutTransform::kTransformName[] =
    "BasicBlockLayoutTransform";

BasicBlockLayoutTransform::BasicBlockLayoutTransform(Order* order)
    : order_(order) {
  DCHECK(order != NULL);
}

BasicBlockLayoutTransform::~BasicBlockLayoutTransform() {
}

bool BasicBlockLayoutTransform::PreBlockGraphIteration(
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BlockGraph::Block* header_block) {
  DCHECK(policy != NULL);
  DCHECK(block_graph != NULL);
  DCHECK(header_block != NULL);

  if (!FindOrCreateSections(block_graph))
    return false;

  BuildBlockInfos();
  return true;
}

bool BasicBlockLayoutTransform::OnBlock(
    const TransformPolicyInterface* policy,
    block_graph::BlockGraph* block_graph,
    block_graph::BlockGraph::Block* block) {
  DCHECK(policy != NULL);
  DCHECK(block_graph != NULL);
  DCHECK(block != NULL);

  // Get the range of block specifications that are to be applied to this
  // source block.
  BlockInfos::iterator it_begin = std::lower_bound(block_infos_.begin(),
                                                   block_infos_.end(),
                                                   block,
                                                   BlockInfoComparator());
  BlockInfos::iterator it_end = std::upper_bound(block_infos_.begin(),
                                                 block_infos_.end(),
                                                 block,
                                                 BlockInfoComparator());

  // This block is not specified in the ordering. It will be left to fall to
  // the tail of its original section by the orderer.
  if (it_begin == it_end)
    return true;

  // Build the basic block map. This maps from BB offsets to
  // (block index, bb index) pairs.
  BasicBlockMap bb_map;
  size_t block_count = 0;
  if (!BuildBasicBlockMap(it_begin, it_end, &bb_map, &block_count))
    return false;

  BlockVector new_blocks;

#ifndef NDEBUG
  // We expect the block_spec not to have been updated in place yet. If it
  // has it's because this block has already been seen by the BB transform,
  // which should never happen.
  for (BlockInfos::iterator it = it_begin; it != it_end; ++it) {
    DCHECK_EQ(it->original_block, it->block_spec->block);
  }
#endif  // NDEBUG

  // Special case: a single block with no BB layout specification. Simply
  // ensure the block is in the appropriate section, add an entry to the
  // block specification map and move on.
  if (block_count == 1 && bb_map.empty()) {
    new_blocks.push_back(block);
  } else {
    // If we get here it's because we have an explicitly specified BB layout.
    DCHECK(!bb_map.empty());

    // Layout the basic-blocks using a basic block subgraph transform.
    BasicBlockSubGraphLayoutTransform bb_layout_tx(bb_map);
    if (!ApplyBasicBlockSubGraphTransform(
            &bb_layout_tx,
            policy,
            block_graph,
            block,
            &new_blocks)) {
      return false;
    }
  }

  // We expect there to be as many blocks created as there are block
  // specifications.
  DCHECK_EQ(block_count, new_blocks.size());

  // The transform returns the newly created blocks in the same order as they
  // were specified by the BasicBlockMap, thus we can simply iterate through the
  // blocks to assign them to the appropriate sections and update the block
  // infos.
  BlockInfos::iterator it = it_begin;
  for (size_t i = 0; i < new_blocks.size(); ++i, ++it) {
    new_blocks[i]->set_section(it->section_spec->id);
    it->block_spec->block = new_blocks[i];
    it->block_spec->basic_block_offsets.clear();
  }

  return true;
}

bool BasicBlockLayoutTransform::FindOrCreateSections(BlockGraph* block_graph) {
  DCHECK(block_graph != NULL);
  DCHECK(order_ != NULL);

  Order::SectionSpecVector::iterator section_it = order_->sections.begin();
  for (; section_it != order_->sections.end(); ++section_it) {
    if (!FindOrCreateSection(block_graph, &(*section_it)))
      return false;
  }
  return true;
}

bool BasicBlockLayoutTransform::FindOrCreateSection(
    BlockGraph* block_graph,
    Order::SectionSpec* section_spec) {
  DCHECK(block_graph != NULL);
  DCHECK(section_spec != NULL);
  DCHECK(!section_spec->name.empty());

  BlockGraph::Section* section = NULL;

  // Explicit section ID? Ensure it exists and validate it.
  if (section_spec->id != Order::SectionSpec::kNewSectionId) {
    section = block_graph->GetSectionById(section_spec->id);
    if (section == NULL) {
      LOG(ERROR) << "Order specifies an invalid section ID.";
      return false;
    }

    // Rename the section if we've been asked to do so.
    if (section_spec->name != section->name()) {
      LOG(INFO) << "Renaming section \"" << section->name() << "\" to \""
                << section_spec->name << "\".";
      section->set_name(section_spec->name);
    }

    // Set the section characteristics if need be.
    if (section_spec->characteristics != section->characteristics()) {
      LOG(INFO) << "Changing characteristics from "
                << base::StringPrintf("0x%08X", section->characteristics())
                << " to "
                << base::StringPrintf("0x%08X", section_spec->characteristics)
                << ".";
      section->set_characteristics(section_spec->characteristics);
    }
  } else {
    // If an ID wasn't provided then this section better contain at least one
    // block.
    if (section_spec->blocks.empty()) {
      LOG(ERROR) << "Invalid section specification.";
      return false;
    }

    // Otherwise, create a new section.
    section = block_graph->AddSection(
        section_spec->name, section_spec->characteristics);
    if (section == NULL) {
      LOG(ERROR) << "Failed to add section \"" << section_spec->name
                 << "\".";
      return false;
    }

    // Save the ID of this newly created section.
    section_spec->id = section->id();
  }

  return true;
}

void BasicBlockLayoutTransform::BuildBlockInfos() {
  Order::SectionSpecVector::iterator section_spec_it =
      order_->sections.begin();
  for (; section_spec_it != order_->sections.end(); ++section_spec_it) {
    Order::SectionSpec* section_spec = &(*section_spec_it);

    Order::BlockSpecVector::iterator block_spec_it =
        section_spec_it->blocks.begin();
    for (; block_spec_it != section_spec_it->blocks.end(); ++block_spec_it) {
      Order::BlockSpec* block_spec = &(*block_spec_it);

      BlockInfo block_info = { block_spec->block, section_spec, block_spec };
      block_infos_.push_back(block_info);
    }
  }

  std::sort(block_infos_.begin(), block_infos_.end(), BlockInfoComparator());
}

const char BasicBlockSubGraphLayoutTransform::kTransformName[] =
    "BasicBlockSubGraphLayoutTransform";

bool BasicBlockSubGraphLayoutTransform::TransformBasicBlockSubGraph(
    const TransformPolicyInterface* policy,
    BlockGraph* bg,
    BasicBlockSubGraph* bbsg) {
  DCHECK(policy != NULL);
  DCHECK(bg != NULL);
  DCHECK(bbsg != NULL);
  DCHECK_EQ(1u, bbsg->block_descriptions().size());

  typedef BasicBlockSubGraph::BasicBlock BasicBlock;
  typedef BasicBlockSubGraph::BBCollection::iterator BBIterator;
  typedef std::map<BlockPositionPair, BasicBlock*> ReverseMap;

  // Iterate through the basic blocks in the original block. While we're at it
  // we invert the basic block map so that iterating through it the blocks will
  // be in the necessary order.
  size_t block_count = 0;
  ReverseMap reverse_map;
  BBIterator bb_it = bbsg->basic_blocks().begin();
  for (; bb_it != bbsg->basic_blocks().end(); ++bb_it) {
    // Find the entry for this basic block in the basic block map. If there
    // isn't one the basic block is being deleted. If the BB is required for
    // layouting (is referenced by another BB) this will cause an error, but
    // we'll find that out when we build the block(s).
    BasicBlock* bb = *bb_it;
    BasicBlockMap::const_iterator bb_map_it = bb_map_.find(bb->offset());
    if (bb_map_it == bb_map_.end())
      continue;

    block_count = std::max(block_count, bb_map_it->second.first);
    CHECK(reverse_map.insert(std::make_pair(bb_map_it->second, bb)).second);
  }
  ++block_count;

  // Create the necessary new block descriptions.
  BlockDescriptions block_descs;
  if (!CreateBlockDescriptions(block_count, bbsg, &block_descs))
    return false;
  DCHECK_EQ(block_count, block_descs.size());

  // The reverse map will be conveniently in sorted order for us. So we simply
  // need to append blocks to the block descriptions in the appropriate order.
  ReverseMap::iterator rev_map_it = reverse_map.begin();
  size_t prev_block_index = -1;
  size_t prev_bb_index = -1;
  for (; rev_map_it != reverse_map.end(); ++rev_map_it) {
    size_t block_index = rev_map_it->first.first;
    size_t bb_index = rev_map_it->first.second;
    BasicBlock* bb = rev_map_it->second;

    // We validate the basic block map by ensuring that it specifies each
    // block using values [0, block_count) and that the basic blocks are also
    // specified contiguously from 0.
    if (block_index != prev_block_index) {
      if (block_index != prev_block_index + 1 || block_index >= block_count) {
        LOG(ERROR) << "Invalid block index in BasicBlockMap.";
        return false;
      }
      prev_bb_index = -1;
      prev_block_index = block_index;
    }

    if (bb_index != prev_bb_index + 1) {
      LOG(ERROR) << "Invalid basic block index in BasicBlockMap.";
      return false;
    }
    prev_bb_index = bb_index;

    // Append this basic block to the appropriate block description.
    block_descs[block_index]->basic_block_order.push_back(bb);
  }

  // All blocks should have been written to.
  if (prev_block_index + 1 != block_count) {
    LOG(ERROR) << "Not all blocks were written to.";
    return false;
  }

  return true;
}

bool BasicBlockSubGraphLayoutTransform::CreateBlockDescriptions(
    size_t block_count,
    BasicBlockSubGraph* bbsg,
    BlockDescriptions* block_descs) {
  DCHECK(bbsg != NULL);
  DCHECK(block_descs != NULL);
  DCHECK(block_descs->empty());

  // Get the original block description and empty its list of basic blocks.
  BasicBlockSubGraph::BlockDescriptionList::iterator orig_block_desc =
      bbsg->block_descriptions().begin();
  orig_block_desc->basic_block_order.clear();

  block_descs->reserve(block_count);
  block_descs->push_back(&(*orig_block_desc));

  DCHECK_EQ(1u, bbsg->block_descriptions().size());

  if (block_count == 1)
    return true;

  // TODO(chrisha): We could be more specific in setting CODE or DATA block
  //     type by analyzing basic-block types. If any CODE basic blocks exist,
  //     the block type should be code. Otherwise, it should be data.

  // If we're outputting to multiple blocks, then create the appropriate
  // number of block descriptions. The block descriptions are identical to the
  // input block description.
  for (size_t i = 1; i < block_count; ++i) {
    std::string name = base::StringPrintf(
        "%s[%d]", orig_block_desc->name.c_str(), i);

    BasicBlockSubGraph::BlockDescription* block_desc =
        bbsg->AddBlockDescription(name,
                                  orig_block_desc->compiland_name,
                                  orig_block_desc->type,
                                  orig_block_desc->section,
                                  orig_block_desc->alignment,
                                  orig_block_desc->attributes);
    if (block_desc == NULL) {
      LOG(ERROR) << "Failed to create new block description.";
      return false;
    }
    block_descs->push_back(block_desc);
  }

  DCHECK_EQ(block_count, block_descs->size());

  return true;
}

}  // namespace transforms
}  // namespace reorder
