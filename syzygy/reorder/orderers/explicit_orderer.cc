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

#include "syzygy/reorder/orderers/explicit_orderer.h"

#include <algorithm>
#include <vector>

#include "base/strings/stringprintf.h"

namespace reorder {
namespace orderers {

namespace {

using block_graph::BlockGraph;
using block_graph::BlockVector;
using core::RelativeAddress;

void GetSortedBlocks(BlockGraph* block_graph, BlockVector* blocks) {
  DCHECK(block_graph != NULL);
  DCHECK(blocks != NULL);

  blocks->clear();
  blocks->reserve(block_graph->blocks().size());

  BlockGraph::BlockMap::iterator block_it =
      block_graph->blocks_mutable().begin();
  for (; block_it != block_graph->blocks_mutable().end(); ++block_it) {
    BlockGraph::Block* block = &block_it->second;
    blocks->push_back(block);
  }

  // Sort by block address.
  std::sort(blocks->begin(), blocks->end());
}

}  // namespace

const char ExplicitOrderer::kOrdererName[] = "ExplicitOrderer";

bool ExplicitOrderer::OrderBlockGraph(
    OrderedBlockGraph* ordered_block_graph,
    BlockGraph::Block* /* header_block */) {
  DCHECK(ordered_block_graph != NULL);
  DCHECK(order_ != NULL);

  BlockGraph* bg = ordered_block_graph->block_graph();

  BlockVector sorted_blocks;
  GetSortedBlocks(bg, &sorted_blocks);

  Reorderer::Order::SectionSpecVector::const_iterator section_it =
      order_->sections.begin();
  for (; section_it != order_->sections.end(); ++section_it) {
    const Reorderer::Order::SectionSpec& section_spec = *section_it;

    // The section specification should always refer to a section that already
    // exists. They should all have been created by this point.
    DCHECK_NE(Reorderer::Order::SectionSpec::kNewSectionId, section_spec.id);

    // You can't specify ordering for 'special' blocks that lie outside of any
    // explicit section.
    DCHECK_NE(BlockGraph::kInvalidSectionId, section_spec.id);

    // Look up the section.
    BlockGraph::Section* section = bg->GetSectionById(section_spec.id);
    if (section == NULL) {
      LOG(ERROR) << "No section found with ID " << section_spec.id << ".";
      return false;
    }

    DCHECK(section != NULL);
    LOG(INFO) << "Applying order to section " << section->id()
              << " (" << section->name() << ").";

    // We walk through these in reverse order so that we can use PlaceAtHead.
    for (size_t i = section_spec.blocks.size(); i > 0;) {
      const Reorderer::Order::BlockSpec& block_spec = section_spec.blocks[--i];

      // Ensure the block-spec specifies a block without BB information. Any
      // BB ordering must already have been applied.
      if (!block_spec.basic_block_offsets.empty()) {
        LOG(ERROR) << "ExplicitOrderer can't handle basic-block orders.";
        return false;
      }

      // Look for the block with the matching address in memory. We do this
      // just in case the BlockGraph has evolved since the order object was
      // built.
      BlockVector::const_iterator block_it =
          std::lower_bound(sorted_blocks.begin(),
                           sorted_blocks.end(),
                           block_spec.block);

      // Not found?
      if (block_it == sorted_blocks.end() || *block_it != block_spec.block) {
        LOG(ERROR) << "Block specified in order does not exist in BlockGraph.";
        return false;
      }

      // At this point we have a single unique block that we've found, so
      // place it at the beginning of the section.
      ordered_block_graph->PlaceAtHead(section, *block_it);
    }
  }

  return true;
}

}  // namespace orderers
}  // namespace reorder
