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

#include "syzygy/reorder/orderers/explicit_orderer.h"

#include <algorithm>
#include <vector>

#include "base/stringprintf.h"

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

  typedef Reorderer::Order::BlockListMap BlockListMap;
  typedef Reorderer::Order::BlockList BlockList;

  BlockVector sorted_blocks;
  GetSortedBlocks(bg, &sorted_blocks);

  BlockListMap::const_iterator section_it = order_->section_block_lists.begin();
  for (; section_it != order_->section_block_lists.end(); ++section_it) {
    // Find the section in the original block-graph with the same ID.
    BlockGraph::Section* section = bg->GetSectionById(section_it->first);
    if (section == NULL) {
      LOG(ERROR) << "No section found with ID " << section_it->first << ".";
      return false;
    }

    LOG(INFO) << "Applying order to section " << section_it->first
              << "(" << section->name() << ").";

    // We walk through these in reverse order so that we can use PlaceAtHead.
    for (size_t i = section_it->second.size(); i > 0; --i) {
      // Look for the block with the matching address in memory. We do this
      // just in case the BlockGraph has evolved since the order object was
      // built.
      const BlockGraph::Block* block = section_it->second[i - 1];
      BlockVector::const_iterator block_it =
          std::lower_bound(sorted_blocks.begin(),
                           sorted_blocks.end(),
                           block);

      // Not found?
      if (block_it == sorted_blocks.end() || *block_it != block) {
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
