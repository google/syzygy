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

  BlockVector sorted_blocks;
  GetSortedBlocks(bg, &sorted_blocks);

  Reorderer::Order::SectionSpecVector::const_iterator section_it =
      order_->sections.begin();
  for (; section_it != order_->sections.end(); ++section_it) {
    // Find the section in the original block-graph with the same ID.
    const Reorderer::Order::SectionSpec& section_spec = *section_it;
    BlockGraph::Section* section = NULL;

    // Lookup or create the target section.
    // TODO(rogerm, chrisha): This responsibility belongs in the bb-layout
    //     transform. Remove/adjust this once that CL lands.
    if (section_spec.id == Reorderer::Order::SectionSpec::kNewSectionId) {
      // If the section is not given by id, then it needs to be created.
      section = bg->FindOrAddSection(section_spec.name,
                                     section_spec.characteristics);
      if (section == NULL) {
        LOG(ERROR) << "Failed to find or add section: "
                   << section_spec.name << ".";
        return false;
      }
    } else {  // section_spec.id != BlockGraph::kInvalidSection
      // If the section is given by ID then find it and update it's name and
      // characteristics as appropriate.
      section = bg->GetSectionById(section_spec.id);
      if (section == NULL) {
        LOG(ERROR) << "No section found with ID " << section_spec.id << ".";
        return false;
      }
      if (section->name() != section_spec.name) {
        LOG(INFO) << "Renaming section " << section->id() << " ("
                  << section->name() << ") to '" << section_spec.name << "'.";
        section->set_name(section_spec.name);
      }
      if (section->characteristics() != section_spec.characteristics) {
        LOG(INFO) << "Resetting section characteristics for section "
                  << section->id() << " (" << section->name() << ").";
        section->set_characteristic(section_spec.characteristics);
      }
    }

    DCHECK(section != NULL);
    LOG(INFO) << "Applying order to section " << section->id()
              << "(" << section->name() << ").";

    // We walk through these in reverse order so that we can use PlaceAtHead.
    for (size_t i = section_spec.blocks.size(); i > 0;) {
      // Look for the block with the matching address in memory. We do this
      // just in case the BlockGraph has evolved since the order object was
      // built.
      const Reorderer::Order::BlockSpec& block_spec = section_spec.blocks[--i];
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
