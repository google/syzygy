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

#include "syzygy/block_graph/orderers/random_orderer.h"

#include <time.h>

namespace block_graph {
namespace orderers {

const char RandomOrderer::kOrdererName[] = "RandomOrderer";

RandomOrderer::RandomOrderer(bool default_shuffle_section)
    : default_shuffle_section_(default_shuffle_section),
      rng_(static_cast<uint32_t>(time(NULL))) {
}

RandomOrderer::RandomOrderer(bool default_shuffle_section, uint32_t seed)
    : default_shuffle_section_(default_shuffle_section), rng_(seed) {
}

void RandomOrderer::SetShuffleSection(const BlockGraph::Section* section,
                                      bool shuffle) {
  DCHECK(section != NULL);
  shuffle_map_[section] = shuffle;
}

bool RandomOrderer::ShouldShuffleSection(
    const BlockGraph::Section* section) const {
  // Look for an overridden value, otherwise use the default.
  ShuffleMap::const_iterator shuffle_map_it = shuffle_map_.find(section);
  if (shuffle_map_it != shuffle_map_.end())
    return shuffle_map_it->second;
  return default_shuffle_section_;
}

bool RandomOrderer::OrderBlockGraph(OrderedBlockGraph* ordered_block_graph,
                                    BlockGraph::Block* /* header_block */) {
  DCHECK(ordered_block_graph != NULL);

  // Run through the sections shuffling those that we need to.
  OrderedBlockGraph::SectionList::const_iterator section_it =
      ordered_block_graph->ordered_sections().begin();
  for (; section_it != ordered_block_graph->ordered_sections().end();
       ++section_it) {
    const BlockGraph::Section* section = (*section_it)->section();

    // Shuffle the sections.
    if (ShouldShuffleSection(section))
      ShuffleBlocks(*section_it, ordered_block_graph);
  }

  return true;
}

void RandomOrderer::ShuffleBlocks(
    const OrderedBlockGraph::OrderedSection* section, OrderedBlockGraph* obg) {
  DCHECK(section != NULL);

  BlockVector blocks(section->ordered_blocks().begin(),
                     section->ordered_blocks().end());
  std::random_shuffle(blocks.begin(), blocks.end(), rng_);

  for (size_t i = 0; i < blocks.size(); ++i)
    obg->PlaceAtTail(section->section(), blocks[i]);
}

}  // namespace orderers
}  // namespace block_graph
