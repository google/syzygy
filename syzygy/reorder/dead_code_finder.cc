// Copyright 2011 Google Inc. All Rights Reserved.
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

#include "syzygy/reorder/dead_code_finder.h"

namespace reorder {

DeadCodeFinder::DeadCodeFinder()
    : Reorderer::OrderGenerator("Dead Code Finder") {
}

DeadCodeFinder::~DeadCodeFinder() {
}

bool DeadCodeFinder::OnCodeBlockEntry(const Block* block,
                                      RelativeAddress /*address*/,
                                      uint32_t /*process_id*/,
                                      uint32_t /*thread_id*/,
                                      const UniqueTime& /*time*/) {
  visited_blocks_.insert(block);
  return true;
}

bool DeadCodeFinder::IsDead(const Block* block) const {
  // We don't consider gap blocks as interesting for the purposes of dead code
  // identification. We don't have good names for these blocks, so they end up
  // just being noise (not easily actionable) for the consumer of the dead code
  // finder's output.
  return ((block->attributes() & BlockGraph::GAP_BLOCK) == 0)
      && (visited_blocks_.find(block) == visited_blocks_.end());
}

bool DeadCodeFinder::CalculateReordering(const PEFile& pe_file,
                                         const ImageLayout& image,
                                         bool reorder_code,
                                         bool reorder_data,
                                         Order* order) {
  DCHECK(order != NULL);

  order->comment = "Unvisited blocks per section";
  order->sections.clear();
  order->sections.resize(image.sections.size());
  for (size_t i = 0; i < image.sections.size(); ++i) {
    const ImageLayout::SectionInfo& section = image.sections[i];
    order->sections[i].id = i;
    order->sections[i].name = section.name;
    order->sections[i].characteristics = section.characteristics;
    if ((section.characteristics & IMAGE_SCN_CNT_CODE) == 0)
      continue;

    // Prepare to iterate over all block in the section.
    BlockGraph::AddressSpace::Range section_range(section.addr, section.size);
    AddressSpace::RangeMapConstIterPair section_blocks(
        image.blocks.GetIntersectingBlocks(
            section_range.start(), section_range.size()));

    // Gather up all unvisited blocks within the section in the "order".
    AddressSpace::RangeMapConstIter& section_it = section_blocks.first;
    const AddressSpace::RangeMapConstIter& section_end = section_blocks.second;
    Order::BlockSpecVector& block_vector = order->sections[i].blocks;
    for (; section_it != section_end; ++section_it) {
      const BlockGraph::Block* block = section_it->second;
      if (IsDead(block)) {
        block_vector.push_back(Order::BlockSpec(block));
      }
    }
  }

  return true;
}

}  // namespace reorder
