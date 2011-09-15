// Copyright 2011 Google Inc.
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
                                      uint32 /*process_id*/,
                                      uint32 /*thread_id*/,
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

bool DeadCodeFinder::CalculateReordering(bool /*reorder_code*/,
                                         bool /*reorder_data*/,
                                         Reorderer::Order* order) {
  DCHECK(order != NULL);

  const IMAGE_NT_HEADERS* nt_headers =
      reinterpret_cast<const IMAGE_NT_HEADERS*>(
          order->image.header.nt_headers->data());
  DCHECK(nt_headers != NULL);
  const IMAGE_SECTION_HEADER* sections =
      reinterpret_cast<const IMAGE_SECTION_HEADER*>(nt_headers + 1);

  for (size_t i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i) {
    const IMAGE_SECTION_HEADER& section = sections[i];
    if ((sections[i].Characteristics & IMAGE_SCN_CNT_CODE) == 0)
      continue;

    // Prepare to iterate over all block in the section.
    BlockGraph::AddressSpace::Range section_range(
        RelativeAddress(section.VirtualAddress), section.Misc.VirtualSize);
    AddressSpace::RangeMapConstIterPair section_blocks(
        order->image.address_space.GetIntersectingBlocks(section_range.start(),
                                                         section_range.size()));

    // Gather up all unvisited blocks within the section in the "order".
    AddressSpace::RangeMapConstIter& section_it = section_blocks.first;
    const AddressSpace::RangeMapConstIter& section_end = section_blocks.second;
    Order::BlockList& block_list = order->section_block_lists[i];
    for (; section_it != section_end; ++section_it) {
      const BlockGraph::Block* block = section_it->second;
      if (IsDead(block)) {
        block_list.push_back(block);
      }
    }
  }

  return true;
}

}  // namespace reorder
