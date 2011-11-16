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

#include "syzygy/reorder/random_order_generator.h"

#include <algorithm>

#include "syzygy/core/random_number_generator.h"

namespace reorder {

namespace {

const DWORD kDataCharacteristics =
    IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_CNT_UNINITIALIZED_DATA;

}  // namespace

RandomOrderGenerator::RandomOrderGenerator(int seed)
    : Reorderer::OrderGenerator("Random Order Generator"),
      seed_(seed) {
}

RandomOrderGenerator::~RandomOrderGenerator() {
}

bool RandomOrderGenerator::OnCodeBlockEntry(const BlockGraph::Block* /*block*/,
                                            RelativeAddress /*address*/,
                                            uint32 /*process_id*/,
                                            uint32 /*thread_id*/,
                                            const UniqueTime& /*time*/) {
  // This is a NOP.
  return true;
}

bool RandomOrderGenerator::CalculateReordering(const PEFile& pe_file,
                                               const ImageLayout& image,
                                               bool reorder_code,
                                               bool reorder_data,
                                               Order* order) {
  DCHECK(order != NULL);

  for (size_t i = 0; i < image.sections.size(); ++i) {
    const ImageLayout::SectionInfo& section = image.sections[i];
    if ((!reorder_code && section.characteristics & IMAGE_SCN_CNT_CODE) ||
        (!reorder_data && section.characteristics & kDataCharacteristics))
      continue;

    LOG(INFO) << "Randomizing section " << i  << " (" << section.name << ").";

    // Prepare to iterate over all block in the section.
    BlockGraph::AddressSpace::Range section_range(section.addr, section.size);
    AddressSpace::RangeMapConstIterPair section_blocks(
        image.blocks.GetIntersectingBlocks(
            section_range.start(), section_range.size()));

    // Gather up all blocks within the section.
    AddressSpace::RangeMapConstIter& section_it = section_blocks.first;
    const AddressSpace::RangeMapConstIter& section_end = section_blocks.second;
    Order::BlockList& block_list = order->section_block_lists[i];
    for (; section_it != section_end; ++section_it) {
      const BlockGraph::Block* block = section_it->second;
      block_list.push_back(block);
    }

    core::RandomNumberGenerator random_number_generator(seed_ + i);
    std::random_shuffle(block_list.begin(),
                        block_list.end(),
                        random_number_generator);
  }

  return true;
}

}  // namespace reorder
