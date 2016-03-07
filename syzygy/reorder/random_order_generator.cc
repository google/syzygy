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

#include "syzygy/reorder/random_order_generator.h"

#include <algorithm>

#include "syzygy/core/random_number_generator.h"
#include "syzygy/pe/pe_utils.h"

namespace reorder {

RandomOrderGenerator::RandomOrderGenerator(int seed)
    : Reorderer::OrderGenerator("Random Order Generator"),
      seed_(seed) {
}

RandomOrderGenerator::~RandomOrderGenerator() {
}

bool RandomOrderGenerator::OnCodeBlockEntry(const BlockGraph::Block* /*block*/,
                                            RelativeAddress /*address*/,
                                            uint32_t /*process_id*/,
                                            uint32_t /*thread_id*/,
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
  order->comment = "Random block ordering";
  order->sections.clear();
  order->sections.resize(image.sections.size());
  for (size_t i = 0; i < image.sections.size(); ++i) {
    const ImageLayout::SectionInfo& section = image.sections[i];
    order->sections[i].id = i;
    order->sections[i].name = section.name;
    order->sections[i].characteristics = section.characteristics;

    // Prepare to iterate over all block in the section.
    BlockGraph::AddressSpace::Range section_range(section.addr, section.size);
    AddressSpace::RangeMapConstIterPair section_blocks(
        image.blocks.GetIntersectingBlocks(
            section_range.start(), section_range.size()));

    // Gather up all blocks within the section.
    AddressSpace::RangeMapConstIter& section_it = section_blocks.first;
    const AddressSpace::RangeMapConstIter& section_end = section_blocks.second;
    for (; section_it != section_end; ++section_it) {
      const BlockGraph::Block* block = section_it->second;
      order->sections[i].blocks.push_back(Order::BlockSpec(block));
    }

    bool is_code = (section.characteristics & IMAGE_SCN_CNT_CODE) != 0;
    bool is_data = !is_code;
    // If we're not supposed to randomly reorder this section, then we're done.
    if ((is_code && !reorder_code) || (is_data && !reorder_data))
      continue;

    // Otherwise, randomly shuffle blocks in this section.
    LOG(INFO) << "Randomizing section " << i  << " (" << section.name << ").";
    core::RandomNumberGenerator random_number_generator(seed_ + i);
    std::random_shuffle(order->sections[i].blocks.begin(),
                        order->sections[i].blocks.end(),
                        random_number_generator);
  }

  return true;
}

}  // namespace reorder
