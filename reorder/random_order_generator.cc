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
#include "syzygy/core/random_number_generator.h"

#include <algorithm>
namespace reorder {

RandomOrderGenerator::RandomOrderGenerator(int seed)
    : Reorderer::OrderGenerator("Random Order Generator"),
      seed_(seed) {
}

RandomOrderGenerator::~RandomOrderGenerator() {
}

bool RandomOrderGenerator::OnCodeBlockEntry(const Reorderer& /*reorderer*/,
                                            const BlockGraph::Block* /*block*/,
                                            RelativeAddress /*address*/,
                                            uint32 /*process_id*/,
                                            uint32 /*thread_id*/,
                                            const UniqueTime& /*time*/) {
  // This is a NOP.
  return true;
}

bool RandomOrderGenerator::CalculateReordering(const Reorderer& reorderer,
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
    const std::string section_name(pe::PEFile::GetSectionName(section));

    if (!reorderer.MustReorder(i)) {
      LOG(INFO) << "Skipping section " << i  << " (" << section_name << ").";
      continue;
    }

    LOG(INFO) << "Randomizing section " << i  << " (" << section_name << ").";

    // Prepare to iterate over all block in the section.
    BlockGraph::AddressSpace::Range section_range(
        RelativeAddress(section.VirtualAddress), section.Misc.VirtualSize);
    AddressSpace::RangeMapConstIterPair section_blocks(
        order->image.address_space.GetIntersectingBlocks(section_range.start(),
                                                         section_range.size()));

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
