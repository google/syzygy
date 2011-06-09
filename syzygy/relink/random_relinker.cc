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

#include "syzygy/relink/random_relinker.h"

#include <algorithm>
#include "base/file_util.h"
#include "base/json/json_reader.h"
#include "base/values.h"

namespace relink {

RandomRelinker::RandomRelinker(uint32 seed) : random_number_generator_(seed) {
}

bool RandomRelinker::SetupOrdering(Reorderer::Order& /*order*/) {
  // Nothing to do.
  return true;
}

bool RandomRelinker::ReorderSection(size_t /*section_index*/,
                                    const IMAGE_SECTION_HEADER& section,
                                    const Reorderer::Order& /*order*/ ) {
  // TODO(rogerm) We need to make sure we preserve the location of a block as
  //     being inside the initialized or unitilialized part of the section.
  //     For now, we punt by simply making the entire section initialized,
  //     but this increases the cost of paging in blocks that could otherwise
  //     originate in the unitialized part of the section.
  typedef std::vector<BlockGraph::Block*> BlockList;

  // Prepare to iterate over all block in the section.
  BlockGraph::AddressSpace::Range section_range(
      RelativeAddress(section.VirtualAddress), section.Misc.VirtualSize);
  AddressSpace::RangeMapConstIterPair section_blocks(
      original_addr_space().GetIntersectingBlocks(section_range.start(),
                                                  section_range.size()));

  // Gather up all blocks within the section.
  AddressSpace::RangeMapConstIter& section_it = section_blocks.first;
  const AddressSpace::RangeMapConstIter& section_end = section_blocks.second;
  BlockList blocks;
  for (; section_it != section_end; ++section_it) {
    BlockGraph::Block* block = section_it->second;
    blocks.push_back(block);
  }

  std::random_shuffle(blocks.begin(), blocks.end(), random_number_generator_);

  // Insert the blocks into the section in the new order.
  RelativeAddress section_start = builder().next_section_address();
  RelativeAddress insert_at = section_start;
  BlockList::const_iterator block_iter = blocks.begin();
  for (;block_iter != blocks.end(); ++block_iter) {
    BlockGraph::Block* block = *block_iter;

    // Align the output cursor.
    // TODO(chrisha): Output 0xcc bytes here.
    insert_at = insert_at.AlignUp(block->alignment());

    if (!builder().address_space().InsertBlock(insert_at, block)) {
      LOG(ERROR) << "Unable to insert block '" << block->name()
          << "' at " << insert_at;
    }

    insert_at += block->size();

    // If padding is enabled, create a new block and tack it on between the
    // current block and the subsequent block.
    BlockGraph::Block* padding_block = NULL;
    if (!InsertPaddingBlock(insert_at, block->type(), &padding_block)) {
      LOG(ERROR)
          << "Unable to insert padding block at " << insert_at
          << " after '" << block->name() << "'.";
      return false;
    }
    if (padding_block != NULL) {
      insert_at += padding_block->size();
    }
  }

  // Create the reodered section.
  std::string section_name = GetSectionName(section);
  size_t section_length = insert_at - section_start;
  builder().AddSegment(section_name.c_str(),
                       section_length,
                       section_length,
                       section.Characteristics);

  return true;
}

}  // namespace relink
