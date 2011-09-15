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
#include "syzygy/core/random_number_generator.h"

#include <algorithm>
#include "base/file_util.h"
#include "base/json/json_reader.h"
#include "base/values.h"

namespace relink {

RandomRelinker::RandomRelinker(uint32 seed) : seed_(seed) {
}

bool RandomRelinker::SetupOrdering(Reorderer::Order& /*order*/) {
  // Nothing to do.
  return true;
}

bool RandomRelinker::ReorderSection(size_t section_index,
                                    const IMAGE_SECTION_HEADER& section,
                                    const Reorderer::Order& /*order*/ ) {
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

  core::RandomNumberGenerator random_number_generator(seed_ + section_index);
  std::random_shuffle(blocks.begin(), blocks.end(), random_number_generator);

  // Insert the blocks into the section in the new order.
  RelativeAddress section_start = builder().next_section_address();
  RelativeAddress insert_at = section_start;
  BlockList::const_iterator block_iter = blocks.begin();
  for (; block_iter != blocks.end(); ++block_iter) {
    BlockGraph::Block* block = *block_iter;

    // TODO(chrisha): There's presently a bunch of duplicated code here
    //     in each of the relinkers. A better API for the Relinker base-class
    //     would remove this duplication.

    // If this block is a padding block, and it has no references or referrers,
    // then we need not output it.
    if (block->attributes() & BlockGraph::PADDING_BLOCK &&
        block->references().size() == 0 && block->referrers().size() == 0)
      continue;

    // Align the output cursor.
    size_t padding = insert_at.AlignUp(block->alignment()) - insert_at;
    if (!InsertPaddingBlock(block->type(), padding, &insert_at))
      return false;

    if (!builder().address_space().InsertBlock(insert_at, block)) {
      LOG(ERROR) << "Unable to insert block '" << block->name()
          << "' at " << insert_at;
    }

    insert_at += block->size();

    // If padding is enabled, create a new block and tack it on between the
    // current block and the subsequent block.
    if (!InsertPaddingBlock(block->type(), padding_length(), &insert_at))
      return false;
  }

  // Create the reodered section.
  const std::string section_name(pe::PEFile::GetSectionName(section));
  size_t section_length = insert_at - section_start;
  builder().AddSegment(section_name.c_str(),
                       section_length,
                       section_length,
                       section.Characteristics);

  return true;
}

}  // namespace relink
