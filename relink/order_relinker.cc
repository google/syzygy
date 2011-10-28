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

#include "syzygy/relink/order_relinker.h"

#include "base/file_util.h"
#include "base/json/json_reader.h"
#include "base/values.h"

namespace relink {

namespace {

// We use this for aligning sub-sections within sections. It should ideally
// correspond to a cache page size.
// TODO(chrisha): Expose this somewhere central?
const size_t kPageSize = 4096;

// Returns true if the given block matches the BlockInitType.
bool BlockMatchesInitType(OrderRelinker::BlockInitType block_init_type,
                          const core::BlockGraph::Block* block) {
  DCHECK(block != NULL);

  switch (block_init_type) {
    case OrderRelinker::INITIALIZED_BLOCKS:
      return block->data() != NULL;

    case OrderRelinker::UNINITIALIZED_BLOCKS:
      return block->data() == NULL;

    case OrderRelinker::ALL_BLOCKS:
      return true;

    default:
      NOTREACHED() << "Unknown BlockInitType.";
      return false;
  }
}

}  // namespace

OrderRelinker::OrderRelinker(const FilePath& order_file_path)
    : order_file_path_(order_file_path) {
  DCHECK(!order_file_path.empty());
}

bool OrderRelinker::SetupOrdering(const PEFile& pe_file,
                                  const DecomposedImage& image,
                                  Reorderer::Order* order) {
  DCHECK(order != NULL);
  DCHECK(!order_file_path_.empty());
  return order->LoadFromJSON(pe_file, image, order_file_path_);
}

bool OrderRelinker::ReorderSection(size_t section_index,
                                   const ImageLayout::SectionInfo& section,
                                   const Reorderer::Order& order) {
  DCHECK(!order_file_path_.empty());

  // We only reorder the section if a non-empty ordering has actually been
  // provided. Otherwise, we simply copy the section as is.
  Reorderer::Order::BlockListMap::const_iterator section_iter =
      order.section_block_lists.find(section_index);
  if (section_iter == order.section_block_lists.end() ||
      section_iter->second.size() == 0) {
    LOG(INFO) << "No ordering for '" << section.name << "', copying it.";
    return CopySection(section);
  }

  const BlockList& block_order(section_iter->second);

  RelativeAddress section_start = builder().next_section_address();
  RelativeAddress insert_at = section_start;
  BlockSet inserted_blocks;

  if (!OutputBlocks(INITIALIZED_BLOCKS, section, block_order,
                    &inserted_blocks, &insert_at)) {
    return false;
  }

  // Align to a new page boundary before outputting uninitialized blocks.
  size_t padding = insert_at.AlignUp(kPageSize) - insert_at;
  if (!InsertPaddingBlock((*block_order.begin())->type(), padding, &insert_at))
    return false;

  size_t section_data_size = insert_at - section_start;

  if (!OutputBlocks(UNINITIALIZED_BLOCKS, section, block_order,
                    &inserted_blocks, &insert_at))
    return false;

  size_t section_size = insert_at - section_start;

  // Create the reordered section.
  builder().AddSection(section.name.c_str(),
                       section_size,
                       section_data_size,
                       section.characteristics);

  return true;
}

bool OrderRelinker::OutputPadding(BlockInitType block_init_type,
                                  BlockGraph::BlockType block_type,
                                  size_t size,
                                  RelativeAddress* insert_at) {
  DCHECK(insert_at != NULL);

  switch (block_init_type) {
    case INITIALIZED_BLOCKS:
    case ALL_BLOCKS: {
      return InsertPaddingBlock(block_type, size, insert_at);
    }

    case UNINITIALIZED_BLOCKS: {
      *insert_at += size;
      return true;
    }

    default: {
      NOTREACHED() << "Unknown BlockInitType.";
      return false;
    }
  }
}

bool OrderRelinker::OutputBlocks(BlockInitType block_init_type,
                                 const ImageLayout::SectionInfo& section,
                                 const BlockList& block_order,
                                 BlockSet* inserted_blocks,
                                 RelativeAddress* insert_at) {
  DCHECK(inserted_blocks != NULL);
  DCHECK(insert_at != NULL);

  // Insert the ordered blocks into the new address space.
  BlockList::const_iterator block_iter = block_order.begin();
  for (; block_iter != block_order.end(); ++block_iter) {
    const BlockGraph::Block* block = *block_iter;

    // TODO(chrisha): There's presently a bunch of duplicated code here
    //     in each of the relinkers. A better API for the Relinker base-class
    //     would remove this duplication.

    if (!BlockMatchesInitType(block_init_type, block))
      continue;

    // The ordering file shouldn't list a given block twice. But let's not
    // take anybody's word on that!
    if (inserted_blocks->find(block) != inserted_blocks->end()) {
      LOG(WARNING) << "Ordering lists " << block->name() << " multiple times.";
      continue;
    }

    // Align the output cursor.
    size_t padding = insert_at->AlignUp(block->alignment()) - *insert_at;
    if (!OutputPadding(block_init_type, block->type(), padding, insert_at))
      return false;

    // Need to cast away constness to insert the block into the builder's
    // address space.  We "know" that the builder isn't going to add
    // any new references to the block at this point.
    if (!builder().image_layout().blocks.InsertBlock(
            *insert_at, const_cast<BlockGraph::Block*>(block))) {
      LOG(ERROR) << "Unable to insert block '" << block->name() << "' at "
                 << *insert_at;
    }
    *insert_at += block->size();
    inserted_blocks->insert(block);

    // If padding is enabled, create a new block and tack it on between the
    // current block and the subsequent block.
    if (!OutputPadding(block_init_type, block->type(), padding_length(),
                       insert_at))
      return false;
  }

  // Now output those blocks that are selected but that do not have an
  // explicit ordering.
  RelativeAddress orig_section_start = section.addr;
  AddressSpace::RangeMapConstIterPair section_blocks =
      original_addr_space().GetIntersectingBlocks(orig_section_start,
                                                  section.size);
  AddressSpace::RangeMapConstIter& section_it = section_blocks.first;
  const AddressSpace::RangeMapConstIter& section_end = section_blocks.second;
  for (; section_it != section_end; ++section_it) {
    BlockGraph::Block* block = section_it->second;
    if (inserted_blocks->find(block) != inserted_blocks->end())
      continue;

    if (!BlockMatchesInitType(block_init_type, block))
      continue;

    // Align the output cursor.
    size_t padding = insert_at->AlignUp(block->alignment()) - *insert_at;
    if (!OutputPadding(block_init_type, block->type(), padding, insert_at))
      return false;

    if (!builder().image_layout().blocks.InsertBlock(*insert_at, block)) {
      LOG(ERROR) << "Unable to insert block '" << block->name() << "' at "
                 << *insert_at;
    }

    *insert_at += block->size();
    inserted_blocks->insert(block);

    // If padding is enabled, create a new block and tack it on between the
    // current block and the subsequent block.
    if (!OutputPadding(block_init_type, block->type(), padding_length(),
                       insert_at))
      return false;
  }

  return true;
}

}  // namespace relink
