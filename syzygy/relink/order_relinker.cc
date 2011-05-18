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

OrderRelinker::OrderRelinker() {
}

void OrderRelinker::set_order_file(const FilePath& order_file_path) {
  DCHECK(!order_file_path.empty());
  order_file_path_ = order_file_path;
}

bool OrderRelinker::ReorderSection(const IMAGE_SECTION_HEADER& section) {
  // TODO(rogerm) We should try to preserve the location of a block as
  //     being inside the initialized or unitilialized part of the section.
  //     For now, we punt by simply making the entire section initialized,
  //     but this increases the cost of paging in blocks that could otherwise
  //     originate in the unitialized part of the section.
  DCHECK(!order_file_path_.empty());

  std::string file_string;
  if (!file_util::ReadFileToString(order_file_path_, &file_string)) {
    LOG(ERROR) << "Unable to read order file to string";
    return false;
  }

  scoped_ptr<Value> value(base::JSONReader::Read(file_string, false));
  ListValue* order;
  if (value.get() == NULL || !value->GetAsList(&order)) {
    LOG(ERROR) << "Order file does not contain a valid JSON list";
    return false;
  }

  RelativeAddress section_start = builder().next_section_address();
  RelativeAddress insert_at = section_start;
  std::set<BlockGraph::Block*> inserted_blocks;

  // Insert the ordered blocks into the new address space.
  ListValue::iterator iter = order->begin();
  for (; iter != order->end(); ++iter) {
    int address;
    if (!(*iter)->GetAsInteger(&address)) {
      LOG(ERROR) << "Unable to read address value from order list";
      return false;
    }

    BlockGraph::Block* block = original_addr_space().GetBlockByAddress(
        RelativeAddress(address));
    if (!block) {
      LOG(ERROR) << "Unable to get block at address " << address;
      return false;
    }
    // Two separate RVAs may point to the same block, so make sure we only
    // insert each block once.
    if (inserted_blocks.find(block) != inserted_blocks.end())
      continue;

    if (!builder().address_space().InsertBlock(insert_at, block)) {
      LOG(ERROR) << "Unable to insert block '" << block->name() << "' at "
          << insert_at;
    }
    insert_at += block->size();
    inserted_blocks.insert(block);

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

  // To make sure we don't omit any blocks, iterate over all the blocks
  // in the section and append any blocks that weren't mentioned by the
  // ordering.
  BlockGraph::AddressSpace::Range section_range(
      RelativeAddress(section.VirtualAddress), section.Misc.VirtualSize);
  AddressSpace::RangeMapConstIterPair section_blocks =
      original_addr_space().GetIntersectingBlocks(section_range.start(),
                                                  section_range.size());

  AddressSpace::RangeMapConstIter& section_it = section_blocks.first;
  const AddressSpace::RangeMapConstIter& section_end = section_blocks.second;
  for (; section_it != section_end; ++section_it) {
    BlockGraph::Block* block = section_it->second;
    if (inserted_blocks.find(block) != inserted_blocks.end())
      continue;

    if (!builder().address_space().InsertBlock(insert_at, block)) {
      LOG(ERROR) << "Unable to insert block '" << block->name() << "' at "
          << insert_at;
    }

    insert_at += block->size();
    inserted_blocks.insert(block);

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

  // Create the reordered section.
  std::string section_name = GetSectionName(section);
  size_t section_length = insert_at - section_start;
  builder().AddSegment(section_name.c_str(),
                       section_length,
                       section_length,
                       section.Characteristics);

  return true;
}
