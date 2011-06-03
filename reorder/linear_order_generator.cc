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
#include "syzygy/reorder/linear_order_generator.h"

#include <algorithm>

namespace reorder {

LinearOrderGenerator::LinearOrderGenerator()
    : Reorderer::OrderGenerator("Linear Order Generator") {
}

LinearOrderGenerator::~LinearOrderGenerator() {
}

bool LinearOrderGenerator::OnCodeBlockEntry(const Reorderer& reorderer,
                                            const BlockGraph::Block* block,
                                            RelativeAddress address,
                                            uint32 process_id,
                                            uint32 thread_id,
                                            const UniqueTime& time) {
  return TouchBlock(block, time);
}

bool LinearOrderGenerator::CalculateReordering(const Reorderer& reorderer,
                                               Order* order) {
  DCHECK(order != NULL);

  // If data ordering is enabled, turn each code block event into a set
  // of data block events as well. This creates new blocks in the map as we go,
  // so we need to filter on code blocks only.
  if (reorderer.flags() & Reorderer::kFlagReorderData) {
    BlockCallMap::const_iterator it = block_calls_.begin();
    for (; it != block_calls_.end(); ++it) {
      DCHECK(it->first != NULL);
      if (it->first->type() == BlockGraph::CODE_BLOCK &&
          !TouchDataBlocks(it->first, it->second))
        return false;
    }
  }

  typedef std::vector<std::pair<UniqueTime, const BlockGraph::Block*> >
      BlockCallVector;

  // Turn the BlockCallMap into a BlockCallVector, and sort based on time.
  BlockCallVector calls(block_calls_.size());
  BlockCallMap::const_iterator it = block_calls_.begin();
  for (size_t i = 0; it != block_calls_.end(); ++it, ++i) {
    calls[i].first = it->second;
    calls[i].second = it->first;
  }
  std::sort(calls.begin(), calls.end());

  // Create the output, which is simply the new ordering of blocks, per section.
  // We currently throw away any blocks that map to an invalid section id.
  // TODO(chrisha): We need to make sure that all blocks in the decomposed
  //     image properly set the 'section' attribute of Block.
  for (size_t i = 0; i < calls.size(); ++i) {
    const BlockGraph::Block* block = calls[i].second;
    size_t section_id = block->section();
    if (section_id == core::kInvalidSection)
      continue;
    order->section_block_lists[section_id].push_back(block);
  }

  return true;
}

bool LinearOrderGenerator::TouchBlock(const BlockGraph::Block* block,
                                 const UniqueTime& time) {
  // Store the block along with the earliest time it was called.
  BlockCallMap::iterator it = block_calls_.find(block);
  if (it == block_calls_.end()) {
    std::pair<BlockCallMap::iterator, bool> insert_return;
    insert_return = block_calls_.insert(std::make_pair(block, time));
    it = insert_return.first;
    DCHECK(insert_return.second);
    DCHECK(it != block_calls_.end());
  } else {
    // Keep around the earliest call to this block only.
    it->second = std::min(it->second, time);
  }
  return true;
}

// Given a code block, touches the data blocks associated with it.
bool LinearOrderGenerator::TouchDataBlocks(const BlockGraph::Block* code_block,
                                           const UniqueTime& time) {
  DCHECK(code_block != NULL);
  DCHECK(code_block->type() == BlockGraph::CODE_BLOCK);

  // Iterate through any data blocks that are referenced by this
  // function, and also store them with the same time. This is a pessimistic
  // optimization, and assumes that all data linked to a code block will
  // be touched by that code block.
  BlockGraph::Block::ReferenceMap::const_iterator ref_it =
      code_block->references().begin();
  for (; ref_it != code_block->references().end(); ++ref_it) {
    const BlockGraph::Block* ref = ref_it->second.referenced();
    DCHECK(ref != NULL);
    // Only update non-code blocks, as we get all code-block events directly
    // from the trace.
    if (ref->type() == BlockGraph::CODE_BLOCK)
      continue;
    if (!TouchBlock(ref, time))
      return false;
  }
  return true;
}

}  // namespace reorder
