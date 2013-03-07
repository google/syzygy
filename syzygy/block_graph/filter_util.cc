// Copyright 2013 Google Inc. All Rights Reserved.
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

#include "syzygy/block_graph/filter_util.h"

namespace block_graph {

bool IsFiltered(const RelativeAddressFilter& filter,
                const BlockGraph::Block* block) {
  DCHECK(block != NULL);

  // We iterate over all of the source ranges in the block. If any of them are
  // marked then we return false.
  BlockGraph::Block::SourceRanges::RangePairs::const_iterator it =
      block->source_ranges().range_pairs().begin();
  for (; it != block->source_ranges().range_pairs().end(); ++it) {
    // If a block is *not* unmarked, then it's at least partially marked.
    // Which to us means it is filtered.
    if (!filter.IsUnmarked(it->second))
      return true;
  }

  return false;
}

bool IsFiltered(const RelativeAddressFilter& filter,
                const BasicBlock* basic_block) {
  DCHECK(basic_block != NULL);

  if (basic_block->type() == BasicBlock::BASIC_DATA_BLOCK) {
    const BasicDataBlock* basic_data_block = BasicDataBlock::Cast(basic_block);
    DCHECK(basic_data_block != NULL);
    if (!IsFiltered(filter, basic_data_block))
      return false;
  } else {
    DCHECK_EQ(BasicBlock::BASIC_CODE_BLOCK, basic_block->type());
    const BasicCodeBlock* basic_code_block = BasicCodeBlock::Cast(basic_block);
    DCHECK(basic_code_block != NULL);
    if (!IsFiltered(filter, basic_code_block))
      return false;
  }

  return true;
}

bool IsFiltered(const RelativeAddressFilter& filter,
                const BasicCodeBlock* basic_block) {
  DCHECK(basic_block != NULL);

  // Iterate over all of the instructions and check their source ranges. If any
  // of them are at all marked then the basic block is filtered.
  BasicBlock::Instructions::const_iterator it =
      basic_block->instructions().begin();
  for (; it != basic_block->instructions().end(); ++it) {
    if (!filter.IsUnmarked(it->source_range()))
      return true;
  }

  return false;
}

bool IsFiltered(const RelativeAddressFilter& filter,
                const BasicDataBlock* basic_block) {
  DCHECK(basic_block != NULL);

  if (filter.IsUnmarked(basic_block->source_range()))
    return false;

  return true;
}

bool IsFiltered(const RelativeAddressFilter& filter,
                const Instruction& instruction) {
  if (filter.IsUnmarked(instruction.source_range()))
    return false;

  return true;
}

}  // namespace block_graph
