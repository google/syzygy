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

#include "syzygy/block_graph/iterate.h"

namespace block_graph {

bool IterateBlockGraph(const IterationCallback& callback,
                       BlockGraph* block_graph) {
  DCHECK(block_graph != NULL);

  if (block_graph->blocks().size() == 0)
    return true;

  // Get the ID of the last existing block in iterator order.
  BlockGraph::BlockMap::iterator last_block_it =
      block_graph->blocks_mutable().end();
  --last_block_it;
  BlockGraph::BlockId last_block_id = last_block_it->second.id();

  // Iterate through all blocks. We stop after having visited the last block
  // that was pre-existing prior to the iteration.
  BlockGraph::BlockMap::iterator block_it =
      block_graph->blocks_mutable().begin();
  BlockGraph::BlockId id = 0;
  do {
    // Get the block ID and the next block prior to invoking the callback.
    // This is because the callback is allowed to delete the current block, and
    // it may not be valid to use block_it after the callback completes.
    id = block_it->second.id();
    BlockGraph::BlockMap::iterator next_block_it = block_it;
    ++next_block_it;

    if (!callback.Run(block_graph, &block_it->second)) {
      LOG(ERROR) << "IterateBlocks callback failed for block "
                 << "\"" << block_it->second.name() << "\".";
      return false;
    }

    block_it = next_block_it;
  } while (id != last_block_id);

  return true;
}

}  // namespace block_graph
