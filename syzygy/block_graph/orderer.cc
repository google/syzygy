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

#include "syzygy/block_graph/orderer.h"

namespace block_graph {

// Applies a vector of BlockGraphOrderers.
// @param orderers The vector of orderers.
// @param ordered_block_graph the block graph to order.
// @param header_block The header block of the block graph to transform.
// @returns true on success, false otherwise.
bool ApplyBlockGraphOrderers(
    const std::vector<BlockGraphOrdererInterface*>& orderers,
    OrderedBlockGraph* ordered_block_graph,
    BlockGraph::Block* header_block) {
  DCHECK_NE(reinterpret_cast<OrderedBlockGraph*>(NULL), ordered_block_graph);
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), header_block);
  for (size_t i = 0; i < orderers.size(); ++i) {
    DCHECK_NE(reinterpret_cast<BlockGraphOrdererInterface*>(NULL), orderers[i]);
    LOG(INFO) << "Applying orderer \"" << orderers[i]->name() << "\".";
    if (!orderers[i]->OrderBlockGraph(ordered_block_graph, header_block)) {
      LOG(ERROR) << "Orderer \"" << orderers[i]->name() << "\" failed.";
      return false;
    }
  }

  return true;
}

}  // namespace block_graph
