// Copyright 2012 Google Inc. All Rights Reserved.
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
//
// Declares a simple API for ordering block graphs.

#ifndef SYZYGY_BLOCK_GRAPH_ORDERER_H_
#define SYZYGY_BLOCK_GRAPH_ORDERER_H_

#include "syzygy/block_graph/ordered_block_graph.h"

namespace block_graph {

// BlockGraphOrdererInterface is a pure virtual base class defining the orderer
// API.
class BlockGraphOrdererInterface {
 public:
  virtual ~BlockGraphOrdererInterface() { }

  // Gets the name of this orderer.
  //
  // @returns the name of this orderer.
  virtual const char* name() const = 0;

  // Applies this orderer to the provided block graph.
  //
  // @param ordered_block_graph the block graph to order.
  // @param header_block The header block of the block graph to transform.
  // @returns true on success, false otherwise.
  virtual bool OrderBlockGraph(OrderedBlockGraph* ordered_block_graph,
                               BlockGraph::Block* header_block) = 0;
};

// Applies a vector of BlockGraphOrderers.
// @param orderers The vector of orderers.
// @param ordered_block_graph The block graph to order.
// @param header_block The header block of the block graph to transform.
// @returns true on success, false otherwise.
bool ApplyBlockGraphOrderers(
    const std::vector<BlockGraphOrdererInterface*>& orderers,
    OrderedBlockGraph* ordered_block_graph,
    BlockGraph::Block* header_block);

}  // namespace block_graph

#endif  // SYZYGY_BLOCK_GRAPH_ORDERER_H_
