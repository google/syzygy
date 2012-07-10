// Copyright 2012 Google Inc.
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
// Utilities for dealing with block-graphs and blocks.

#ifndef SYZYGY_BLOCK_GRAPH_BLOCK_UTIL_H_
#define SYZYGY_BLOCK_GRAPH_BLOCK_UTIL_H_

#include "syzygy/block_graph/block_graph.h"

namespace block_graph {

// Determines if this code block's attributes preclude basic-block
// decomposition.
// @param block the code block whose attributes are to be inspected.
// @returns true if the block attributes are safe for decomposition to basic-
//     blocks, false otherwise.
// @pre block has type CODE_BLOCK.
bool CodeBlockAttributesAreBasicBlockSafe(
    const block_graph::BlockGraph::Block* block);

}  // namespace block_graph

#endif  // SYZYGY_BLOCK_GRAPH_BLOCK_UTIL_H_
