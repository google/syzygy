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
//
// A function for iterating over a changing BlockGraph. Intended for use by
// BlockGraphTransforms.

#ifndef SYZYGY_BLOCK_GRAPH_ITERATE_H_
#define SYZYGY_BLOCK_GRAPH_ITERATE_H_

#include "base/callback.h"
#include "syzygy/block_graph/block_graph.h"

namespace block_graph {

// The type of callback used by the IterateBlockGraph function.
typedef base::Callback<bool(BlockGraph* block_graph,
                            BlockGraph::Block*)> IterationCallback;

// This is an iterating primitive that transforms can make use of. It takes
// care of iterating in such a manner that the callback function may modify the
// block-graph being iterating without worry.
//
// The callback has freedom to modify any block in the block-graph, and to add
// any number of blocks to the block-graph. It is constrained to be allowed
// to delete only the current block being handled by the callback.
//
// The iteration will only visit those blocks that were pre-existing in the
// BlockGraph. That is, if the callback causes new blocks to be generated those
// blocks will never be visited and passed to the callback.
//
// @param callback the callback to invoke for each pre-existing block in the
//     block graph.
// @param block_graph the block graph that is to be iterated. This is non
//     const as the callback function may modify the block graph as the
//     iteration proceeds.
bool IterateBlockGraph(const IterationCallback& callback,
                       BlockGraph* block_graph);

}  // namespace block_graph

#endif  // SYZYGY_BLOCK_GRAPH_ITERATE_H_
