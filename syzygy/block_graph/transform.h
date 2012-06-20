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
// Declares a simple API for transforming BlockGraphs in situ.

#ifndef SYZYGY_BLOCK_GRAPH_TRANSFORM_H_
#define SYZYGY_BLOCK_GRAPH_TRANSFORM_H_

#include "base/callback.h"
#include "syzygy/block_graph/block_graph.h"

namespace block_graph {

// A BlockGraphTransform is a pure virtual base class defining the transform
// API.
class BlockGraphTransformInterface {
 public:
  virtual ~BlockGraphTransformInterface() { }

  // Gets the name of this transform.
  //
  // @returns the name of this transform.
  virtual const char* name() const = 0;

  // Applies this transform to the provided block graph.
  //
  // @param block_graph The block graph to transform.
  // @param header_block The header block of the block graph to transform.
  // @returns true on success, false otherwise.
  virtual bool TransformBlockGraph(BlockGraph* block_graph,
                                   BlockGraph::Block* header_block) = 0;
};

// This applies the provided BlockGraphTransform and checks that that invariant
// has been satisfied; namely, that the header block has not been deleted from
// the block graph.
//
// @param transform the transform to apply.
// @param block_graph the block graph to transform.
// @param header_block the header block from block_graph.
bool ApplyBlockGraphTransform(BlockGraphTransformInterface* transform,
                              BlockGraph* block_graph,
                              BlockGraph::Block* header_block);

}  // namespace block_graph

#endif  // SYZYGY_BLOCK_GRAPH_TRANSFORM_H_
