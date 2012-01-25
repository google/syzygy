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
// Declares a block-graph transform that trims unnecessary block data from
// blocks, such that the implicit uninitialized data at the tail of the block
// is maximized.
//
// Post TrimTransform the BlockGraph will satisfy the invariant that the
// data_size of each block is exactly equal to its initialized data length.
// This invariant is expected by OrderedBlockGraph and BlockGraphOrderers.

#ifndef SYZYGY_BLOCK_GRAPH_TRANSFORMS_TRIM_TRANSFORM_H_
#define SYZYGY_BLOCK_GRAPH_TRANSFORMS_TRIM_TRANSFORM_H_

#include "syzygy/block_graph/transform.h"
#include "syzygy/block_graph/transforms/iterative_transform.h"
#include "syzygy/block_graph/transforms/named_transform.h"

namespace block_graph {
namespace transforms {

class TrimTransform : public IterativeTransformImpl<TrimTransform> {
 public:
  TrimTransform() { }
  virtual ~TrimTransform() { }

 private:
  friend IterativeTransformImpl<TrimTransform>;
  friend NamedTransformImpl<TrimTransform>;

  // For NamedTransformImpl.
  static const char kTransformName[];

  // For IterativeTransformImpl.
  bool OnBlock(BlockGraph* block_graph, BlockGraph::Block* block);
};

}  // namespace transforms
}  // namespace block_graph

#endif  // SYZYGY_BLOCK_GRAPH_TRANSFORMS_TRIM_TRANSFORM_H_
