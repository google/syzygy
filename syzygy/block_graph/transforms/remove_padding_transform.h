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
// Defines a simple transform that scours a block-graph and removes any
// blocks that have been marked as padding. These are included in an
// original decomposition for completeness but they are not required when
// rewriting an image.

#ifndef SYZYGY_BLOCK_GRAPH_TRANSFORMS_REMOVE_PADDING_TRANSFORM_H_
#define SYZYGY_BLOCK_GRAPH_TRANSFORMS_REMOVE_PADDING_TRANSFORM_H_

#include "syzygy/block_graph/transforms/iterative_transform.h"

namespace block_graph {
namespace transforms {

class RemovePaddingTransform
    : public IterativeTransformImpl<RemovePaddingTransform> {
 public:
 private:
  // @name IterativeTransformImpl implementation.
  // @{
  friend IterativeTransformImpl<RemovePaddingTransform>;
  friend NamedBlockGraphTransformImpl<RemovePaddingTransform>;
  static const char kTransformName[];
  bool OnBlock(BlockGraph* block_graph, BlockGraph::Block* block);
  // @}
};

}  // namespace transforms
}  // namespace block_graph

#endif  // SYZYGY_BLOCK_GRAPH_TRANSFORMS_REMOVE_PADDING_TRANSFORM_H_
