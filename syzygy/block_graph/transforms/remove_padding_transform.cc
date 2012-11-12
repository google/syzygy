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

#include "syzygy/block_graph/transforms/remove_padding_transform.h"

namespace block_graph {
namespace transforms {

const char RemovePaddingTransform::kTransformName[] =
    "RemovePaddingTransform";

bool RemovePaddingTransform::OnBlock(BlockGraph* block_graph,
                                     BlockGraph::Block* block) {
  DCHECK(block_graph != NULL);
  DCHECK(block != NULL);

  // We skip anything that isn't a padding block.
  if ((block->attributes() & BlockGraph::PADDING_BLOCK) == 0)
    return true;

  return block_graph->RemoveBlock(block);
}

}  // namespace transforms
}  // namespace block_graph
