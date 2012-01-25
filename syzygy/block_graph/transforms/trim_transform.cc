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

#include "syzygy/block_graph/transforms/trim_transform.h"

namespace block_graph {
namespace transforms {

namespace {

// Returns the length of the initialized data for the given block.
size_t InitializedDataSize(const BlockGraph::Block* block) {
  size_t size = 0;

  if (!block->references().empty()) {
    // NOTE: This relies on ReferenceMap being sorted by the offset!
    BlockGraph::Block::ReferenceMap::const_iterator ref =
        --block->references().end();
    size = ref->first + ref->second.size();
  }

  // If we have no data it consists of implicit zeros.
  if (block->data() == NULL || block->data_size() <= size)
    return size;

  // If we do have data then we peel off any explicit zeros at the end of the
  // buffer.
  const uint8* data = block->data() + block->data_size() - 1;
  for (size_t i = block->data_size(); i > size; --i, --data) {
    if (*data != 0)
      return i;
  }

  return size;
}

}  // namespace

const char TrimTransform::kTransformName[] = "TrimTransform";

bool TrimTransform::OnBlock(BlockGraph* /* block_graph */,
                            BlockGraph::Block* block) {
  DCHECK(block != NULL);

  size_t init_size = InitializedDataSize(block);
  if (init_size != block->data_size())
    block->ResizeData(init_size);

  return true;
}

}  // namespace transforms
}  // namespace block_graph
