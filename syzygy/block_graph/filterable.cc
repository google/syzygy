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

#include "syzygy/block_graph/filterable.h"

namespace block_graph {

bool Filterable::IsFiltered(const block_graph::BlockGraph::Block* block) const {
  DCHECK(block != NULL);
  if (filter_ == NULL)
    return false;
  return block_graph::IsFiltered(*filter_, block);
}

bool Filterable::IsFiltered(const block_graph::BasicBlock* basic_block) const {
  DCHECK(basic_block != NULL);
  if (filter_ == NULL)
    return false;
  return block_graph::IsFiltered(*filter_, basic_block);
}

bool Filterable::IsFiltered(
    const block_graph::BasicCodeBlock* basic_block) const {
  DCHECK(basic_block != NULL);
  if (filter_ == NULL)
    return false;
  return block_graph::IsFiltered(*filter_, basic_block);
}

bool Filterable::IsFiltered(
    const block_graph::BasicDataBlock* basic_block) const {
  DCHECK(basic_block != NULL);
  if (filter_ == NULL)
    return false;
  return block_graph::IsFiltered(*filter_, basic_block);
}

bool Filterable::IsFiltered(const block_graph::Instruction& instruction) const {
  if (filter_ == NULL)
    return false;
  return block_graph::IsFiltered(*filter_, instruction);
}

}  // namespace block_graph
