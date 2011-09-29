// Copyright 2010 Google Inc.
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

#ifndef SYZYGY_EXPERIMENTAL_COMPARE_H_
#define SYZYGY_EXPERIMENTAL_COMPARE_H_

#include <map>
#include <vector>
#include "syzygy/core/block_graph.h"

namespace experimental {

typedef std::map<const core::BlockGraph::Block*,
                 const core::BlockGraph::Block*> BlockGraphMapping;

typedef std::vector<const core::BlockGraph::Block*> BlockVector;

// Builds a mapping between two related BlockGraphs. The mapping will be a
// partial bijection between the blocks in each BlockGraph. If provided,
// unmapped1 and unmapped2 will be populated with a list of blocks that were
// not mapped from each block graph.
bool BuildBlockGraphMapping(const core::BlockGraph& bg1,
                            const core::BlockGraph& bg2,
                            BlockGraphMapping* mapping,
                            BlockVector* unmapped1,
                            BlockVector* unmapped2);

// Reverses a block mapping. This can not be done in-place, so
// @p reverse_mapping and @p mapping must not be the same object.
bool ReverseBlockGraphMapping(const BlockGraphMapping& mapping,
                              BlockGraphMapping* reverse_mapping);

}  // experimental

#endif  // SYZYGY_EXPERIMENTAL_COMPARE_H_
