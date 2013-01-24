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
// Declares utility functions for building mappings between two distinct
// BlockGraphs. This is intended for use in generating mappings between two
// BlockGraphs that represent different versions of the same binary but it
// should work for arbitrary BlockGraphs. See compare.cc for a full description
// of the algorithm.
#ifndef SYZYGY_EXPERIMENTAL_COMPARE_COMPARE_H_
#define SYZYGY_EXPERIMENTAL_COMPARE_COMPARE_H_

#include <map>
#include <vector>

#include "syzygy/block_graph/block_graph.h"

namespace experimental {

typedef std::map<const block_graph::BlockGraph::Block*,
                 const block_graph::BlockGraph::Block*> BlockGraphMapping;

// Builds a mapping between two related BlockGraphs. The mapping will be a
// partial bijection between the blocks in each BlockGraph. If provided,
// unmapped1 and unmapped2 will be populated with a list of blocks that were
// not mapped from each block graph.
bool BuildBlockGraphMapping(const block_graph::BlockGraph& bg1,
                            const block_graph::BlockGraph& bg2,
                            BlockGraphMapping* mapping,
                            block_graph::ConstBlockVector* unmapped1,
                            block_graph::ConstBlockVector* unmapped2);

// Reverses a block mapping. This can not be done in-place, so
// @p reverse_mapping and @p mapping must not be the same object.
bool ReverseBlockGraphMapping(const BlockGraphMapping& mapping,
                              BlockGraphMapping* reverse_mapping);

}  // experimental

#endif  // SYZYGY_EXPERIMENTAL_COMPARE_COMPARE_H_
