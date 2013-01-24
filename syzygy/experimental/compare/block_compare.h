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
// Defines a comparison function for BlockGraph::Blocks. This function is
// constructed such that if two blocks compare equal, the hashes computed
// by BlockHash will be equal. It can be used to resolve BlockHash conflicts.

#ifndef SYZYGY_EXPERIMENTAL_COMPARE_BLOCK_COMPARE_H_
#define SYZYGY_EXPERIMENTAL_COMPARE_BLOCK_COMPARE_H_

#include "syzygy/block_graph/block_graph.h"

namespace experimental {

using block_graph::BlockGraph;

// Compares two blocks. This uses the same semantics as that used by the
// BlockHash function, allowing us to use it to detect hash collisions.
int BlockCompare(const BlockGraph::Block* block0,
                 const BlockGraph::Block* block1);

}  // namespace experimental

#endif  // SYZYGY_EXPERIMENTAL_COMPARE_BLOCK_COMPARE_H_
