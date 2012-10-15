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
// Utilities for dealing with block-graphs and blocks.

#ifndef SYZYGY_BLOCK_GRAPH_BLOCK_UTIL_H_
#define SYZYGY_BLOCK_GRAPH_BLOCK_UTIL_H_

#include "syzygy/block_graph/basic_block.h"
#include "syzygy/block_graph/block_graph.h"

namespace block_graph {

// Determines whether @p block's attributes preclude basic-block
// decomposition.
// @param block the code block whose attributes are to be inspected.
// @returns true if the block attributes are safe for decomposition to basic-
//     blocks, false otherwise.
// @pre block has type CODE_BLOCK.
bool CodeBlockAttributesAreBasicBlockSafe(const BlockGraph::Block* block);

// Determines whether @p bb's instructions and successors comprise a contiguous
// source range, and return it if so.
// @param bb the basic block to inspect.
// @param source_range returns @p bb's source range on success.
// @returns true iff @p bb's instructions and successors comprise a contiguous
//     source range.
// @note @p bb's source range is deemed contiguous if at least one instruction
//     or successor has a source range, and if all the source ranges constitute
//     a single contiguous range, irrespective order. This means that this
//     function may succeed even if instructions in @p bb have been added,
//     reordered or mutated.
bool GetBasicBlockSourceRange(const BasicCodeBlock& bb,
                              BlockGraph::Block::SourceRange* source_range);

}  // namespace block_graph

#endif  // SYZYGY_BLOCK_GRAPH_BLOCK_UTIL_H_
