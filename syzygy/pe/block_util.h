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
// Utilities for dealing with block-graphs and blocks generated over a PE
// binary.

#ifndef SYZYGY_PE_BLOCK_UTIL_H_
#define SYZYGY_PE_BLOCK_UTIL_H_

#include "syzygy/block_graph/block_graph.h"

namespace pe {

// Determines if this code block's attributes are consistent with CL.EXE
// compiled code. That is, neither HAS_INLINE_ASSEMBLY nor
// BUILT_BY_UNSUPPORTED_COMPILER are set. It also ensures that no unsafe
// attributes are set on the block, indicating compiler features that we are
// not confidently able to basic-block decompose.
// @param block the code block whose attributes are to be inspected.
// @returns true if the block attributes are safe for basic-block decomposition.
// @pre block has type CODE_BLOCK.
bool CodeBlockAttributesAreClConsistent(
    const block_graph::BlockGraph::Block* block);

// Determines if this code block's references are consistent with CL.EXE
// compiled code. The following criteria must hold: all references from this
// block to any code block (including self-references) must be direct.
//
// @param block the code block whose references are to be inspected.
// @returns true if the block's references are consistent with CL.EXE compiled
//     code, false otherwise.
// @pre block has type CODE_BLOCK.
bool CodeBlockReferencesAreClConsistent(
    const block_graph::BlockGraph::Block* block);

// Determines if this code block's referrers are consistent with CL.EXE compiled
// code. This will be true if all the intra- and inter-block references are
// of valid types, depending on their origins and destinations (see
// implementation for full details). It also requires that all data labels be
// directly referenced, and that if the block has data, it be strictly at the
// end of the block.
//
// @param block the block whose referrers are to be inspected.
// @returns true if the block's referrers are consistent with CL.EXE compiled
//     code, false otherwise.
// @pre block has type CODE_BLOCK.
bool CodeBlockReferrersAreClConsistent(
    const block_graph::BlockGraph::Block* block);

// Determines if a code block is consistent with CL.EXE compiled code. This is
// true iff CodeBlockAttributesAreClConsistent,
// CodeBlockReferencesAreClConsistent and CodeBlockReferrersAreClConsistent
// all return true.
// @returns true if this code block is consistent with CL.EXE compiled code,
//     false otherwise.
// @pre block has type CODE_BLOCK.
bool CodeBlockIsClConsistent(
    const block_graph::BlockGraph::Block* block);

// Determines if a code block is basic-block decomposable. This is possible if
// CodeBlockIsClConsistent passes, or if the block has the BUILT_BY_SYZYGY
// attribute.
// @returns true if this code block is BB decomposable, false otherwise.
// @pre block has type CODE_BLOCK.
bool CodeBlockIsBasicBlockDecomposable(
    const block_graph::BlockGraph::Block* block);

}  // namespace pe

#endif  // SYZYGY_PE_BLOCK_UTIL_H_
