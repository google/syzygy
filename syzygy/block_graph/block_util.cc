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

#include "syzygy/pe/block_util.h"

namespace block_graph {

bool CodeBlockAttributesAreBasicBlockSafe(
    const block_graph::BlockGraph::Block* block) {
  DCHECK(block != NULL);
  DCHECK_EQ(BlockGraph::CODE_BLOCK, block->type());

  // If the block was built by our toolchain it's inherently safe. This
  // attribute is used to whitelist a block.
  if (block->attributes() & BlockGraph::BUILT_BY_SYZYGY)
    return true;

  // Any of the following attributes make it unsafe to basic-block
  // decompose the code block.
  static const BlockGraph::BlockAttributes kInvalidAttributes =
      BlockGraph::GAP_BLOCK |
      BlockGraph::PADDING_BLOCK |
      BlockGraph::HAS_INLINE_ASSEMBLY |
      BlockGraph::BUILT_BY_UNSUPPORTED_COMPILER |
      BlockGraph::ERRORED_DISASSEMBLY |
      BlockGraph::HAS_EXCEPTION_HANDLING |
      BlockGraph::DISASSEMBLED_PAST_END;
  if ((block->attributes() & kInvalidAttributes) != 0)
    return false;

  return true;
}

}  // namespace block_graph
