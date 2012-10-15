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

#include "syzygy/block_graph/block_util.h"

#include <algorithm>
#include <vector>

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

bool GetBasicBlockSourceRange(const BasicCodeBlock& bb,
                              BlockGraph::Block::SourceRange* source_range) {
  DCHECK(source_range != NULL);

  typedef BlockGraph::Block::SourceRange SourceRange;
  std::vector<SourceRange> ranges;

  // Collect all the instruction and successor source ranges.
  BasicBlock::Instructions::const_iterator inst_it(bb.instructions().begin());
  for (; inst_it != bb.instructions().end(); ++inst_it) {
    const SourceRange& range = inst_it->source_range();
    if (range.size() > 0)
      ranges.push_back(range);
  }
  BasicBlock::Successors::const_iterator succ_it(bb.successors().begin());
  for (; succ_it != bb.successors().end(); ++succ_it) {
    const SourceRange& range = succ_it->source_range();
    if (range.size() > 0)
      ranges.push_back(range);
  }

  if (ranges.size() == 0)
    return false;

  // Sort the ranges.
  std::sort(ranges.begin(), ranges.end());

  // Test that they're all contiguous, while computing their total length.
  SourceRange::Size size = ranges[0].size();
  for (size_t i = 0; i < ranges.size() - 1; ++i) {
    size += ranges[i + 1].size();
    if (ranges[i].start() + ranges[i].size() != ranges[i + 1].start())
      return false;
  }
  *source_range = SourceRange(ranges[0].start(), size);

  return true;
}

}  // namespace block_graph
