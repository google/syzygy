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

#include "syzygy/optimize/transforms/basic_block_reordering_transform.h"

#include "syzygy/block_graph/block_graph.h"

namespace optimize {
namespace transforms {

namespace {
  using block_graph::BasicBlock;
  using block_graph::BasicCodeBlock;
}  // namespace

BasicBlockReorderingTransform::BasicBlockReorderingTransform(
    ApplicationProfile* profile) : profile_(profile) {
  DCHECK_NE(reinterpret_cast<ApplicationProfile*>(NULL), profile);
}

bool BasicBlockReorderingTransform::TransformBasicBlockSubGraph(
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BasicBlockSubGraph* subgraph,
    ApplicationProfile* profile,
    SubGraphProfile* subgraph_profile) {
  DCHECK_NE(reinterpret_cast<TransformPolicyInterface*>(NULL), policy);
  DCHECK_NE(reinterpret_cast<BlockGraph*>(NULL), block_graph);
  DCHECK_NE(reinterpret_cast<BasicBlockSubGraph*>(NULL), subgraph);
  DCHECK_NE(reinterpret_cast<ApplicationProfile*>(NULL), profile_);
  DCHECK_NE(reinterpret_cast<ApplicationProfile*>(NULL), profile);
  DCHECK_NE(reinterpret_cast<SubGraphProfile*>(NULL), subgraph_profile);

  // Do not reorder cold code.
  const BlockGraph::Block* block = subgraph->original_block();
  DCHECK_NE(reinterpret_cast<const BlockGraph::Block*>(NULL), block);
  const ApplicationProfile::BlockProfile* block_profile =
      profile_->GetBlockProfile(block);
  if (block_profile == NULL || block_profile->count() == 0)
    return true;

  // Avoid reordering a block with a jump table or data block.
  // TODO(etienneb): Add support for jump table reordering.
  BasicBlockSubGraph::BBCollection::iterator bb_iter =
      subgraph->basic_blocks().begin();
  for (; bb_iter != subgraph->basic_blocks().end(); ++bb_iter) {
    BasicCodeBlock* bb = BasicCodeBlock::Cast(*bb_iter);
    if (bb == NULL)
      return true;
  }

  // TODO(etienneb): Implement the Pettis algorithm here.

  return true;
}

}  // namespace transforms
}  // namespace optimize
