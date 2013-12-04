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

#include "syzygy/optimize/transforms/block_alignment_transform.h"

#include "syzygy/block_graph/block_graph.h"

namespace optimize {
namespace transforms {

namespace {
  using block_graph::BasicBlock;
  using block_graph::BasicCodeBlock;
}  // namespace

bool BlockAlignmentTransform::TransformBasicBlockSubGraph(
      const TransformPolicyInterface* policy,
      BlockGraph* block_graph,
      BasicBlockSubGraph* subgraph,
      ApplicationProfile* profile,
      SubGraphProfile* subgraph_profile) {
  DCHECK_NE(reinterpret_cast<TransformPolicyInterface*>(NULL), policy);
  DCHECK_NE(reinterpret_cast<BlockGraph*>(NULL), block_graph);
  DCHECK_NE(reinterpret_cast<BasicBlockSubGraph*>(NULL), subgraph);
  DCHECK_NE(reinterpret_cast<ApplicationProfile*>(NULL), profile);
  DCHECK_NE(reinterpret_cast<SubGraphProfile*>(NULL), subgraph_profile);

  // Iterates through each basic block.
  BasicBlockSubGraph::BBCollection::iterator bb_iter =
      subgraph->basic_blocks().begin();
  for (; bb_iter != subgraph->basic_blocks().end(); ++bb_iter) {
    BasicCodeBlock* bb = BasicCodeBlock::Cast(*bb_iter);
    if (bb == NULL)
      continue;
    // TODO(etienneb): Basic block alignment based on frequencies (PGO).
  }

  // Apply function alignment.
  if (!subgraph->block_descriptions().empty()) {
    BasicBlockSubGraph::BlockDescription& description =
        subgraph->block_descriptions().front();
    // TODO(etienneb): Function alignment based on frequencies (PGO).
    if (description.alignment <= 1)
      description.alignment = 32;
  }

  return true;
}

}  // namespace transforms
}  // namespace optimize
