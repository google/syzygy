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
//
// Implementation of ChainedBasicBlockTransform.

#include "syzygy/block_graph/transforms/chained_basic_block_transforms.h"

namespace block_graph {
namespace transforms {

const char ChainedBasicBlockTransforms::kTransformName[] =
    "ChainedBasicBlockTransforms";

bool ChainedBasicBlockTransforms::AppendTransform(
    BasicBlockSubGraphTransformInterface* transform) {
  DCHECK_NE(reinterpret_cast<BasicBlockSubGraphTransformInterface*>(NULL),
            transform);
  transforms_.push_back(transform);
  return true;
}

bool ChainedBasicBlockTransforms::OnBlock(
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BlockGraph::Block* block) {
  DCHECK_NE(reinterpret_cast<TransformPolicyInterface*>(NULL), policy);
  DCHECK_NE(reinterpret_cast<BlockGraph*>(NULL), block_graph);
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), block);

  // Avoid decomposition if no transforms are applied.
  if (transforms_.empty())
    return true;

  // Use the decomposition policy to skip blocks that aren't eligible for
  // basic-block decomposition.
  if (!policy->BlockIsSafeToBasicBlockDecompose(block))
    return true;

  // Apply the series of basic block transforms to this block.
  if (!ApplyBasicBlockSubGraphTransforms(
           transforms_, policy, block_graph, block, NULL)) {
    return false;
  }

  return true;
}

}  // namespace transforms
}  // namespace block_graph
