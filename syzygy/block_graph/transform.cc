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

#include "syzygy/block_graph/transform.h"

#include "syzygy/block_graph/basic_block_decomposer.h"
#include "syzygy/block_graph/block_builder.h"
#include "syzygy/block_graph/block_util.h"

namespace block_graph {

bool ApplyBlockGraphTransform(BlockGraphTransformInterface* transform,
                              const TransformPolicyInterface* policy,
                              BlockGraph* block_graph,
                              BlockGraph::Block* header_block) {
  DCHECK(transform != NULL);
  DCHECK(transform->name() != NULL);
  DCHECK(policy != NULL);
  DCHECK_GT(strlen(transform->name()), 0u);
  DCHECK(block_graph != NULL);
  DCHECK(header_block != NULL);

  // Get the ID of the header block. As a sanity check we want to ensure
  // that it still exists after the transform.
  BlockGraph::BlockId header_block_id = header_block->id();

  if (!transform->TransformBlockGraph(policy, block_graph, header_block)) {
    LOG(ERROR) << "Transform \"" << transform->name() << "\" failed.";
    return false;
  }

  // Ensure that the header block still exists. If it was changed, it needs
  // to have been changed in place.
  BlockGraph::Block* block = block_graph->GetBlockById(header_block_id);
  if (block == NULL) {
    LOG(ERROR) << "Header block not found after \"" << transform->name()
               << "\" transform.";
    return false;
  }
  DCHECK_EQ(header_block, block);

  return true;
}

bool ApplyBasicBlockSubGraphTransform(
    BasicBlockSubGraphTransformInterface* transform,
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BlockGraph::Block* block,
    BlockVector* new_blocks) {
  DCHECK(transform != NULL);
  DCHECK(policy != NULL);
  DCHECK(block_graph != NULL);
  DCHECK(block != NULL);
  DCHECK_EQ(BlockGraph::CODE_BLOCK, block->type());
  DCHECK(policy->BlockIsSafeToBasicBlockDecompose(block));

  // Decompose block to basic blocks.
  BasicBlockSubGraph subgraph;
  BasicBlockDecomposer bb_decomposer(block, &subgraph);
  if (!bb_decomposer.Decompose())
    return false;

  // Call the transform.
  if (!transform->TransformBasicBlockSubGraph(policy, block_graph, &subgraph))
    return false;

  // Update the block-graph post transform.
  BlockBuilder builder(block_graph);
  if (!builder.Merge(&subgraph))
    return false;

  if (new_blocks != NULL) {
    new_blocks->assign(builder.new_blocks().begin(),
                       builder.new_blocks().end());
  }

  return true;
}

bool ApplyBasicBlockSubGraphTransforms(
    const std::vector<BasicBlockSubGraphTransformInterface*>& transforms,
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BlockGraph::Block* block,
    BlockVector* new_blocks) {
  DCHECK(policy != NULL);
  DCHECK(block_graph != NULL);
  DCHECK(block != NULL);
  DCHECK_EQ(BlockGraph::CODE_BLOCK, block->type());
  DCHECK(policy->BlockIsSafeToBasicBlockDecompose(block));

  // Decompose block to basic blocks.
  BasicBlockSubGraph subgraph;
  BasicBlockDecomposer bb_decomposer(block, &subgraph);
  if (!bb_decomposer.Decompose())
    return false;

  // Call the transforms.
  std::vector<BasicBlockSubGraphTransformInterface*>::const_iterator it =
      transforms.begin();
  for (; it != transforms.end(); ++it) {
    BasicBlockSubGraphTransformInterface* transform = *it;
    DCHECK(transform != NULL);
    if (!transform->TransformBasicBlockSubGraph(policy, block_graph, &subgraph))
      return false;
  }

  // Update the block-graph post transform.
  BlockBuilder builder(block_graph);
  if (!builder.Merge(&subgraph))
    return false;

  if (new_blocks != NULL) {
    new_blocks->assign(builder.new_blocks().begin(),
                       builder.new_blocks().end());
  }

  return true;
}

}  // namespace block_graph
