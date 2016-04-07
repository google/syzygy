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

bool ApplyImageLayoutTransform(
    ImageLayoutTransformInterface* transform,
    const TransformPolicyInterface* policy,
    const pe::ImageLayout* image_layout,
    const OrderedBlockGraph* ordered_block_graph) {
  DCHECK(transform != NULL);
  DCHECK(transform->name() != NULL);
  DCHECK(policy != NULL);
  DCHECK_GT(strlen(transform->name()), 0u);
  DCHECK(image_layout != NULL);
  DCHECK(ordered_block_graph != NULL);

  // Only the contents of block data can be changed in-place. References are
  // allowed to change. However one cannot add, delete or reorder blocks and/or
  // sections, nor can the size of blocks or sections be changed by adding or
  // deteling data bytes.
  // Get total number and the size of each block.
  size_t no_blocks = image_layout->blocks.size();
  std::vector<size_t> block_size;
  auto block_it = image_layout->blocks.begin();
  for (; block_it != image_layout->blocks.end(); ++block_it) {
    block_size.push_back(block_it->first.size());
  }

  if (!transform->TransformImageLayout(policy, image_layout,
      ordered_block_graph)) {
    LOG(ERROR) << "Layout transform \"" << transform->name() << "\" failed.";
    return false;
  }

  // Ensure the number of blocks and the size of each block has not changed
  if (no_blocks != image_layout->blocks.size()) {
    LOG(ERROR) << "Layout transform \"" << transform->name() << "\" changed "
               << "number of blocks.";
    return false;
  }
  block_it = image_layout->blocks.begin();
  for (size_t i = 0; block_it != image_layout->blocks.end(); ++block_it, ++i) {
    if (block_size[i] != block_it->first.size()) {
      LOG(ERROR) << "Layout transform \"" << transform->name() << "\" changed "
                 << "size of blocks.";
      return false;
    }
  }

  return true;
}

bool ApplyImageLayoutTransforms(
    const std::vector<ImageLayoutTransformInterface*>& transforms,
    const TransformPolicyInterface* policy,
    const pe::ImageLayout* image_layout,
    const OrderedBlockGraph* ordered_block_graph) {
  DCHECK_NE(reinterpret_cast<TransformPolicyInterface*>(NULL), policy);
  DCHECK_NE(reinterpret_cast<pe::ImageLayout*>(NULL), image_layout);
  DCHECK_NE(reinterpret_cast<OrderedBlockGraph*>(NULL), ordered_block_graph);

  // Apply the transforms sequentially.
  for (size_t i = 0; i < transforms.size(); ++i) {
    if (!ApplyImageLayoutTransform(transforms[i],
        policy,
        image_layout,
        ordered_block_graph)) {
      return false;
    }
  }

  return true;
}

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

bool ApplyBlockGraphTransforms(
    const std::vector<BlockGraphTransformInterface*>& transforms,
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BlockGraph::Block* header_block) {
  DCHECK_NE(reinterpret_cast<TransformPolicyInterface*>(NULL), policy);
  DCHECK_NE(reinterpret_cast<BlockGraph*>(NULL), block_graph);
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), header_block);

  // Apply the transforms sequentially.
  for (size_t i = 0; i < transforms.size(); ++i) {
    if (!ApplyBlockGraphTransform(transforms[i],
                                  policy,
                                  block_graph,
                                  header_block)) {
      return false;
    }
  }

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
  if (!bb_decomposer.Decompose()) {
    // If the failure is due to unsupported instructions then simply mark the
    // block as undecomposable so it won't be processed again.
    if (bb_decomposer.contains_unsupported_instructions()) {
      VLOG(1) << "Block contains unsupported instruction(s): "
              << BlockInfo(block);
      block->set_attribute(BlockGraph::UNSUPPORTED_INSTRUCTIONS);
      return true;
    }

    return false;
  }

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
