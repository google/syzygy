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

#include "syzygy/optimize/transforms/chained_subgraph_transforms.h"

#include <stack>

#include "syzygy/block_graph/basic_block_decomposer.h"
#include "syzygy/block_graph/block_builder.h"
#include "syzygy/block_graph/block_util.h"
#include "syzygy/optimize/transforms/subgraph_transform.h"

namespace optimize {
namespace transforms {

namespace {

using block_graph::BasicBlockDecomposer;
using block_graph::BasicBlockSubGraph;
using block_graph::BlockBuilder;
using block_graph::BlockGraph;
using block_graph::BlockVector;
typedef BlockGraph::Block::ReferrerSet ReferrerSet;
typedef std::list<BlockGraph::Block*> BlockOrdering;

// Traverse the call-graph in reverse call order (callee to caller) and push
// blocks in post-order. The resulting ordering can be iterated to visit all
// blocks from leaf to root. The ordering has the guarantee that all callees
// have been visited before their callers (except for recursive calls and
// indirect calls).
// TODO(etienneb): Hoist this function into block_graph.
void FlattenCallgraphPostOrder(BlockGraph* block_graph, BlockOrdering* order) {
  DCHECK_NE(reinterpret_cast<BlockGraph*>(NULL), block_graph);
  DCHECK_NE(reinterpret_cast<BlockOrdering*>(NULL), order);

  // The algorithms uses a std::stack allocated in the heap to avoid stack
  // overflow.
  std::stack<BlockGraph::Block*> stack;
  std::set<BlockGraph::Block*> visiting;

  // Traverse the call-graph in depth-first.
  BlockGraph::BlockMap& blocks = block_graph->blocks_mutable();
  BlockGraph::BlockMap::iterator block_iter = blocks.begin();
  for (; block_iter != blocks.end(); ++block_iter) {
    BlockGraph::Block* block = &block_iter->second;

    // This block is already visited.
    if (!visiting.insert(block).second)
      continue;

    // This block needs to be visited, add it to the stack.
    stack.push(block);

    // Follow the referrers.
    while (!stack.empty()) {
      block = stack.top();

      // Put unvisited referrers on the stack.
      typedef std::map<BlockGraph::BlockId, BlockGraph::Block*> OrderedBlockMap;
      OrderedBlockMap missing;
      bool missing_referrers = false;
      if (block->type() == BlockGraph::CODE_BLOCK) {
        const ReferrerSet& referrers = block->referrers();
        ReferrerSet::iterator referrer = referrers.begin();
        for (; referrer != referrers.end(); ++referrer) {
          BlockGraph::Block* from = referrer->first;
          if (visiting.insert(from).second) {
            missing.insert(std::make_pair(from->id(), from));
            missing_referrers = true;
          }
        }
      }

      // Push missing referrers into the stack, ordered by block id.
      OrderedBlockMap::iterator referrer = missing.begin();
      for (; referrer != missing.end(); ++referrer)
        stack.push(referrer->second);

      // When there are no missing referrers, this block is fully visited and
      // can be pushed in the ordering (post-order).
      if (!missing_referrers) {
        order->push_front(block);
        // Remove this block from the stack.
        DCHECK_EQ(block, stack.top());
        stack.pop();
      }
    }
  }
}

}  // namespace

const char ChainedSubgraphTransforms::kTransformName[] =
    "ChainedSubgraphTransforms";

void ChainedSubgraphTransforms::AppendTransform(
    SubGraphTransformInterface* transform) {
  DCHECK_NE(reinterpret_cast<SubGraphTransformInterface*>(NULL), transform);
  transforms_.push_back(transform);
}

bool ChainedSubgraphTransforms::TransformBlockGraph(
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BlockGraph::Block* header_block) {

  // Avoid processing if no transforms are applied.
  if (transforms_.empty())
    return true;

  BlockOrdering order;
  FlattenCallgraphPostOrder(block_graph, &order);

  BlockOrdering::iterator block_iter = order.begin();
  for (; block_iter != order.end(); ++block_iter) {
    BlockGraph::Block* block = *block_iter;

    // Use the decomposition policy to skip blocks that aren't eligible for
    // basic-block decomposition.
    if (!policy->BlockIsSafeToBasicBlockDecompose(block))
      continue;

    // Decompose block to basic blocks.
    BasicBlockSubGraph subgraph;
    BasicBlockDecomposer bb_decomposer(block, &subgraph);
    if (!bb_decomposer.Decompose())
      return false;

    // Update subgraph profile.
    scoped_ptr<SubGraphProfile> subgraph_profile;
    profile_->ComputeSubGraphProfile(&subgraph, &subgraph_profile);

    // Apply the series of basic block transforms to this block.
    TransformList::const_iterator it = transforms_.begin();
    for (; it != transforms_.end(); ++it) {
      SubGraphTransformInterface* transform = *it;
      DCHECK(transform != NULL);
      if (!transform->TransformBasicBlockSubGraph(policy,
                                                  block_graph,
                                                  &subgraph,
                                                  profile_,
                                                  subgraph_profile.get())) {
        return false;
      }
    }

    // Update the block-graph post transform.
    BlockBuilder builder(block_graph);
    if (!builder.Merge(&subgraph))
      return false;

    // TODO(etienneb): This is needed until the labels refactoring.
    const BlockVector& blocks = builder.new_blocks();
    BlockVector::const_iterator new_block = blocks.begin();
    for (; new_block != blocks.end(); ++new_block)
      (*new_block)->set_attribute(BlockGraph::BUILT_BY_SYZYGY);
  }

  return true;
}

}  // namespace transforms
}  // namespace optimize
