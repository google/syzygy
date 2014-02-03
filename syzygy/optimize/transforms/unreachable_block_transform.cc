// Copyright 2014 Google Inc. All Rights Reserved.
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
// Implementation of unreachable block transform.

#include "syzygy/optimize/transforms/unreachable_block_transform.h"

namespace optimize {
namespace transforms {

namespace {

using block_graph::BlockGraph;
typedef BlockGraph::Block::ReferenceMap ReferenceMap;

}  // namespace

const char UnreachableBlockTransform::kTransformName[] =
    "UnreachableBlockTransform";

bool UnreachableBlockTransform::TransformBlockGraph(
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BlockGraph::Block* header_block) {

  std::set<const BlockGraph::Block*> reachable;
  std::stack<const BlockGraph::Block*> working;

  // Mark roots as reachable.
  reachable.insert(header_block);
  working.push(header_block);

  BlockGraph::BlockMap& blocks = block_graph->blocks_mutable();
  BlockGraph::BlockMap::iterator block_iter = blocks.begin();
  for (block_iter = blocks.begin(); block_iter != blocks.end(); ++block_iter) {
    BlockGraph::Block* block = &block_iter->second;
    if ((block->attributes() & BlockGraph::PE_PARSED) == 0)
      continue;
    reachable.insert(block);
    working.push(block);
  }

  // Follow the reachable graph.
  while (!working.empty()) {
    const BlockGraph::Block* block = working.top();
    working.pop();

    const ReferenceMap& references = block->references();
    ReferenceMap::const_iterator reference = references.begin();
    for (; reference != references.end(); ++reference) {
      const BlockGraph::Block* reference_block = reference->second.referenced();
      if (reachable.insert(reference_block).second)
        working.push(reference_block);
    }
  }

  // Remove references of unreachable blocks. This pass is needed because blocks
  // with references cannot be removed.
  block_iter = blocks.begin();
  std::vector<BlockGraph::BlockId> to_remove;
  for (block_iter = blocks.begin(); block_iter != blocks.end(); ++block_iter) {
    BlockGraph::Block* block = &block_iter->second;
    if (reachable.find(block) == reachable.end()) {
      block->RemoveAllReferences();
      to_remove.push_back(block->id());
    }
  }

  // Remove unreachable blocks from the block graph.
  std::vector<BlockGraph::BlockId>::iterator dead_block = to_remove.begin();
  for (; dead_block != to_remove.end(); ++dead_block)
    block_graph->RemoveBlockById(*dead_block);

  return true;
}

}  // namespace transforms
}  // namespace optimize
