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

#include <stack>

namespace optimize {
namespace transforms {

namespace {

// Forward declaration.
struct SubTreeInformation;

using block_graph::BlockGraph;
typedef BlockGraph::Block::ReferenceMap ReferenceMap;
typedef std::set<const BlockGraph::Block*> ReachableSet;
typedef std::stack<const BlockGraph::Block*> ReachableStack;
typedef std::map<const BlockGraph::Block*, SubTreeInformation> RecursiveSizeMap;

struct SubTreeInformation {
  size_t size;
  size_t count;
};

// This function computes the number and the total size of the reachable blocks
// from the given root |block|.
void ComputeSubTreeInformation(const BlockGraph::Block* block,
                               const BlockGraph::BlockMap& blocks,
                               const ReachableSet& reachable,
                               SubTreeInformation* subtree,
                               ReachableSet* visited) {
  DCHECK_NE(reinterpret_cast<SubTreeInformation*>(NULL), subtree);
  DCHECK_NE(reinterpret_cast<ReachableSet*>(NULL), visited);

  // Avoid repeatedly visiting the same block within a sub-tree. Even if a block
  // is reachable via multiple paths, it contributes only once to the size of
  // the sub-tree.
  if (!visited->insert(block).second)
    return;

  // Add the size of the current block.
  subtree->size += block->size();
  subtree->count += 1;

  // Sum the size of each sub-tree by following references.
  const ReferenceMap& references = block->references();
  ReferenceMap::const_iterator reference = references.begin();
  for (; reference != references.end(); ++reference) {
    const BlockGraph::Block* reference_block = reference->second.referenced();
    if (reachable.find(reference_block) != reachable.end())
      continue;
    ComputeSubTreeInformation(
        reference_block, blocks, reachable, subtree, visited);
  }
}

bool DumpUnreachableCallgraph(const base::FilePath& path,
                              const BlockGraph::BlockMap& blocks,
                              const ReachableSet& reachable) {

  // A cache of computed sizes.
  RecursiveSizeMap subtrees;

  // Dump a cachegrind file.
  base::ScopedFILE file(base::OpenFile(path, "wb+"));
  if (!file.get()) {
    LOG(ERROR) << "Could not create file.";
    return false;
  }

  ::fprintf(file.get(), "events: Size Count\n");

  BlockGraph::BlockMap::const_iterator block_iter = blocks.begin();
  for (block_iter = blocks.begin(); block_iter != blocks.end(); ++block_iter) {
    const BlockGraph::Block* block = &block_iter->second;
    if (reachable.find(block) != reachable.end())
      continue;

    ::fprintf(file.get(), "ob=%s\n", block->compiland_name().c_str());
    ::fprintf(file.get(), "fn=%s\n", block->name().c_str());
    ::fprintf(file.get(), "%u %u %u\n", block->id(), block->size(), 1);

    ReachableSet subtree_visited;
    subtree_visited.insert(block);

    const ReferenceMap& references = block->references();
    ReferenceMap::const_iterator reference = references.begin();
    for (; reference != references.end(); ++reference) {
      const BlockGraph::Block* reference_block = reference->second.referenced();
      if (reachable.find(reference_block) != reachable.end())
        continue;
      if (subtree_visited.find(reference_block) != subtree_visited.end())
        continue;

      SubTreeInformation subtree = {0, 0};
      RecursiveSizeMap::iterator look = subtrees.find(reference_block);
      if (look != subtrees.end()) {
        subtree = look->second;
      } else {
        ComputeSubTreeInformation(reference_block,
                                  blocks,
                                  reachable,
                                  &subtree,
                                  &subtree_visited);
        subtrees[reference_block] = subtree;
      }

      ::fprintf(file.get(), "cob=%s\n",
                reference_block->compiland_name().c_str());
      ::fprintf(file.get(), "cfn=%s\n",
                reference_block->name().c_str());
      ::fprintf(file.get(), "calls=%u %u\n", 1, reference_block->size());
      ::fprintf(file.get(), "%u %u %u\n",
                block->id(),
                subtree.size,
                subtree.count);
    }
    ::fprintf(file.get(), "\n");
  }

  return true;
}

}  // namespace

const char UnreachableBlockTransform::kTransformName[] =
    "UnreachableBlockTransform";

bool UnreachableBlockTransform::TransformBlockGraph(
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BlockGraph::Block* header_block) {

  ReachableSet reachable;
  ReachableStack working;

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

  // Dump a cachegrind graph of unreachable blocks.
  if (!unreachable_graph_path_.empty())
    DumpUnreachableCallgraph(unreachable_graph_path_, blocks, reachable);

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
