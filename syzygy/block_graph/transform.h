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
//
// Declares a simple API for transforming BlockGraphs in situ.

#ifndef SYZYGY_BLOCK_GRAPH_TRANSFORM_H_
#define SYZYGY_BLOCK_GRAPH_TRANSFORM_H_

#include "syzygy/block_graph/basic_block_subgraph.h"
#include "syzygy/block_graph/block_graph.h"
#include "syzygy/block_graph/transform_policy.h"

namespace block_graph {

// A BlockGraphTransform is a pure virtual base class defining the transform
// API.
class BlockGraphTransformInterface {
 public:
  virtual ~BlockGraphTransformInterface() { }

  // Gets the name of this transform.
  //
  // @returns the name of this transform.
  virtual const char* name() const = 0;

  // Applies this transform to the provided block graph.
  //
  // @param policy The policy object restricting how the transform is applied.
  // @param block_graph The block graph to transform.
  // @param header_block The header block of the block graph to transform.
  // @returns true on success, false otherwise.
  virtual bool TransformBlockGraph(const TransformPolicyInterface* policy,
                                   BlockGraph* block_graph,
                                   BlockGraph::Block* header_block) = 0;
};

// This applies the provided BlockGraphTransform and checks that invariant has
// been satisfied; namely, that the header block has not been deleted from the
// block graph.
//
// @param transform the transform to apply.
// @param policy The policy object restricting how the transform is applied.
// @param block_graph the block graph to transform.
// @param header_block the header block from block_graph.
// @returns true on success, false otherwise.
bool ApplyBlockGraphTransform(BlockGraphTransformInterface* transform,
                              const TransformPolicyInterface* policy,
                              BlockGraph* block_graph,
                              BlockGraph::Block* header_block);

// A BasicBlockSubGraphTransform is a pure virtual base class defining the
// basic-block transform API.
class BasicBlockSubGraphTransformInterface {
 public:
  virtual ~BasicBlockSubGraphTransformInterface() { }

  // Gets the name of this transform.
  //
  // @returns the name of this transform.
  virtual const char* name() const = 0;

  // Applies this transform to the provided block.
  //
  // @param policy The policy object restricting how the transform is applied.
  // @param block_graph the block-graph of which the basic block subgraph
  //     is a part.
  // @param basic_block_subgraph the basic block subgraph to be transformed.
  // @returns true on success, false otherwise.
  virtual bool TransformBasicBlockSubGraph(
      const TransformPolicyInterface* policy,
      BlockGraph* block_graph,
      BasicBlockSubGraph* basic_block_subgraph) = 0;
};

// Applies the provided BasicBlockSubGraphTransform to a single block. Takes
// care of basic-block decomposing the block, passes it to the transform, and
// recomposes the block.
//
// @param transform the transform to apply.
// @param policy The policy object restricting how the transform is applied.
// @param block_graph the block containing the block to be transformed.
// @param block the block to be transformed.
// @param new_blocks On success, any newly created blocks will be returned
//     here. Note that this parameter may be NULL if you are not interested
//     in retrieving the set of new blocks.
// @pre block must be a code block.
// @returns true on success, false otherwise.
bool ApplyBasicBlockSubGraphTransform(
    BasicBlockSubGraphTransformInterface* transform,
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BlockGraph::Block* block,
    BlockVector* new_blocks);

// Applies a series of BasicBlockSubGraphTransform to a single block. Takes
// care of basic-block decomposing the block, passes it to the transform, and
// recomposes the block.
//
// @param transforms the series of transform to apply.
// @param policy The policy object restricting how the transform is applied.
// @param block_graph the block containing the block to be transformed.
// @param block the block to be transformed.
// @param new_blocks On success, any newly created blocks will be returned
//     here. Note that this parameter may be NULL if you are not interested
//     in retrieving the set of new blocks.
// @pre block must be a code block.
// @returns true on success, false otherwise.
bool ApplyBasicBlockSubGraphTransforms(
    const std::vector<BasicBlockSubGraphTransformInterface*>& transforms,
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BlockGraph::Block* block,
    BlockVector* new_blocks);

}  // namespace block_graph

#endif  // SYZYGY_BLOCK_GRAPH_TRANSFORM_H_
