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
// The ChainedBasicBlockTransforms is a BlockTransform used to apply a series of
// basic block transform to each Block. Each block is decomposed in a subgraph,
// the sequence of transforms is applied on the subgraph and then the block is
// reconstructed.
//
// It is intended to be used as follows:
//
//    ChainedBasicBlockTransforms chains;
//    chains.AppendTransform(...);
//    chains.AppendTransform(...);
//    chains.AppendTransform(...);
//    chains.AppendTransform(...);
//    ApplyBlockGraphTransform(chains, ...);

#ifndef SYZYGY_BLOCK_GRAPH_TRANSFORMS_CHAINED_BASIC_BLOCK_TRANSFORMS_H_
#define SYZYGY_BLOCK_GRAPH_TRANSFORMS_CHAINED_BASIC_BLOCK_TRANSFORMS_H_

#include "syzygy/block_graph/basic_block.h"
#include "syzygy/block_graph/transform_policy.h"
#include "syzygy/block_graph/transforms/iterative_transform.h"

namespace block_graph {
namespace transforms {

// This class chains a series of BasicBlockTransforms to be applied on blocks.
class ChainedBasicBlockTransforms
    : public block_graph::transforms::
                 IterativeTransformImpl<ChainedBasicBlockTransforms> {
 public:
  typedef block_graph::BlockGraph BlockGraph;
  typedef block_graph::TransformPolicyInterface TransformPolicyInterface;

  // Constructor.
  ChainedBasicBlockTransforms() {}

  // @name IterativeTransformImpl implementation.
  // @{
  bool OnBlock(const TransformPolicyInterface* policy,
               BlockGraph* block_graph,
               BlockGraph::Block* block);
  // @}

  // @param transform a transform to be applied.
  // @returns true on success, or false otherwise.
  bool AppendTransform(BasicBlockSubGraphTransformInterface* transform);

  // The transform name.
  static const char kTransformName[];

 protected:
  // Transforms to be applied, in order.
  std::vector<BasicBlockSubGraphTransformInterface*> transforms_;

 private:
  DISALLOW_COPY_AND_ASSIGN(ChainedBasicBlockTransforms);
};

}  // namespace transforms
}  // namespace block_graph

#endif  // SYZYGY_BLOCK_GRAPH_TRANSFORMS_CHAINED_BASIC_BLOCK_TRANSFORMS_H_
