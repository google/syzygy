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
// The ChainedSubgraphTransforms is a BlockTransform used to apply a series of
// basic block transform to each Block. Each block is decomposed in a subgraph,
// the sequence of transforms is applied on the subgraph and then the block is
// reconstructed.
//
// It is intended to be used as follows:
//
//    ChainedSubgraphTransforms chains;
//    chains.AppendTransform(...);
//    chains.AppendTransform(...);
//    chains.AppendTransform(...);
//    chains.AppendTransform(...);
//    ApplyBlockGraphTransform(chains, ...);

#ifndef SYZYGY_OPTIMIZE_TRANSFORMS_CHAINED_SUBGRAPH_TRANSFORMS_H_
#define SYZYGY_OPTIMIZE_TRANSFORMS_CHAINED_SUBGRAPH_TRANSFORMS_H_

#include "syzygy/block_graph/basic_block_subgraph.h"
#include "syzygy/block_graph/block_graph.h"
#include "syzygy/block_graph/transforms/named_transform.h"
#include "syzygy/optimize/application_profile.h"
#include "syzygy/optimize/transforms/subgraph_transform.h"

namespace optimize {
namespace transforms {

class ChainedSubgraphTransforms
    : public block_graph::transforms::
          NamedBlockGraphTransformImpl<ChainedSubgraphTransforms> {
 public:
  typedef block_graph::BlockGraph BlockGraph;
  typedef block_graph::TransformPolicyInterface TransformPolicyInterface;
  typedef std::list<SubGraphTransformInterface*> TransformList;

  // Constructor.
  explicit ChainedSubgraphTransforms(ApplicationProfile* profile)
      : profile_(profile) {
    DCHECK_NE(reinterpret_cast<ApplicationProfile*>(NULL), profile);
  }

  // This is the main body of the transform. The transform decomposes each
  // block into a subgraph, applies the series of transform and rebuilds the
  // subgraph into a block.
  //
  // @param policy The policy object restricting how the transform is applied.
  // @param block_graph the block graph being transformed.
  // @param block the block to process.
  // @returns true on success, false otherwise.
  virtual bool TransformBlockGraph(const TransformPolicyInterface* policy,
                                   BlockGraph* block_graph,
                                   BlockGraph::Block* header_block) OVERRIDE;

  // Insert a subgraph transform to the optimizing pipeline.
  // @param transform a transform to be applied.
  void AppendTransform(SubGraphTransformInterface* transform);

  // The transform name.
  static const char kTransformName[];

 protected:
  // Transforms to be applied, in order.
  TransformList transforms_;

  // Application profile information.
  ApplicationProfile* profile_;

 private:
  DISALLOW_COPY_AND_ASSIGN(ChainedSubgraphTransforms);
};

}  // namespace transforms
}  // namespace optimize

#endif  // SYZYGY_OPTIMIZE_TRANSFORMS_CHAINED_SUBGRAPH_TRANSFORMS_H_
