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

#ifndef SYZYGY_OPTIMIZE_TRANSFORMS_SUBGRAPH_TRANSFORM_H_
#define SYZYGY_OPTIMIZE_TRANSFORMS_SUBGRAPH_TRANSFORM_H_

#include "syzygy/block_graph/basic_block_subgraph.h"
#include "syzygy/block_graph/block_graph.h"
#include "syzygy/block_graph/transform_policy.h"
#include "syzygy/optimize/application_profile.h"

namespace optimize {
namespace transforms {

// A SubGraphTransformInterface is a pure virtual base class defining
// the basic-block transform API augmented with profiling information.
class SubGraphTransformInterface {
 public:
  typedef block_graph::BlockGraph BlockGraph;
  typedef block_graph::BasicBlockSubGraph BasicBlockSubGraph;
  typedef block_graph::TransformPolicyInterface TransformPolicyInterface;

  virtual ~SubGraphTransformInterface() { }

  // Applies this transform to the provided block.
  //
  // @param policy The policy object restricting how the transform is applied.
  // @param block_graph the block-graph of which the basic block subgraph
  //     is a part.
  // @param basic_block_subgraph the basic block subgraph to be transformed.
  // @param subgraph_profile the profile information of the subgraph.
  // @returns true on success, false otherwise.
  virtual bool TransformBasicBlockSubGraph(
      const TransformPolicyInterface* policy,
      BlockGraph* block_graph,
      BasicBlockSubGraph* basic_block_subgraph,
      ApplicationProfile* profile,
      SubGraphProfile* subgraph_profile) = 0;
};

}  // namespace transforms
}  // namespace optimize

#endif  // SYZYGY_OPTIMIZE_TRANSFORMS_SUBGRAPH_TRANSFORM_H_
