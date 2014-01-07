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
// Peephole optimization is a kind of optimization performed over a very small
// set of instructions  called a "peephole". It works by recognizing patterns
// of instructions that can be replaced by shorter or faster sets of
// instructions.

#ifndef SYZYGY_OPTIMIZE_TRANSFORMS_PEEPHOLE_TRANSFORM_H_
#define SYZYGY_OPTIMIZE_TRANSFORMS_PEEPHOLE_TRANSFORM_H_

#include "syzygy/block_graph/filterable.h"
#include "syzygy/block_graph/transform_policy.h"
#include "syzygy/optimize/application_profile.h"
#include "syzygy/optimize/transforms/subgraph_transform.h"

namespace optimize {
namespace transforms {

// This class implements the peephole transformation.
class PeepholeTransform : public SubGraphTransformInterface {
 public:
  typedef block_graph::BasicBlock BasicBlock;
  typedef block_graph::BasicBlockSubGraph BasicBlockSubGraph;
  typedef block_graph::BlockGraph BlockGraph;
  typedef block_graph::TransformPolicyInterface TransformPolicyInterface;

  // Constructor.
  PeepholeTransform() { }

  // @name SubGraphTransformInterface implementation.
  // @{
  // Apply the sequence of patterns to simplify the contents of a subgraph until
  // a fixed point is reached.
  virtual bool TransformBasicBlockSubGraph(
      const TransformPolicyInterface* policy,
      BlockGraph* block_graph,
      BasicBlockSubGraph* subgraph,
      ApplicationProfile* profile,
      SubGraphProfile* subgraph_profile) OVERRIDE;
  // @}

  // Apply a sequence of patterns to simplify the contents of a subgraph. The
  // sequence of patterns is applied once.
  // @param subgraph the subgraph to simplify.
  // @returns true if the subgraph has been simplified, false otherwise.
  static bool SimplifySubgraph(BasicBlockSubGraph* subgraph);

  // Remove dead instruction in the contents of a subgraph. The dead code
  // elimination is applied once.
  // @param subgraph the subgraph to simplify.
  // @returns true if the subgraph has been simplified, false otherwise.
  static bool RemoveDeadCodeSubgraph(BasicBlockSubGraph* subgraph);

 private:
  DISALLOW_COPY_AND_ASSIGN(PeepholeTransform);
};

}  // namespace transforms
}  // namespace optimize

#endif  // SYZYGY_OPTIMIZE_TRANSFORMS_PEEPHOLE_TRANSFORM_H_
