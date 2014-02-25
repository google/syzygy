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
// This class implements the basic block reordering transformation.
//
// The transformation reorders basic blocks to decrease the amount of taken and
// mispredicted jumps.
//
// see: K.Pettis, R.C.Hansen, Profile Guided Code Positioning,
//     Proceedings of the ACM SIGPLAN 1990 Conference on Programming Language
//     Design and Implementation, Vol. 25, No. 6, June 1990, pp. 16-27.

#ifndef SYZYGY_OPTIMIZE_TRANSFORMS_BASIC_BLOCK_REORDERING_TRANSFORM_H_
#define SYZYGY_OPTIMIZE_TRANSFORMS_BASIC_BLOCK_REORDERING_TRANSFORM_H_

#include "syzygy/block_graph/filterable.h"
#include "syzygy/block_graph/transform_policy.h"
#include "syzygy/block_graph/analysis/control_flow_analysis.h"
#include "syzygy/optimize/application_profile.h"
#include "syzygy/optimize/transforms/subgraph_transform.h"

namespace optimize {
namespace transforms {

// This transformation uses the Pettis algorithm to reorder basic blocks.
class BasicBlockReorderingTransform : public SubGraphTransformInterface {
 public:
  typedef block_graph::BasicBlockSubGraph BasicBlockSubGraph;
  typedef block_graph::BlockGraph BlockGraph;
  typedef block_graph::TransformPolicyInterface TransformPolicyInterface;
  typedef block_graph::analysis::ControlFlowAnalysis::BasicBlockOrdering
      BasicBlockOrdering;

  // Constructor.
  BasicBlockReorderingTransform() { }

  // @name SubGraphTransformInterface implementation.
  // @{
  virtual bool TransformBasicBlockSubGraph(
      const TransformPolicyInterface* policy,
      BlockGraph* block_graph,
      BasicBlockSubGraph* subgraph,
      ApplicationProfile* profile,
      SubGraphProfile* subgraph_profile) OVERRIDE;
  // @}

 protected:
  // Exposed for unittesting.
  // @{
  static bool FlattenStructuralTreeToAnOrder(
      const BasicBlockSubGraph* subgraph,
      const SubGraphProfile* subgraph_profile,
      BasicBlockOrdering* order);

  static uint64 EvaluateCost(const BasicBlockOrdering& order,
                             const SubGraphProfile& profile);

  static void CommitOrdering(
      const BasicBlockOrdering& order,
      block_graph::BasicEndBlock* basic_end_block,
      BasicBlockSubGraph::BasicBlockOrdering* target);
  // @}

 private:
  DISALLOW_COPY_AND_ASSIGN(BasicBlockReorderingTransform);
};

}  // namespace transforms
}  // namespace optimize

#endif  // SYZYGY_OPTIMIZE_TRANSFORMS_BASIC_BLOCK_REORDERING_TRANSFORM_H_
