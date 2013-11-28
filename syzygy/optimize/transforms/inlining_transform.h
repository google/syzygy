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
// This class implements the functions inlining transformation.
//
// The inlining expansion replaces a function call site with the body of the
// callee. It is used to eliminate the time overhead when a function is called.
//
// TODO(etienneb): The actual implementation does not inline a sequence of
//    calls like Foo -> Bar -> Bat. This may be addressed by iterating this
//    function until no changes occurred or by changing the ordering the
//    blocks are traversed in the ChainedBasicBlockTransform.

#ifndef SYZYGY_OPTIMIZE_TRANSFORMS_INLINING_TRANSFORM_H_
#define SYZYGY_OPTIMIZE_TRANSFORMS_INLINING_TRANSFORM_H_

#include "syzygy/block_graph/filterable.h"
#include "syzygy/block_graph/transform_policy.h"
#include "syzygy/block_graph/transforms/iterative_transform.h"
#include "syzygy/block_graph/transforms/named_transform.h"
#include "syzygy/optimize/application_profile.h"

namespace optimize {
namespace transforms {

class InliningTransform
    : public block_graph::transforms::NamedBasicBlockSubGraphTransformImpl<
          InliningTransform> {
 public:
  typedef block_graph::BasicBlockSubGraph BasicBlockSubGraph;
  typedef block_graph::BlockGraph BlockGraph;
  typedef block_graph::TransformPolicyInterface TransformPolicyInterface;
  typedef std::map<BlockGraph::Block*, BasicBlockSubGraph> SubGraphCache;

  // Constructor.
  // @param profile Application profile information.
  explicit InliningTransform(ApplicationProfile* profile);

  // @name BasicBlockSubGraphTransformInterface implementation.
  // @{
  virtual bool TransformBasicBlockSubGraph(
      const TransformPolicyInterface* policy,
      BlockGraph* block_graph,
      BasicBlockSubGraph* basic_block_subgraph) OVERRIDE;
  // @}

  // The transform name.
  static const char kTransformName[];

 protected:
  ApplicationProfile* profile_;

  // A cache of decomposed subgraphs.
  SubGraphCache subgraph_cache_;

 private:
  DISALLOW_COPY_AND_ASSIGN(InliningTransform);
};

}  // namespace transforms
}  // namespace optimize

#endif  // SYZYGY_OPTIMIZE_TRANSFORMS_INLINING_TRANSFORM_H_
