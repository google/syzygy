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
// TODO(etienneb): describe the algorithm here.

#include "syzygy/optimize/transforms/inlining_transform.h"

namespace optimize {
namespace transforms {

const char InliningTransform::kTransformName[] =
    "InlineBasicBlockTransform";

bool InliningTransform::TransformBasicBlockSubGraph(
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BasicBlockSubGraph* subgraph) {
  DCHECK_NE(reinterpret_cast<TransformPolicyInterface*>(NULL), policy);
  DCHECK_NE(reinterpret_cast<BlockGraph*>(NULL), block_graph);
  DCHECK_NE(reinterpret_cast<BasicBlockSubGraph*>(NULL), subgraph);

  // TODO(etienneb): Implement this function.

  return true;
}

}  // namespace transforms
}  // namespace optimize
