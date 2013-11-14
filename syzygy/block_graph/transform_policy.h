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
// Declares the interface for transform policy objects. The policy object is
// used to configure and guide the behaviour of the transformation process
// applied to a block-graph. The concepts in here are general for block-graphs,
// regardless of the image format or machine format of the underlying data.

#ifndef SYZYGY_BLOCK_GRAPH_TRANSFORM_POLICY_H_
#define SYZYGY_BLOCK_GRAPH_TRANSFORM_POLICY_H_

#include "syzygy/block_graph/block_graph.h"

namespace block_graph {

// The interface that guides image and basic-block decomposition decisions.
class TransformPolicyInterface {
 public:
  virtual ~TransformPolicyInterface() { }

  // This brings in a few types for the convenience of implementations of this
  // class.
  typedef block_graph::BlockGraph BlockGraph;

  // Determines if the given block is safe for basic-block decomposition.
  // @param block The block to evaluate.
  // @returns true if it is safe to basic block decompose the given block,
  //     false otherwise.
  virtual bool BlockIsSafeToBasicBlockDecompose(
      const BlockGraph::Block* block) const = 0;

  // Returns true if the given references @p ref from @p referrer may be safely
  // redirected. If both the referrer and the referenced blocks are irregular
  // in any way we cannot safely assume that @p reference has call semantics,
  // i.e., where a return address is at the top of stack at entry. For any
  // instrumentation or manipulation that uses return address swizzling,
  // instrumenting an unsafe reference generally leads to crashes.
  // @param referrer The block containing the reference.
  // @param reference The reference itself.
  // @returns true if the reference is safe and may be thunked, false otherwise.
  virtual bool ReferenceIsSafeToRedirect(
      const BlockGraph::Block* referrer,
      const BlockGraph::Reference& reference) const = 0;
};

}  // namespace block_graph

#endif  // SYZYGY_BLOCK_GRAPH_TRANSFORM_POLICY_H_
