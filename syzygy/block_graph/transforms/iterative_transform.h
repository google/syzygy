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
// Declares a BlockGraphTransform implementation wrapping the common transform
// that iterates over each block in the image.

#ifndef SYZYGY_BLOCK_GRAPH_TRANSFORMS_ITERATIVE_TRANSFORM_H_
#define SYZYGY_BLOCK_GRAPH_TRANSFORMS_ITERATIVE_TRANSFORM_H_

#include "base/bind.h"
#include "syzygy/block_graph/iterate.h"
#include "syzygy/block_graph/transforms/named_transform.h"

namespace block_graph {
namespace transforms {

// An implementation of a BlockGraph transform encapsulating the simple pattern
// of Pre, per-block, and Post functions. The derived class is responsible for
// implementing 'OnBlock' and 'name', and may optionally override Pre and
// Post. The derived type needs to also define the static public member
// variable:
//
//   static const char DerivedType::kTransformName[];
//
// @tparam DerivedType the type of the derived class.
template<class DerivedType>
class IterativeTransformImpl
    : public NamedBlockGraphTransformImpl<DerivedType> {
 public:
  // This is the main body of the transform. This takes care of calling Pre,
  // iterating through the blocks and calling OnBlock for each one, and finally
  // calling Post. If any step fails the entire transform fails.
  //
  // @param policy The policy object restricting how the transform is applied.
  // @param block_graph the block graph being transformed.
  // @param block the block to process.
  // @returns true on success, false otherwise.
  virtual bool TransformBlockGraph(const TransformPolicyInterface* policy,
                                   BlockGraph* block_graph,
                                   BlockGraph::Block* header_block) override;

 protected:
  // This function is called prior to the iterative portion of the transform.
  // If it fails, the rest of the transform will not run. A default
  // implementation is provided but it may be overridden.
  //
  // @param policy The policy object restricting how the transform is applied.
  // @param block_graph the block graph being transformed.
  // @param header_block the header block.
  // @returns true on success, false otherwise.
  bool PreBlockGraphIteration(const TransformPolicyInterface* policy,
                              BlockGraph* block_graph,
                              BlockGraph::Block* header_block) {
    return true;
  }

  // This function is called for every block returned by the iterator. If it
  // returns false the transform will be aborted and is considered to have
  // failed. This function must be implemented by the derived class. This will
  // not be called if PreBlockGraphIteration fails.
  //
  // @param policy The policy object restricting how the transform is applied.
  // @param block_graph the block graph being transformed.
  // @param block the block to process.
  // @returns true on success, false otherwise.
  bool OnBlock(const TransformPolicyInterface* policy,
               BlockGraph* block_graph,
               BlockGraph::Block* block);

  // This function is called after the iterative portion of the transform. If
  // it fails, the transform is considered to have failed. A default
  // implementation is provided but it may be overridden. This will not be
  // called if PreBlockGraphIteration fails or any call to OnBlock fails.
  //
  // @param policy The policy object restricting how the transform is applied.
  // @param block_graph the block graph being transformed.
  // @param header_block the header block.
  // @returns true on success, false otherwise.
  bool PostBlockGraphIteration(const TransformPolicyInterface* policy,
                               BlockGraph* block_graph,
                               BlockGraph::Block* header_block) {
    return true;
  }
};

template <class DerivedType>
bool IterativeTransformImpl<DerivedType>::TransformBlockGraph(
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BlockGraph::Block* header_block) {
  DCHECK(policy != NULL);
  DCHECK(block_graph != NULL);
  DCHECK(header_block != NULL);

  DerivedType* self = static_cast<DerivedType*>(this);

  if (!self->PreBlockGraphIteration(policy, block_graph, header_block)) {
    LOG(ERROR) << "PreBlockGraphIteration failed for \"" << name()
               << "\" transform.";
    return false;
  }

  bool result = IterateBlockGraph(
      base::Bind(&DerivedType::OnBlock,
                 base::Unretained(self),
                 base::Unretained(policy)),
      block_graph);
  if (!result) {
    LOG(ERROR) << "Iteration failed for \"" << name() << "\" transform.";
    return false;
  }

  if (!self->PostBlockGraphIteration(policy, block_graph, header_block)) {
    LOG(ERROR) << "PostBlockGraphIteration failed for \"" << name()
               << "\" transform.";
    return false;
  }

  return true;
}

}  // namespace transforms
}  // namespace block_graph

#endif  // SYZYGY_BLOCK_GRAPH_TRANSFORMS_ITERATIVE_TRANSFORM_H_
