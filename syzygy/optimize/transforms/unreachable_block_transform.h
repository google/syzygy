// Copyright 2014 Google Inc. All Rights Reserved.
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
// The unreachable block transform finds blocks that are not used and removes
// them from the block_graph. The goal of the transform is to decrease the image
// size. This algorithm is greedy and does not take decisions which increase the
// image size.
//
// The transform operates in two phases. It marks every reachable blocks
// starting from the roots. Afterwards, it removes every blocks not marked as
// they cannot be used.
//
// The algorithm consider blocks marked with the attribute PE_PARSED as roots.

#ifndef SYZYGY_OPTIMIZE_TRANSFORMS_UNREACHABLE_BLOCK_TRANSFORM_H_
#define SYZYGY_OPTIMIZE_TRANSFORMS_UNREACHABLE_BLOCK_TRANSFORM_H_

#include "syzygy/block_graph/block_graph.h"
#include "syzygy/block_graph/transforms/named_transform.h"

namespace optimize {
namespace transforms {

class UnreachableBlockTransform
    : public block_graph::transforms::
          NamedBlockGraphTransformImpl<UnreachableBlockTransform> {
 public:
  typedef block_graph::BlockGraph BlockGraph;
  typedef block_graph::TransformPolicyInterface TransformPolicyInterface;

  // Constructor.
  UnreachableBlockTransform() {
  }

  // Apply the transform on a given block graph.
  //
  // @param policy The policy object restricting how the transform is applied.
  // @param block_graph the block graph being transformed.
  // @param block the block to process.
  // @returns true on success, false otherwise.
  virtual bool TransformBlockGraph(const TransformPolicyInterface* policy,
                                   BlockGraph* block_graph,
                                   BlockGraph::Block* header_block) OVERRIDE;

  // The transform name.
  static const char kTransformName[];

  // Set the path to dump the unreachable graph.
  // @param path the path to the graph to generate.
  void set_unreachable_graph_path(const base::FilePath& path) {
    unreachable_graph_path_ = path;
  }

 private:
  // The path to dump a cachegrind file of the unreachable blocks.
  base::FilePath unreachable_graph_path_;

  DISALLOW_COPY_AND_ASSIGN(UnreachableBlockTransform);
};

}  // namespace transforms
}  // namespace optimize

#endif  // SYZYGY_OPTIMIZE_TRANSFORMS_UNREACHABLE_BLOCK_TRANSFORM_H_
