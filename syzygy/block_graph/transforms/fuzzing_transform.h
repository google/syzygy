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

#ifndef SYZYGY_BLOCK_GRAPH_TRANSFORMS_FUZZING_TRANSFORM_H_
#define SYZYGY_BLOCK_GRAPH_TRANSFORMS_FUZZING_TRANSFORM_H_

#include "syzygy/block_graph/iterate.h"
#include "syzygy/block_graph/transforms/iterative_transform.h"
#include "syzygy/block_graph/transforms/named_transform.h"

namespace block_graph {
namespace transforms {

typedef block_graph::BlockGraph BlockGraph;
typedef block_graph::BasicBlockSubGraph BasicBlockSubGraph;

// This class applies the liveness fuzzing transformation to each basic block.
//
// At each program point where a register has been proven dead (i.e., it has
// no downstream read dependency), an instruction is inserted which modifies
// the contents of the register to contain a dummy value.
class LivenessFuzzingBasicBlockTransform
    : public block_graph::transforms::NamedBasicBlockSubGraphTransformImpl<
          LivenessFuzzingBasicBlockTransform> {
 public:
  LivenessFuzzingBasicBlockTransform() {}

  // The transform name.
  static const char kTransformName[];

 protected:
  // @name BasicBlockSubGraphTransformInterface method.
  virtual bool TransformBasicBlockSubGraph(
      const TransformPolicyInterface* policy,
      BlockGraph* block_graph,
      BasicBlockSubGraph* basic_block_subgraph) override;

 private:
  DISALLOW_COPY_AND_ASSIGN(LivenessFuzzingBasicBlockTransform);
};

// This transformation applied some basic block transform to validate analysis
// done on subgraph. The behavior must be the same with each transformation.
class FuzzingTransform
    : public block_graph::transforms::IterativeTransformImpl<FuzzingTransform> {
 public:
  FuzzingTransform();

  // @name IterativeTransformImpl implementation.
  // @{
  bool OnBlock(const TransformPolicyInterface* policy,
               BlockGraph* block_graph,
               BlockGraph::Block* block);
  // @}

  // The transform name.
  static const char kTransformName[];

 private:
  DISALLOW_COPY_AND_ASSIGN(FuzzingTransform);
};

}  // namespace transforms
}  // namespace block_graph

#endif  // SYZYGY_BLOCK_GRAPH_TRANSFORMS_FUZZING_TRANSFORM_H_
