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
// Implementation of the jump table count instrumentation transform.

#ifndef SYZYGY_INSTRUMENT_TRANSFORMS_JUMP_TABLE_COUNT_TRANSFORM_H_
#define SYZYGY_INSTRUMENT_TRANSFORMS_JUMP_TABLE_COUNT_TRANSFORM_H_

#include <string>
#include <vector>

#include "syzygy/block_graph/transforms/iterative_transform.h"
#include "syzygy/block_graph/transforms/named_transform.h"
#include "syzygy/instrument/transforms/add_indexed_frequency_data_transform.h"

namespace instrument {
namespace transforms {

// An iterative transform that instruments the accesses to the jump/case tables
// to measure the frequency of each case.
class JumpTableCaseCountTransform
    : public block_graph::transforms::IterativeTransformImpl<
          JumpTableCaseCountTransform>,
      public block_graph::transforms::NamedBasicBlockSubGraphTransformImpl<
          JumpTableCaseCountTransform> {
 public:
  typedef block_graph::BlockGraph BlockGraph;
  typedef block_graph::BasicBlockSubGraph BasicBlockSubGraph;

  // Initialize a new JumpTableCaseCountTransform instance using the default
  // module and function names.
  JumpTableCaseCountTransform();

 protected:
  typedef std::map<BlockGraph::Offset, BlockGraph::Block*> ThunkBlockMap;

  friend NamedBlockGraphTransformImpl<JumpTableCaseCountTransform>;
  friend IterativeTransformImpl<JumpTableCaseCountTransform>;
  friend NamedBasicBlockSubGraphTransformImpl<JumpTableCaseCountTransform>;

  // @name IterativeTransformImpl implementation.
  // @{
  bool PreBlockGraphIteration(BlockGraph* block_graph,
                              BlockGraph::Block* header_block);
  bool OnBlock(BlockGraph* block_graph, BlockGraph::Block* block);
  bool PostBlockGraphIteration(BlockGraph* block_graph,
                               BlockGraph::Block* header_block);
  // @}

  // @name BasicBlockSubGraphTransformInterface methods.
  // @{
  virtual bool TransformBasicBlockSubGraph(
      BlockGraph* block_graph,
      BasicBlockSubGraph* basic_block_subgraph) OVERRIDE;
  // @}

  // The instrumentation dll used by this transform.
  std::string instrument_dll_name_;

  // The name of this transform.
  static const char kTransformName[];

 private:
  DISALLOW_COPY_AND_ASSIGN(JumpTableCaseCountTransform);
};

}  // namespace transforms
}  // namespace instrument

#endif  // SYZYGY_INSTRUMENT_TRANSFORMS_JUMP_TABLE_COUNT_TRANSFORM_H_
