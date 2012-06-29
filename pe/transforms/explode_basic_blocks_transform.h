// Copyright 2012 Google Inc.
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
// Declares the ExplodeBasicBlocksTransform. This transform seperates all of
// the basic-blocks in a block-graph into individual code and data blocks.
// This is primarily a test to exercise the basic-block motion machinery.

#ifndef SYZYGY_PE_TRANSFORMS_EXPLODE_BASIC_BLOCKS_TRANSFORM_H_
#define SYZYGY_PE_TRANSFORMS_EXPLODE_BASIC_BLOCKS_TRANSFORM_H_

#include "base/file_path.h"
#include "syzygy/block_graph/transforms/iterative_transform.h"

namespace pe {
namespace transforms {

// A sample BlockGraph transform that explodes all basic-blocks in each code
// block into individual code or data blocks.
class ExplodeBasicBlocksTransform
    : public block_graph::transforms::IterativeTransformImpl<
          ExplodeBasicBlocksTransform> {
 public:
  typedef block_graph::BlockGraph BlockGraph;

  ExplodeBasicBlocksTransform();

  // Explodes each basic code block in @p block referenced by into separate
  // blocks, then erases @p block from @p block_graph.
  // @param block_graph The block graph being modified.
  // @param block The block to explode, this must be in @p block_graph.
  // @note This method is required by the IterativeTransformImpl parent class.
  bool OnBlock(BlockGraph* block_graph, BlockGraph::Block* block);

  // @name Accessors.
  // @{
  bool exclude_padding() const { return exclude_padding_; }
  void set_exclude_padding(bool value) { exclude_padding_ = value; }
  // @}

  // The transform name.
  static const char kTransformName[];

 protected:
  // Hooks for unit-testing.
  virtual bool SkipThisBlock(const BlockGraph::Block* candidate);

  // A flag for whether padding (and dead code) basic-blocks should be excluded
  // when reconstituting the exploded blocks.
  bool exclude_padding_;

  DISALLOW_COPY_AND_ASSIGN(ExplodeBasicBlocksTransform);
};

}  // namespace transforms
}  // namespace pe

#endif  // SYZYGY_PE_TRANSFORMS_EXPLODE_BASIC_BLOCKS_TRANSFORM_H_
