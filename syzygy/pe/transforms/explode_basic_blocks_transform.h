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
// Declares the ExplodeBasicBlockSubGraphTransform and
// ExplodeBasicBlocksTransform classes. These transforms separate all
// of the basic-blocks in a subgraph or block-graph respectively, into
// individual code and data blocks. This is primarily a test to exercise
// the basic-block motion machinery.

#ifndef SYZYGY_PE_TRANSFORMS_EXPLODE_BASIC_BLOCKS_TRANSFORM_H_
#define SYZYGY_PE_TRANSFORMS_EXPLODE_BASIC_BLOCKS_TRANSFORM_H_

#include "syzygy/block_graph/transforms/iterative_transform.h"
#include "syzygy/block_graph/transforms/named_transform.h"

namespace pe {
namespace transforms {

// A BasicBlockSubBlockGraph transform that explodes all basic-blocks in a
// basic_block subgraph into individual code or data blocks.
class ExplodeBasicBlockSubGraphTransform
    : public block_graph::transforms::NamedBasicBlockSubGraphTransformImpl<
          ExplodeBasicBlockSubGraphTransform> {
 public:
  typedef block_graph::BlockGraph BlockGraph;
  typedef block_graph::BasicBlockSubGraph BasicBlockSubGraph;
  typedef block_graph::TransformPolicyInterface TransformPolicyInterface;

  // Initialize a new ExplodeBasicBlockSubGraphTransform instance.
  explicit ExplodeBasicBlockSubGraphTransform(bool exclude_padding);

  // @name BasicBlockSubGraphTransformInterface methods.
  // @{
  virtual bool TransformBasicBlockSubGraph(
      const TransformPolicyInterface* policy,
      BlockGraph* block_graph,
      BasicBlockSubGraph* basic_block_subgraph) override;
  // @}

  // The transform name.
  static const char kTransformName[];

  // @name Accessors.
  // @{
  size_t output_code_blocks() const { return output_code_blocks_; }
  size_t output_data_blocks() const { return output_data_blocks_; }
  // @}

 protected:
  // A flag for whether padding (and dead code) basic-blocks should be excluded
  // when reconstituting the exploded blocks.
  bool exclude_padding_;
  size_t output_code_blocks_;
  size_t output_data_blocks_;

 private:
  DISALLOW_COPY_AND_ASSIGN(ExplodeBasicBlockSubGraphTransform);
};

// A BlockGraph transform that, for every code block which is eligible for
// decomposition to basic-blocks, and transforms every basic-blocks in each
// code block into an individual code or data block.
class ExplodeBasicBlocksTransform
    : public block_graph::transforms::IterativeTransformImpl<
          ExplodeBasicBlocksTransform> {
 public:
  typedef block_graph::BlockGraph BlockGraph;
  typedef block_graph::TransformPolicyInterface TransformPolicyInterface;

  // Initialize a new ExplodeBasicBlocksTransform instance.
  ExplodeBasicBlocksTransform();

  // Explodes each basic code block in @p block referenced by into separate
  // blocks, then erases @p block from @p block_graph.
  // @param policy The policy object restricting how the transform is applied.
  // @param block_graph The block graph being modified.
  // @param block The block to explode, this must be in @p block_graph.
  // @note This method is required by the IterativeTransformImpl parent class.
  bool OnBlock(const TransformPolicyInterface* policy,
               BlockGraph* block_graph,
               BlockGraph::Block* block);

  // Logs metrics about the performed transform.
  // @param policy The policy object restricting how the transform is applied.
  // @param block_graph The block graph being modified.
  // @param header_block The header block associated with the image.
  bool PostBlockGraphIteration(const TransformPolicyInterface* policy,
                               BlockGraph* block_graph,
                               BlockGraph::Block* header_block);

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

  // Statistics on blocks encountered and generated.
  size_t non_decomposable_code_blocks_;
  size_t skipped_code_blocks_;
  size_t input_code_blocks_;
  size_t output_code_blocks_;
  size_t output_data_blocks_;

 private:
  DISALLOW_COPY_AND_ASSIGN(ExplodeBasicBlocksTransform);
};

}  // namespace transforms
}  // namespace pe

#endif  // SYZYGY_PE_TRANSFORMS_EXPLODE_BASIC_BLOCKS_TRANSFORM_H_
