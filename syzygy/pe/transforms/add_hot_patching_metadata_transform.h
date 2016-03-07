// Copyright 2015 Google Inc. All Rights Reserved.
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
// A BlockGraph transform that saves a hot patching metadata stream (.syzyhp)
// that contains the locations and sizes of the blocks that have been prepared
// for hot patching.
//
// Before using this transform, one should prepare blocks for hot patching
// using the PEHotPatchingBasicBlockTransfrom and use the set_blocks_prepared
// method to pass the vector of prepared blocks.

#ifndef SYZYGY_PE_TRANSFORMS_ADD_HOT_PATCHING_METADATA_TRANSFORM_H_
#define SYZYGY_PE_TRANSFORMS_ADD_HOT_PATCHING_METADATA_TRANSFORM_H_

#include <vector>

#include "base/callback.h"
#include "syzygy/block_graph/transforms/named_transform.h"

namespace pe {
namespace transforms {

class AddHotPatchingMetadataTransform
    : public block_graph::transforms::NamedBlockGraphTransformImpl<
          AddHotPatchingMetadataTransform> {
 public:
  typedef block_graph::BlockGraph BlockGraph;
  typedef block_graph::TransformPolicyInterface TransformPolicyInterface;
  typedef std::vector<BlockGraph::Block*> BlockVector;

  // The transform name.
  static const char kTransformName[];

  AddHotPatchingMetadataTransform();

  // @name NamedBlockGraphTransformImpl implementation.
  // @{
  // Add the metadata stream to the BlockGraph.
  // @param policy The policy object restricting how the transform is applied.
  // @param block_graph the block graph being transformed.
  // @param header_block the header block.
  // @returns true on success, false otherwise.
  bool TransformBlockGraph(const TransformPolicyInterface* policy,
                           BlockGraph* block_graph,
                           BlockGraph::Block* header_block);
  // @}

  // @name Accessors.
  // @{
  // Before using this transform, one should pass a pointer to a vector of
  // blocks that have been prepared for hot patching to this function.
  // @param blocks_prepared The vector that contains the prepared blocks.
  void set_blocks_prepared(const BlockVector* blocks_prepared) {
    blocks_prepared_ = blocks_prepared;
  }
  // Retrieves the pointer to vector of blocks that have been prepared for
  // hot patching.
  // @returns the pointer to the vector of blocks.
  const BlockVector* blocks_prepared() {
    return blocks_prepared_;
  }
  // @}

 protected:
  // Adds a section containing the hot patching metadata.
  // @param block_graph The block_graph to modify.
  void AddHotPatchingSection(BlockGraph* block_graph);

  // Calculates the code size of a block. It assumes that everything before the
  // first DATA_LABEL is code. If the block contains no data labels, the whole
  // data of the block is considered to be code.
  // @param block The block to calculate
  // @returns the size of the code the block contains.
  static size_t CalculateCodeSize(const BlockGraph::Block* block);

 private:
  // This is a pointer to a vector that contains the blocks prepared for
  // hot patching. The TransformBlockGraph uses this data to build the
  // hot patching stream.
  const BlockVector* blocks_prepared_;

  DISALLOW_COPY_AND_ASSIGN(AddHotPatchingMetadataTransform);
};

}  // namespace transforms
}  // namespace pe

#endif  // SYZYGY_PE_TRANSFORMS_ADD_HOT_PATCHING_METADATA_TRANSFORM_H_
