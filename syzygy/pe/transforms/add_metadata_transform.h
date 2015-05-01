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
// Declares a basic BlockGraphTransform for adding a Syzygy-toolchain metadata
// section to a PE image.

#ifndef SYZYGY_PE_TRANSFORMS_ADD_METADATA_TRANSFORM_H_
#define SYZYGY_PE_TRANSFORMS_ADD_METADATA_TRANSFORM_H_

#include "base/files/file_path.h"
#include "syzygy/block_graph/transforms/named_transform.h"

namespace pe {
namespace transforms {

using block_graph::BlockGraph;
using block_graph::TransformPolicyInterface;
using block_graph::transforms::NamedBlockGraphTransformImpl;

class AddMetadataTransform
    : public NamedBlockGraphTransformImpl<AddMetadataTransform> {
 public:
  // @param module_path the path to the module that the metadata will refer to.
  //     This should be the original module from which the block-graph was
  //     generated.
  explicit AddMetadataTransform(const base::FilePath& module_path);

  // Applies this transform to the provided PE image block graph.
  //
  // @param policy The policy object restricting how the transform is applied.
  // @param block_graph The block graph to transform.
  // @param dos_header_block The DOS header block of the block graph. This is
  //     unused in this transform.
  // @returns true on success, false otherwise.
  virtual bool TransformBlockGraph(
      const TransformPolicyInterface* policy,
      BlockGraph* block_graph,
      BlockGraph::Block* /*dos_header_block*/) override;

  BlockGraph::Block* metadata_block() const { return metadata_block_; }

  // The name of this transform.
  static const char kTransformName[];

 private:
  // The path to the module which the metadata refers to.
  base::FilePath module_path_;

  // The block that has been created or reused to hold metadata.
  BlockGraph::Block* metadata_block_;

  DISALLOW_COPY_AND_ASSIGN(AddMetadataTransform);
};

}  // namespace transforms
}  // namespace pe

#endif  // SYZYGY_PE_TRANSFORMS_ADD_METADATA_TRANSFORM_H_
