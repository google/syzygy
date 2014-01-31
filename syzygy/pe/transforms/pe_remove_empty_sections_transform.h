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
// Declares a BlockGraphTransform that removes empty sections (e.g sections
// without blocks). Empty sections cannot contribute any bytes to the final
// image. It is safe to remove them.

#ifndef SYZYGY_PE_TRANSFORMS_PE_REMOVE_EMPTY_SECTIONS_TRANSFORM_H_
#define SYZYGY_PE_TRANSFORMS_PE_REMOVE_EMPTY_SECTIONS_TRANSFORM_H_

#include "syzygy/block_graph/transforms/named_transform.h"

namespace pe {
namespace transforms {

using block_graph::transforms::NamedBlockGraphTransformImpl;

// A transform for removing empty sections in a given block graph.
class PERemoveEmptySectionsTransform
    : public NamedBlockGraphTransformImpl<PERemoveEmptySectionsTransform> {
 public:
  typedef block_graph::BlockGraph BlockGraph;
  typedef block_graph::TransformPolicyInterface TransformPolicyInterface;

  PERemoveEmptySectionsTransform();

  // Performs the transform which removes every empty section.
  //
  // @param policy The policy object restricting how the transform is applied.
  // @param block_graph The block graph to transform.
  // @param dos_header_block the block containing the module's DOS header.
  // @returns true on success, false otherwise.
  virtual bool TransformBlockGraph(
      const TransformPolicyInterface* policy,
      BlockGraph* block_graph,
      BlockGraph::Block* dos_header_block) OVERRIDE;

  // The name of this transform.
  static const char kTransformName[];
};

}  // namespace transforms
}  // namespace pe

#endif  // SYZYGY_PE_TRANSFORMS_PE_REMOVE_EMPTY_SECTIONS_TRANSFORM_H_
