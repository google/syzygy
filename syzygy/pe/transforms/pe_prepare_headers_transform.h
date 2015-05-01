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
// Declares a BlockGraphTransform that trims the DOS header and ensures the NT
// headers are sufficiently big to represent all sections in the block graph.
// To be applied before layout so that the layout remains valid after
// finalizing the headers.
//
// After this transform both the DOS header and the NT headers have been sized
// appropriately for the resulting image. The DOS header has also been finalized
// and will be valid after the transform. The NT headers are not necessarily
// valid.

#ifndef SYZYGY_PE_TRANSFORMS_PE_PREPARE_HEADERS_TRANSFORM_H_
#define SYZYGY_PE_TRANSFORMS_PE_PREPARE_HEADERS_TRANSFORM_H_

#include "syzygy/block_graph/transforms/named_transform.h"

namespace pe {
namespace transforms {

class PEPrepareHeadersTransform
    : public block_graph::transforms::NamedBlockGraphTransformImpl<
          PEPrepareHeadersTransform> {
 public:
  typedef block_graph::BlockGraph BlockGraph;
  typedef block_graph::TransformPolicyInterface TransformPolicyInterface;

  // Applies this transform to the provided PE image block graph.
  //
  // @param policy The policy object restricting how the transform is applied.
  // @param block_graph The block graph to transform.
  // @param dos_header_block The DOS header block of the block graph.
  // @returns true on success, false otherwise.
  virtual bool TransformBlockGraph(
      const TransformPolicyInterface* policy,
      BlockGraph* block_graph,
      BlockGraph::Block* dos_header_block) override;

  // The name of this transform.
  static const char kTransformName[];
};

}  // namespace transforms
}  // namespace pe

#endif  // SYZYGY_PE_TRANSFORMS_PE_PREPARE_HEADERS_TRANSFORM_H_
