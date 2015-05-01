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
// CoffPrepareHeadersTransform is the COFF-equivalent of
// PEPrepareHeadersTransform. The transform adjusts the contents of the
// headers block to match block graph metadata, so it can be written back as
// a COFF file.

#ifndef SYZYGY_PE_TRANSFORMS_COFF_PREPARE_HEADERS_TRANSFORM_H_
#define SYZYGY_PE_TRANSFORMS_COFF_PREPARE_HEADERS_TRANSFORM_H_

#include "syzygy/block_graph/transforms/named_transform.h"

namespace pe {
namespace transforms {

// A block graph transform that resizes the headers block to fit the number
// of sections of the block graph, and updates the file header
// accordingly. All references are also wiped from the headers block, so as
// to make removing dependent (referenced) blocks, such as relocation
// tables, possible.
class CoffPrepareHeadersTransform
    : public block_graph::transforms::NamedBlockGraphTransformImpl<
          CoffPrepareHeadersTransform> {
 public:
  typedef block_graph::BlockGraph BlockGraph;
  typedef block_graph::TransformPolicyInterface TransformPolicyInterface;

  // Apply this transform to the specified COFF block graph.
  //
  // @param policy The policy object restricting how the transform is applied.
  // @param block_graph The block graph to transform.
  // @param headers_block The COFF headers block of the block graph.
  // @returns true on success, false otherwise.
  virtual bool TransformBlockGraph(const TransformPolicyInterface* policy,
                                   BlockGraph* block_graph,
                                   BlockGraph::Block* headers_block) override;

  // The name of this transform.
  static const char kTransformName[];
};

}  // namespace transforms
}  // namespace pe

#endif  // SYZYGY_PE_TRANSFORMS_COFF_PREPARE_HEADERS_TRANSFORM_H_
