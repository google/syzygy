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
// Declares a transform for converting non-relocation reference types in code
// blocks to equivalent relocation references. Legacy transformations that have
// not been updated to fully support COFF may insert these kinds of references
// when generating or altering code.
//
// TODO(chrisha): Remove this eventually. It appears that *all* references use
//     the RELOC_REF_BIT when processing COFF files, and that reference types
//     are never mixed. Thus, the bit basically only indicates that we are
//     dealing with a COFF file, which is already known.

#ifndef SYZYGY_PE_TRANSFORMS_COFF_CONVERT_LEGACY_CODE_REFERENCES_TRANSFORM_H_
#define SYZYGY_PE_TRANSFORMS_COFF_CONVERT_LEGACY_CODE_REFERENCES_TRANSFORM_H_

#include "syzygy/block_graph/transforms/named_transform.h"

namespace pe {
namespace transforms {

// A transform for converting non-relocation reference types in code blocks
// to equivalent relocation references.
class CoffConvertLegacyCodeReferencesTransform
    : public block_graph::transforms::NamedBlockGraphTransformImpl<
          CoffConvertLegacyCodeReferencesTransform> {
 public:
  typedef block_graph::BlockGraph BlockGraph;
  typedef block_graph::TransformPolicyInterface TransformPolicyInterface;

  // Construct a CoffConvertLegacyCodeReferencesTransform.
  CoffConvertLegacyCodeReferencesTransform() {}

  // Perform the transform. Convert legacy references in all code blocks.
  // @param policy the policy object restricting how the transform is applied.
  // @param block_graph the BlockGraph to transform.
  // @param headers_block the block containing the headers. This is currently
  //     unused.
  // @returns true on success, false otherwise.
  virtual bool TransformBlockGraph(
      const TransformPolicyInterface* policy,
      BlockGraph* block_graph,
      BlockGraph::Block* /* headers_block */) OVERRIDE;

  // The name of this transform.
  static const char kTransformName[];

 private:
  DISALLOW_COPY_AND_ASSIGN(CoffConvertLegacyCodeReferencesTransform);
};

}  // namespace transforms
}  // namespace pe

#endif  // SYZYGY_PE_TRANSFORMS_COFF_CONVERT_LEGACY_CODE_REFERENCES_TRANSFORM_H_
