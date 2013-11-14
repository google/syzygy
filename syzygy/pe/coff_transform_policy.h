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
// Declares the COFF-specific transform policy object. This guides decisions
// made during image decomposition, basic-block decomposition, transforms and
// block building.

#ifndef SYZYGY_PE_COFF_TRANSFORM_POLICY_H_
#define SYZYGY_PE_COFF_TRANSFORM_POLICY_H_

#include "syzygy/block_graph/transform_policy.h"
#include "syzygy/pe/pe_transform_policy.h"

namespace pe {

// The interface that guides image and basic-block transform decisions for COFF
// files.
class CoffTransformPolicy : public block_graph::TransformPolicyInterface {
 public:
  CoffTransformPolicy() { }
  virtual ~CoffTransformPolicy() { }

  // @name TransformPolicyInterface implementation
  // @{
  virtual bool BlockIsSafeToBasicBlockDecompose(
      const BlockGraph::Block* block) const OVERRIDE;
  virtual bool ReferenceIsSafeToRedirect(
      const BlockGraph::Block* referrer,
      const BlockGraph::Reference& reference) const OVERRIDE;
  // @}

 private:
  // TODO(chrisha): For now we are only a thin wrapper around a PE transform
  //     policy. When the rest of the COFF machinery lands reimplement this to
  //     respect the differences between COFF and PE code blocks.
  PETransformPolicy pe_policy_;

  DISALLOW_COPY_AND_ASSIGN(CoffTransformPolicy);
};

}  // namespace pe

#endif  // SYZYGY_PE_COFF_TRANSFORM_POLICY_H_
