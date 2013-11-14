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

#include "syzygy/pe/coff_transform_policy.h"

namespace pe {

bool CoffTransformPolicy::BlockIsSafeToBasicBlockDecompose(
    const BlockGraph::Block* block) const {
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), block);
  return pe_policy_.BlockIsSafeToBasicBlockDecompose(block);
}

bool CoffTransformPolicy::ReferenceIsSafeToRedirect(
    const BlockGraph::Block* referrer,
    const BlockGraph::Reference& reference) const {
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), referrer);
  return pe_policy_.ReferenceIsSafeToRedirect(referrer, reference);
}

}  // namespace pe
