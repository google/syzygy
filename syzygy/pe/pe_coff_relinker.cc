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

#include "syzygy/pe/pe_coff_relinker.h"

namespace pe {

typedef block_graph::BlockGraphTransformInterface Transform;
typedef block_graph::BlockGraphOrdererInterface Orderer;

using block_graph::ApplyBlockGraphTransform;
using block_graph::BlockGraph;
using block_graph::OrderedBlockGraph;
using core::RelativeAddress;

PECoffRelinker::PECoffRelinker()
    : allow_overwrite_(false),
      inited_(false),
      input_image_layout_(&block_graph_),
      headers_block_(NULL) {
}

void PECoffRelinker::AppendTransform(Transform* transform) {
  DCHECK(transform != NULL);
  transforms_.push_back(transform);
}

void PECoffRelinker::AppendTransforms(
    const std::vector<Transform*>& transforms) {
  transforms_.insert(transforms_.end(), transforms.begin(), transforms.end());
}

void PECoffRelinker::AppendOrderer(Orderer* orderer) {
  DCHECK(orderer != NULL);
  orderers_.push_back(orderer);
}

void PECoffRelinker::AppendOrderers(const std::vector<Orderer*>& orderers) {
  orderers_.insert(orderers_.end(), orderers.begin(), orderers.end());
}

}  // namespace pe
