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

#include "syzygy/block_graph/orderers/original_orderer.h"

namespace pe {
namespace {

typedef block_graph::BlockGraphTransformInterface Transform;
typedef block_graph::BlockGraphOrdererInterface Orderer;

using block_graph::ApplyBlockGraphTransform;
using block_graph::BlockGraph;
using block_graph::OrderedBlockGraph;
using block_graph::TransformPolicyInterface;
using core::RelativeAddress;

}  // namespace

PECoffRelinker::PECoffRelinker(const TransformPolicyInterface* transform_policy)
    : transform_policy_(transform_policy),
      allow_overwrite_(false),
      inited_(false),
      input_image_layout_(&block_graph_),
      headers_block_(NULL) {
  DCHECK(transform_policy != NULL);
}

bool PECoffRelinker::AppendTransform(Transform* transform) {
  DCHECK(transform != NULL);
  transforms_.push_back(transform);
  return true;
}

bool PECoffRelinker::AppendTransforms(
    const std::vector<Transform*>& transforms) {
  transforms_.insert(transforms_.end(), transforms.begin(), transforms.end());
  return true;
}

bool PECoffRelinker::AppendOrderer(Orderer* orderer) {
  DCHECK(orderer != NULL);
  orderers_.push_back(orderer);
  return true;
}

bool PECoffRelinker::AppendOrderers(const std::vector<Orderer*>& orderers) {
  orderers_.insert(orderers_.end(), orderers.begin(), orderers.end());
  return true;
}

bool PECoffRelinker::ApplyUserTransforms() {
  LOG(INFO) << "Transforming block graph.";
  if (!block_graph::ApplyBlockGraphTransforms(
           transforms_, transform_policy_, &block_graph_, headers_block_)) {
    return false;
  }
  return true;
}

bool PECoffRelinker::ApplyUserOrderers(OrderedBlockGraph* ordered_graph) {
  LOG(INFO) << "Ordering block graph.";

  if (orderers_.empty()) {
    // Default orderer.
    LOG(INFO) << "No orderers specified, applying default orderer.";
    block_graph::orderers::OriginalOrderer default_orderer;
    if (!default_orderer.OrderBlockGraph(ordered_graph, headers_block_)) {
      LOG(ERROR) << "Orderer failed: " << default_orderer.name() << ".";
      return false;
    }
  } else {
    // Supplied orderers.
    if (!block_graph::ApplyBlockGraphOrderers(
             orderers_, ordered_graph, headers_block_)) {
      return false;
    }
  }

  return true;
}

}  // namespace pe
