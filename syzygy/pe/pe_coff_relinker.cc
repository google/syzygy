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
using core::RelativeAddress;

// Apply transforms to the specified block graph.
//
// @param transforms the transforms to apply.
// @param block_graph the block graph to transform.
// @param headers_block the headers block in @p block_graph.
// @returns true on success, or false on failure.
bool ApplyTransformsToBlockGraph(const std::vector<Transform*>& transforms,
                                 BlockGraph* block_graph,
                                 BlockGraph::Block* headers_block) {
  DCHECK(block_graph != NULL);
  DCHECK(headers_block != NULL);

  for (size_t i = 0; i < transforms.size(); ++i) {
    LOG(INFO) << "Applying transform: " << transforms[i]->name() << ".";
    if (!ApplyBlockGraphTransform(transforms[i], block_graph, headers_block))
      return false;
  }

  return true;
}

// Apply orderers to the specified block graph.
//
// @param orderers the orderers to apply.
// @param ordered_graph the ordered block graph to order or reorder.
// @param headers_block the headers block in @p block_graph.
// @returns true on success, or false on failure.
bool ApplyOrderersToBlockGraph(const std::vector<Orderer*>& orderers,
                               OrderedBlockGraph* ordered_graph,
                               BlockGraph::Block* headers_block) {
  DCHECK(ordered_graph != NULL);
  DCHECK(headers_block != NULL);

  for (size_t i = 0; i < orderers.size(); ++i) {
    Orderer* orderer = orderers[i];
    DCHECK(orderer != NULL);

    LOG(INFO) << "Applying orderer: " << orderer->name();
    if (!orderer->OrderBlockGraph(ordered_graph, headers_block)) {
      LOG(ERROR) << "Orderer failed: " << orderer->name() << ".";
      return false;
    }
  }

  return true;
}

}  // namespace

PECoffRelinker::PECoffRelinker(const TransformPolicyInterface* transform_policy)
    : transform_policy_(transform_policy),
      allow_overwrite_(false),
      inited_(false),
      input_image_layout_(&block_graph_),
      headers_block_(NULL) {
  DCHECK(transform_policy != NULL);
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

bool PECoffRelinker::ApplyTransforms(
    const std::vector<Transform*>& post_transforms) {
  LOG(INFO) << "Transforming block graph.";
  if (!ApplyTransformsToBlockGraph(transforms_, &block_graph_, headers_block_))
    return false;
  if (!ApplyTransformsToBlockGraph(post_transforms,
                                   &block_graph_, headers_block_)) {
    return false;
  }
  return true;
}

bool PECoffRelinker::ApplyOrderers(const std::vector<Orderer*>& post_orderers,
                                   OrderedBlockGraph* ordered_graph) {
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
    if (!ApplyOrderersToBlockGraph(orderers_, ordered_graph, headers_block_))
      return false;
  }

  if (!ApplyOrderersToBlockGraph(post_orderers, ordered_graph, headers_block_))
    return false;

  return true;
}

}  // namespace pe
