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
// Declares an ordering that duplicates the original ordering implied by the
// underlying block graph's source ranges. If the block graph has not been
// transformed the ordering will be identical to the ordering of the original
// image. If it has been changed, it will be substantially similar. The blocks
// in each section are ordered as follows:
//
//   1. Blocks with initialized data before blocks without.
//   2. Presence of source range data as primary key.
//   3. Source address of first data byte with source data as secondary key.
//   4. Finally, break ties with the always unique block ID.
//
// Sections are ordered by section ID, as the Decomposer currently guarantees
// that this will be the same order in which they were laid out in the original
// image.

#ifndef SYZYGY_BLOCK_GRAPH_ORDERERS_ORIGINAL_ORDERER_H_
#define SYZYGY_BLOCK_GRAPH_ORDERERS_ORIGINAL_ORDERER_H_

#include "syzygy/block_graph/orderers/named_orderer.h"

namespace block_graph {
namespace orderers {

class OriginalOrderer
    : public block_graph::orderers::NamedOrdererImpl<OriginalOrderer> {
 public:
  OriginalOrderer() { }

  // Applies this orderer to the provided block graph.
  //
  // @param ordered_block_graph the block graph to order.
  // @param header_block The header block of the block graph to transform.
  // @returns true on success, false otherwise.
  virtual bool OrderBlockGraph(OrderedBlockGraph* ordered_block_graph,
                               BlockGraph::Block* header_block) override;

  static const char kOrdererName[];

 private:
  DISALLOW_COPY_AND_ASSIGN(OriginalOrderer);
};

}  // namespace orderers
}  // namespace block_graph

#endif  // SYZYGY_BLOCK_GRAPH_ORDERERS_ORIGINAL_ORDERER_H_
