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
// Declares an ordering that orders blocks as explicitly specified in an
// Reorderer::Order object. The order will be preserved for any sections without
// an explicitly specified order. Sections whose order is only partially
// specified will see the unspecified blocks pushed to the tail of the section
// in their original relative order.

#ifndef SYZYGY_REORDER_ORDERERS_EXPLICIT_ORDERER_H_
#define SYZYGY_REORDER_ORDERERS_EXPLICIT_ORDERER_H_

#include "syzygy/block_graph/orderers/named_orderer.h"
#include "syzygy/reorder/reorderer.h"

namespace reorder {
namespace orderers {

class ExplicitOrderer
    : public block_graph::orderers::NamedOrdererImpl<ExplicitOrderer> {
 public:
  typedef block_graph::BlockGraph BlockGraph;
  typedef block_graph::OrderedBlockGraph OrderedBlockGraph;

  // Constructor.
  // @param order a pointer to the order to be applied. The order object must
  //     outlive this orderer.
  explicit ExplicitOrderer(const Reorderer::Order* order) : order_(order) {
    DCHECK(order != NULL);
  }

  // Applies this orderer to the provided block graph.
  //
  // @param ordered_block_graph the block graph to order.
  // @returns true on success, false otherwise.
  virtual bool OrderBlockGraph(OrderedBlockGraph* ordered_block_graph,
                               BlockGraph::Block* header_block_unused) override;

  static const char kOrdererName[];

 private:
  const Reorderer::Order* order_;

  DISALLOW_COPY_AND_ASSIGN(ExplicitOrderer);
};

}  // namespace orderers
}  // namespace reorder

#endif  // SYZYGY_REORDER_ORDERERS_EXPLICIT_ORDERER_H_
