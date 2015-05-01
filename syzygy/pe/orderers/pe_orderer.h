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
// Declares a PE-specific orderer. This orderer ensures that no expectations of
// a valid PE image are violated. For example, that relocations are in the
// last section and that resources are in the second to last section.
//
// NOTE: It currently does not, but will eventually, ensure that data
//     directories and their associated data structures are laid out as
//     expected (contiguous when they need to be, in the appropriate sections,
//     etc).

#ifndef SYZYGY_PE_ORDERERS_PE_ORDERER_H_
#define SYZYGY_PE_ORDERERS_PE_ORDERER_H_

#include "syzygy/block_graph/orderers/named_orderer.h"

namespace pe {
namespace orderers {

class PEOrderer
    : public block_graph::orderers::NamedOrdererImpl<PEOrderer> {
 public:
  typedef block_graph::BlockGraph BlockGraph;
  typedef block_graph::OrderedBlockGraph OrderedBlockGraph;

  PEOrderer() { }

  // Applies this orderer to the provided block graph.
  //
  // @param ordered_block_graph the block graph to order.
  // @param dos_header_block The header block of the block graph to transform.
  //     This must be a valid DOS header block, and refer to a valid NT
  //     headers block.
  // @returns true on success, false otherwise.
  virtual bool OrderBlockGraph(OrderedBlockGraph* ordered_block_graph,
                               BlockGraph::Block* dos_header_block) override;

  static const char kOrdererName[];

 private:
  DISALLOW_COPY_AND_ASSIGN(PEOrderer);
};

}  // namespace orderers
}  // namespace pe

#endif  // SYZYGY_PE_ORDERERS_PE_ORDERER_H_
