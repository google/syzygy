// Copyright 2015 Google Inc. All Rights Reserved.
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

#include "syzygy/protect/protect_lib/protected_basic_block_filter.h"

namespace  protect {

  using block_graph::BlockGraph;
  using block_graph::BasicBlockSubGraph;
  using block_graph::BasicBlock;

  void ProtectedBBlockFilter::Add(
    std::pair<block_graph::BlockGraph::RelativeAddress,
    block_graph::BlockGraph::Size> &tuple)
  {
    this->filter.push_back(tuple);
  }

  bool ProtectedBBlockFilter::Filter(
      std::vector<BasicBlock *>& to_protect,
      BasicBlockSubGraph *subgraph)
  {
    std::vector < std::pair<BlockGraph::RelativeAddress,
      BlockGraph::Size> > ::iterator adr_range = filter.begin();

    BlockGraph::RelativeAddress start_addr, block_addr;
    const BlockGraph::Block *original_block = subgraph->original_block();

    if (original_block == NULL) // the subgraph is new; it has no original block
      return false;
    // else
      const BasicBlockSubGraph::BasicBlockOrdering& original_order =
        subgraph->block_descriptions().front().basic_block_order;
      BasicBlockSubGraph::BasicBlockOrdering::const_iterator bb_iter =
        original_order.begin();
      for (; bb_iter != original_order.end(); ++bb_iter) {
        if ((*bb_iter)->type() != BasicBlock::BasicBlockType::BASIC_CODE_BLOCK)
          continue;

        const block_graph::BasicCodeBlock* bb =
          block_graph::BasicCodeBlock::Cast(*bb_iter);
        if (bb == NULL)
          continue;

        // BasicBlock is in the protected area, adding to the vector
          to_protect.push_back(*bb_iter);
      }

    return true;
  }

  std::string ProtectedBBlockFilter::ToString()
  {
    std::stringstream ss;

    ss << "Filter" << std::endl;
    ss << "size: " << filter.size() << std::endl << std::endl;

    for (size_t i = 0; i < filter.size(); ++i) {
      ss << "Entry " << i << std::endl;
      ss << "   Addr: " << filter[i].first << std::endl;
      ss << "   Size: " << filter[i].second << std::endl;
    }

    ss << std::endl;
    std::string ret = ss.str();

    return ret;
  }

} // namespace protect
