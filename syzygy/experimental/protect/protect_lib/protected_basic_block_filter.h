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

#ifndef SYZYGY_PROTECT_PROTECT_LIB_PROTECTED_BASIC_BLOCK_FILTER_H_
#define SYZYGY_PROTECT_PROTECT_LIB_PROTECTED_BASIC_BLOCK_FILTER_H_

#include <vector>
#include "syzygy/block_graph/basic_block_subgraph.h"
#include "syzygy/block_graph/block_builder.h"
#include "syzygy/block_graph/block_graph.h"


namespace protect {

class ProtectedBBlockFilter {
 public:
    // Constructor

    ProtectedBBlockFilter() {}

    ProtectedBBlockFilter(
      std::vector<std::pair<block_graph::BlockGraph::RelativeAddress,
      block_graph::BlockGraph::Size> >& filter)
      : filter(filter) {}

    // Adds another address <-> size pair tot the filter
    //
    // @param tuple Address/size pair to be inserted
    void Add(std::pair<block_graph::BlockGraph::RelativeAddress,
      block_graph::BlockGraph::Size> &tuple);

    // This is the main function for filtering basic blocks in a subgraph
    // It checks if the blocks in the subgraph overalp with any of the defined
    // filter ranges
    //
    // @param to_protect Vector through which all the found blocks are returned.
    // @param subgraph Subgraph that contains all the basic blocks.
    // @return true if filtering was successfull, false otherwise
    bool Filter(std::vector<block_graph::BasicBlock *>& to_protect,
      block_graph::BasicBlockSubGraph *subgraph);

    // Helper function for the current filter
    // @return String representation of the filter
    std::string ToString();

 private:
    // Vector of <Address, Size> pairs used for storing address ranges for filtering.
    std::vector < std::pair<block_graph::BlockGraph::RelativeAddress,
      block_graph::BlockGraph::Size> > filter;
};
} // namespace protect
#endif  // SYZYGY_PROTECT_PROTECT_LIB_PROTECTED_BASIC_BLOCK_FILTER_H_
