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
// Declaration of the BlockBuilder class.

#ifndef SYZYGY_BLOCK_GRAPH_BLOCK_BUILDER_H_
#define SYZYGY_BLOCK_GRAPH_BLOCK_BUILDER_H_

#include "syzygy/block_graph/basic_block_subgraph.h"
#include "syzygy/block_graph/block_graph.h"
#include "syzygy/block_graph/tags.h"

namespace block_graph {

// This class incorporates a BasicBlockSubGraph into a BlockGraph.
class BlockBuilder {
 public:
  explicit BlockBuilder(BlockGraph* block_graph);

  // Merge the @p subgraph into the block graph. This will create all blocks
  // and block relationships described by the subgraph and remove the
  // original block (if any) from which the subgraph was derived.
  // @param subgraph The subgraph to be merged.
  // @returns true on success, false otherwise.
  bool Merge(BasicBlockSubGraph* subgraph);

  // @returns the set of new blocks created upon merging in one or more
  //     subgraphs.
  const BlockVector& new_blocks() const { return new_blocks_; }

  // @returns the tag info map. This is populated by a successful call to Merge.
  const TagInfoMap& tag_info_map() const { return tag_info_map_; }

 private:
  // The block-graph that subgraphs will be merged into.
  BlockGraph* const block_graph_;

  // The set of blocks created so far.
  BlockVector new_blocks_;

  // The tag info map tracking all user data in the subgraph.
  TagInfoMap tag_info_map_;

  DISALLOW_COPY_AND_ASSIGN(BlockBuilder);
};

}  // namespace block_graph

#endif  // SYZYGY_BLOCK_GRAPH_BLOCK_BUILDER_H_
