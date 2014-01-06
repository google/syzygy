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

#ifndef SYZYGY_BLOCK_GRAPH_BLOCK_HASH_H_
#define SYZYGY_BLOCK_GRAPH_BLOCK_HASH_H_

#include "base/md5.h"
#include "syzygy/block_graph/block_graph.h"
#include "syzygy/common/comparable.h"

namespace block_graph {

using block_graph::BlockGraph;

// Represents a hash of the content of a block. Internally we store an 128-bit
// MD5 digest, but this endows it with comparison operators. We explicitly
// provide copy and assignment operators to make this STL container compatible.
struct BlockHash : public common::Comparable<BlockHash> {
 public:
  BlockHash() {
  }

  // Constructor from Block.
  explicit BlockHash(const BlockGraph::Block* block) {
    Hash(block);
  }

  // General comparison function, required by Comparable.
  int Compare(const BlockHash& other) const {
    return memcmp(&md5_digest, &other.md5_digest, sizeof(md5_digest));
  }

  // Populates this block hash from the given block. The hash is calculated
  // on the block content and its references, as follows:
  //     Block properties: type, size, data_size, reference count
  //     References (increasing source offset): source offset, type, size
  //     Data (skipping references)
  void Hash(const BlockGraph::Block* block);

  base::MD5Digest md5_digest;
};

}  // namespace block_graph

#endif  // SYZYGY_BLOCK_GRAPH_BLOCK_HASH_H_
