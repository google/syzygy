// Copyright 2014 Google Inc. All Rights Reserved.
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
// Utility functions for working with Asan Blocks.

#ifndef SYZYGY_AGENT_ASAN_BLOCK_UTILS_H_
#define SYZYGY_AGENT_ASAN_BLOCK_UTILS_H_

#include "base/logging.h"
#include "syzygy/agent/asan/block.h"
#include "syzygy/agent/asan/shadow.h"

namespace agent {
namespace asan {

// A functor that retrieves the total size of an Asan allocation.
struct GetTotalBlockSizeFunctor {
  size_t operator()(const CompactBlockInfo& info) {
    DCHECK_NE(static_cast<BlockHeader*>(nullptr), info.header);
    return info.block_size;
  }
};

// A functor for calculating a hash value associated with a block. This is used
// by the sharded quarantine.
struct GetBlockHashFunctor {
  size_t operator()(const CompactBlockInfo& info) {
    DCHECK_NE(static_cast<BlockHeader*>(nullptr), info.header);
    const BlockTrailer* trailer =
        reinterpret_cast<const BlockTrailer*>(
            reinterpret_cast<const uint8_t*>(info.header) + info.block_size) -
        1;
    return trailer->alloc_ticks + reinterpret_cast<size_t>(info.header);
  }
};

// Checks if a block is corrupt. This checks the block's metadata and its
// checksum.
// @param block_info The information about this block.
// @returns true if the block is corrupt, false otherwise.
// @note The pages containing the entire block must be readable.
bool IsBlockCorrupt(const BlockInfo& block_info);

}  // namespace asan
}  // namespace agent

#endif  // SYZYGY_AGENT_ASAN_BLOCK_UTILS_H_
