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

#include "syzygy/instrument/transforms/asan_interceptor_filter.h"

#include "syzygy/block_graph/block_graph.h"
#include "syzygy/block_graph/block_hash.h"

namespace instrument {
namespace transforms {

using block_graph::BlockGraph;
using block_graph::BlockHash;

void AsanInterceptorFilter::InitializeContentHashes(
    const AsanIntercept* intercepts,
    bool parse_optional_intercepts) {
  DCHECK_NE(reinterpret_cast<AsanIntercept*>(NULL), intercepts);

  // Process and intercepted functions with specified filter hashes, and add
  // them to the filter.
  const AsanIntercept* intercept = intercepts;
  for (; intercept->undecorated_name != NULL; ++intercept) {
    // Skip functions that don't contain hashes.
    if (intercept->valid_content_hashes == NULL)
      continue;

    // Skip optional intercepts if not explicitly processing them.
    if (!parse_optional_intercepts && intercept->optional)
      continue;

    const MD5Hash* hash = intercept->valid_content_hashes;
    for (; hash->hash[0] != 0; ++hash)
      function_hash_map_[intercept->undecorated_name].insert(hash->hash);
  }
}

bool AsanInterceptorFilter::ShouldIntercept(const BlockGraph::Block* block) {
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), block);

  if (block->type() != BlockGraph::CODE_BLOCK)
    return false;

  FunctionHashMap::iterator func_iter = function_hash_map_.find(block->name());

  if (func_iter == function_hash_map_.end())
    return false;

  block_graph::BlockHash block_hash(block);
  std::string hash_val = base::MD5DigestToBase16(block_hash.md5_digest);

  HashSet::iterator hash_iter = func_iter->second.find(hash_val);

  if (hash_iter == func_iter->second.end())
    return false;

  return true;
}

void AsanInterceptorFilter::AddBlockToHashMap(BlockGraph::Block* block) {
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), block);
  BlockHash block_hash(block);
  function_hash_map_[block->name()].insert(
      base::MD5DigestToBase16(block_hash.md5_digest));
}

}  // namespace transforms
}  // namespace instrument
