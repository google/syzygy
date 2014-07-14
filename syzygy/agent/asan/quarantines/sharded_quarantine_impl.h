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
// Internal implementation of a sharded quarantine. This file is not
// meant to be included directly.

#ifndef SYZYGY_AGENT_ASAN_QUARANTINES_SHARDED_QUARANTINE_IMPL_H_
#define SYZYGY_AGENT_ASAN_QUARANTINES_SHARDED_QUARANTINE_IMPL_H_

#include "string.h"

namespace agent {
namespace asan {
namespace quarantines {

namespace detail {

// Given a 32-bit integer, converts it to an integer in the range
// [0, kShardingFactor). Since the input range is unknown and may not use
// the entirety of the 32-bits, this first uses a bit mixing function.
template<size_t kShardingFactor>
size_t ShardedQuarantineHash(size_t a) {
  // Simple full-avalanche (any input bit can affect every output bit)
  // bit mixing. See: http://burtleburtle.net/bob/hash/integer.html
  a -= (a << 6);
  a ^= (a >> 17);
  a -= (a << 9);
  a ^= (a << 4);
  a -= (a << 3);
  a ^= (a << 10);
  a ^= (a >> 15);
  return a % kShardingFactor;
}

}  // namespace detail

template<typename OT, typename SFT, typename HFT, size_t SF>
ShardedQuarantine<OT, SFT, HFT, SF>::ShardedQuarantine() {
  COMPILE_ASSERT(kShardingFactor >= 1, invalid_sharding_factor);
  ::memset(heads_, 0, sizeof(heads_));
  ::memset(tails_, 0, sizeof(tails_));
}

template<typename OT, typename SFT, typename HFT, size_t SF>
ShardedQuarantine<OT, SFT, HFT, SF>::ShardedQuarantine(
    const HashFunctor& hash_functor)
    : hash_functor_(hash_functor) {
  COMPILE_ASSERT(kShardingFactor > 1, invalid_sharding_factor);
  ::memset(heads_, 0, sizeof(heads_));
  ::memset(tails_, 0, sizeof(tails_));
}

template<typename OT, typename SFT, typename HFT, size_t SF>
bool ShardedQuarantine<OT, SFT, HFT, SF>::PushImpl(const Object& object) {
  size_t hash = hash_functor_(object);
  size_t shard = detail::ShardedQuarantineHash<kShardingFactor>(hash);

  Node* node = node_caches_[shard].Allocate(1);
  if (node == NULL)
    return false;
  node->object = object;
  node->next = NULL;

  {
    base::AutoLock lock(locks_[shard]);

    // Append the node to the tail of this shard.
    if (tails_[shard] != NULL) {
      DCHECK_NE(static_cast<Node*>(NULL), heads_[shard]);
      tails_[shard]->next = node;
      tails_[shard] = node;
    } else {
      DCHECK_EQ(static_cast<Node*>(NULL), heads_[shard]);
      heads_[shard] = node;
      tails_[shard] = node;
    }
  }

  return true;
}

template<typename OT, typename SFT, typename HFT, size_t SF>
void ShardedQuarantine<OT, SFT, HFT, SF>::PopImpl(Object* object) {
  DCHECK_NE(static_cast<Object*>(NULL), object);

  // Extract a node from this shard. If the shard is empty then scan linearly
  // until finding a non-empty one.
  Node* node = NULL;
  size_t shard = rand() % kShardingFactor;
  size_t orig_shard = shard;
  while (true) {
    base::AutoLock lock(locks_[shard]);
    node = heads_[shard];
    if (node == NULL) {
      shard = (shard + 1) % kShardingFactor;

      // This should never happen as PopImpl should only be called if there is
      // actually an element in the quarantine.
      CHECK_NE(orig_shard, shard);
      continue;
    }

    // We've found an element to evict so we can stop looking.
    heads_[shard] = node->next;
    if (heads_[shard] == NULL)
      tails_[shard] = NULL;
    break;
  }
  DCHECK_NE(static_cast<Node*>(NULL), node);

  *object = node->object;
  node_caches_[shard].Free(node, 1);

  return;
}

template<typename OT, typename SFT, typename HFT, size_t SF>
void ShardedQuarantine<OT, SFT, HFT, SF>::EmptyImpl(ObjectVector* objects) {
  DCHECK_NE(static_cast<ObjectVector*>(NULL), objects);

  // Iterate over each shard and add the objects to the vector.
  for (size_t i = 0; i < kShardingFactor; ++i) {
    base::AutoLock lock(locks_[i]);

    Node* node = heads_[i];
    while (node) {
      objects->push_back(node->object);
      Node* next_node = node->next;
      node_caches_[i].Free(node, 1);
      node = next_node;
    }
    heads_[i] = NULL;
    tails_[i] = NULL;
  }

  return;
}

}  // namespace quarantines
}  // namespace asan
}  // namespace agent

#endif  // SYZYGY_AGENT_ASAN_QUARANTINES_SHARDED_QUARANTINE_IMPL_H_
