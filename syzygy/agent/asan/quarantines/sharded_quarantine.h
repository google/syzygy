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
// Implements a simple sharded quarantine.

#ifndef SYZYGY_AGENT_ASAN_QUARANTINES_SHARDED_QUARANTINE_H_
#define SYZYGY_AGENT_ASAN_QUARANTINES_SHARDED_QUARANTINE_H_

#include "base/synchronization/lock.h"
#include "syzygy/agent/asan/page_allocator.h"
#include "syzygy/agent/asan/quarantines/size_limited_quarantine.h"

namespace agent {
namespace asan {
namespace quarantines {

// A simple sharded quarantine. This distributes objects among a configurable
// number of shards using a lightweight threadsafe hashing mechanism. Each
// shard has its own lock, greatly reducing lock contention for the quarantine.
//
// @tparam ObjectType The type of object being stored in the cache.
// @tparam SizeFunctorType A functor for extracting the size associated with
//     and object.
// @tparam HashFunctorType A functor for calculating a hash value associated
//     with an object. This does need to be deterministic. A single instance
//     of this will be maintained per instance, so it can use internal state;
//     however, it must be thread-safe. This should implement the method:
//     size_t operator()(const ObjectType& o) const;
// @tparam ShardingFactor The sharding factor. Must be greater than 1.
template<typename ObjectType,
         typename SizeFunctorType,
         typename HashFunctorType,
         size_t ShardingFactor>
class ShardedQuarantine
    : public SizeLimitedQuarantineImpl<ObjectType, SizeFunctorType> {
 public:
  typedef HashFunctorType HashFunctor;

  static const size_t kShardingFactor = ShardingFactor;

  // Constructor. The hash functor must have a default constructor.
  ShardedQuarantine();

  // Constructor with explicit hash functor. The hash functor must have
  // a copy constructor.
  explicit ShardedQuarantine(const HashFunctor& hash_functor);

  // Virtual destructor.
  virtual ~ShardedQuarantine() { }

 protected:
  // @name SizeLimitedQuarantineImpl implementation.
  // @{
  virtual bool PushImpl(const Object& object);
  virtual void PopImpl(Object* object);
  virtual void EmptyImpl(ObjectVector* objects);
  // @}

  // The internal type used for storing objects. This augments them with a
  // 'next' pointer for chaining them together in the cache. These live in
  // a simple page-allocator.
  struct Node {
    Object object;
    Node* next;
  };

  // A simple page allocator that can only allocate individual nodes, and
  // does no bookkeeping. This has its own synchronization primitives.
  // Typical quarantine sizes are 16MB, which is about 120K allocations
  // given Chrome's typical allocation size. This in turn translates to
  // about 1MB of Node data. Typical 16 way sharding means about 65KB.
  // All of this to justify a 32KB page size to balance fragmentation and
  // number of pages.
  typedef TypedPageAllocator<Node, 1, 32 * 1024, false> NodeCache;

  // Linked lists containing quarantined objects. Each shard is under the
  // corresponding locks_ entry. Objects are inserted at the tail, and
  // removed from the head.
  Node* heads_[kShardingFactor];
  Node* tails_[kShardingFactor];

  // Storage for nodes, one per shard. Each is under its own internal lock.
  NodeCache node_caches_[kShardingFactor];

  // Locks, one per linked list.
  base::Lock locks_[kShardingFactor];

  // The hash functor that will be used to assign objects to shards.
  HashFunctor hash_functor_;

 private:
  DISALLOW_COPY_AND_ASSIGN(ShardedQuarantine);
};

}  // namespace quarantines
}  // namespace asan
}  // namespace agent

#include "syzygy/agent/asan/quarantines/sharded_quarantine_impl.h"

#endif  // SYZYGY_AGENT_ASAN_QUARANTINES_SHARDED_QUARANTINE_H_
