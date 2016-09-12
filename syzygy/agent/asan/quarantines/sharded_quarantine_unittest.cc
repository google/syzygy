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

#include "syzygy/agent/asan/quarantines/sharded_quarantine.h"

#include <set>

#include "gtest/gtest.h"

namespace agent {
namespace asan {
namespace quarantines {

namespace {

struct DummyObject {
  size_t size;
  size_t hash;

  DummyObject() : size(0), hash(0) { }
  explicit DummyObject(size_t size) : size(size), hash(0) { }
  DummyObject(const DummyObject& o)
      : size(o.size),
        hash(o.hash) {
  }
  DummyObject& operator=(const DummyObject& o) {
    size = o.size;
    hash = o.hash;
    return *this;
  }
};

struct DummyObjectSizeFunctor {
  size_t operator()(const DummyObject& o) {
    return o.size;
  }
};

struct DummyObjectHashFunctor {
  size_t operator()(const DummyObject& o) { return o.hash; }
};

typedef std::vector<DummyObject> DummyObjectVector;

class TestShardedQuarantine
    : public ShardedQuarantine<DummyObject,
                               DummyObjectSizeFunctor,
                               DummyObjectHashFunctor,
                               8> {
 public:
  typedef ShardedQuarantine<DummyObject,
                            DummyObjectSizeFunctor,
                            DummyObjectHashFunctor,
                            8> Super;

  size_t ShardCount(size_t shard) {
    Super::Node* node = heads_[shard];
    size_t count = 0;
    while (node) {
      ++count;
      node = node->next;
    }
    return count;
  }

  void LockImpl(size_t lock_id) override {
    Super::LockImpl(lock_id);
    lock_set_.insert(lock_id);
  }
  void UnlockImpl(size_t lock_id) override {
    lock_set_.erase(lock_id);
    Super::UnlockImpl(lock_id);
  }

  std::set<size_t> lock_set_;
};

}  // namespace

TEST(ShardedQuarantineTest, EvenLoading) {
  TestShardedQuarantine q;
  DummyObject d(1);
  DummyObject popped;

  // No max object size. This logic is tested in SizeLimitedQuarantineImpl.
  q.set_max_object_size(TestShardedQuarantine::kUnboundedSize);
  q.set_max_quarantine_size(10000);

  EXPECT_EQ(0u, q.GetSizeForTesting());

  // Stuff a bunch of things into the quarantine, but don't saturate it.
  for (size_t i = 0; i < 9000; ++i) {
    {
      TestShardedQuarantine::AutoQuarantineLock lock(&q, d);
      EXPECT_TRUE(q.Push(d).push_successful);
    }
    d.hash++;
    EXPECT_EQ(i + 1, q.GetSizeForTesting());

    EXPECT_FALSE(q.Pop(&popped).pop_successful);
    EXPECT_EQ(i + 1, q.GetSizeForTesting());
  }

  // Saturate the quarantine, invalidating the invariant.
  while (q.GetSizeForTesting() <= q.max_quarantine_size()) {
    {
      TestShardedQuarantine::AutoQuarantineLock lock(&q, d);
      EXPECT_TRUE(q.Push(d).push_successful);
    }
    d.hash++;
  }

  // Now expect one element to be popped off before the invariant is satisfied.
  EXPECT_TRUE(q.Pop(&popped).pop_successful);
  EXPECT_EQ(d.size, popped.size);
  EXPECT_EQ(q.max_quarantine_size(), q.GetSizeForTesting());

  // Expect there to be roughly even loading.
  double expected_count = q.max_quarantine_size() / q.kShardingFactor;
  for (size_t i = 0; i < q.kShardingFactor; ++i) {
    size_t count = q.ShardCount(i);
    EXPECT_LT(0.9 * expected_count, count);
    EXPECT_GT(1.1 * expected_count, count);
  }
}

TEST(ShardedQuarantineTest, StressTest) {
  TestShardedQuarantine q;

  // Doesn't allow the largest of objects we generate.
  q.set_max_object_size((1 << 10) - 1);

  // Is only 4 times as big as the largest element we generate.
  q.set_max_quarantine_size(4 * (1 << 10));

  for (size_t i = 0; i < 1000000; ++i) {
    // Generates a logarithmic distribution of element sizes.
    uint32_t logsize = (1 << rand() % 11);
    uint32_t size = (rand() & (logsize - 1)) | logsize;
    DummyObject d(size);

    size_t old_size = q.GetSizeForTesting();
    size_t old_count = q.GetCountForTesting();
    if (size > q.max_object_size()) {
      {
        TestShardedQuarantine::AutoQuarantineLock lock(&q, d);
        EXPECT_FALSE(q.Push(d).push_successful);
      }
      EXPECT_EQ(old_size, q.GetSizeForTesting());
      EXPECT_EQ(old_count, q.GetCountForTesting());
    } else {
      {
        TestShardedQuarantine::AutoQuarantineLock lock(&q, d);
        EXPECT_TRUE(q.Push(d).push_successful);
      }
      EXPECT_EQ(old_size + size, q.GetSizeForTesting());
      EXPECT_EQ(old_count + 1, q.GetCountForTesting());
    }

    DummyObject popped;
    while (q.GetSizeForTesting() > q.max_quarantine_size()) {
      old_size = q.GetSizeForTesting();
      old_count = q.GetCountForTesting();
      EXPECT_TRUE(q.Pop(&popped).pop_successful);
      EXPECT_EQ(old_size - popped.size, q.GetSizeForTesting());
      EXPECT_EQ(old_count - 1, q.GetCountForTesting());
    }
    EXPECT_FALSE(q.Pop(&popped).pop_successful);
  }

  size_t old_size = q.GetSizeForTesting();
  size_t old_count = q.GetCountForTesting();
  TestShardedQuarantine::ObjectVector os;
  q.Empty(&os);
  EXPECT_EQ(0u, q.GetSizeForTesting());
  EXPECT_EQ(0u, q.GetCountForTesting());
  EXPECT_EQ(old_count, os.size());
  size_t emptied_size = 0;
  for (size_t i = 0; i < os.size(); ++i)
    emptied_size += os[i].size;
  EXPECT_EQ(old_size, emptied_size);
}

TEST(ShardedQuarantineTest, LockUnlock) {
  TestShardedQuarantine q;
  DummyObject dummy;
  size_t lock_id = q.GetLockId(dummy);
  {
    TestShardedQuarantine::AutoQuarantineLock lock(&q, dummy);

    EXPECT_TRUE(q.lock_set_.find(lock_id) != q.lock_set_.end());
  }

  EXPECT_TRUE(q.lock_set_.empty());
}

}  // namespace quarantines
}  // namespace asan
}  // namespace agent
