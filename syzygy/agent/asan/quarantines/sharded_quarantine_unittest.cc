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

#include "gtest/gtest.h"

namespace agent {
namespace asan {
namespace quarantines {

namespace {

struct DummyObject {
  size_t size;

  DummyObject() : size(0) { }
  explicit DummyObject(size_t size) : size(size) { }
  DummyObject(const DummyObject& o) : size(o.size) { }  // NOLINT
};

struct DummyObjectSizeFunctor {
  size_t operator()(const DummyObject& o) {
    return o.size;
  }
};

struct DummyObjectHashFunctor {
  DummyObjectHashFunctor() : hash(0) { }
  size_t hash;
  uint32 operator()(const DummyObject& o) {
    return hash++;
  }
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
};

}  // namespace

TEST(ShardedQuarantineTest, EvenLoading) {
  TestShardedQuarantine q;
  DummyObject d(1);
  DummyObject popped;

  // No max object size. This logic is tested in SizeLimitedQuarantineImpl.
  q.set_max_object_size(0);
  q.set_max_quarantine_size(10000);

  EXPECT_EQ(0u, q.size());

  // Stuff a bunch of things into the quarantine, but don't saturate it.
  for (size_t i = 0; i < 9000; ++i) {
    EXPECT_TRUE(q.Push(d));
    EXPECT_EQ(i + 1, q.size());

    EXPECT_FALSE(q.Pop(&popped));
    EXPECT_EQ(i + 1, q.size());
  }

  // Saturate the quarantine, invalidating the invariant.
  while (q.size() <= q.max_quarantine_size())
    EXPECT_TRUE(q.Push(d));

  // Now expect one element to be popped off before the invariant is satisfied.
  EXPECT_TRUE(q.Pop(&popped));
  EXPECT_EQ(d.size, popped.size);
  EXPECT_EQ(q.max_quarantine_size(), q.size());

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
    size_t logsize = (1 << rand() % 11);
    size_t size = (rand() & (logsize - 1)) | logsize;
    DummyObject d(size);

    size_t old_size = q.size();
    size_t old_count = q.GetCount();
    if (size > q.max_object_size()) {
      EXPECT_FALSE(q.Push(d));
      EXPECT_EQ(old_size, q.size());
      EXPECT_EQ(old_count, q.GetCount());
    } else {
      EXPECT_TRUE(q.Push(d));
      EXPECT_EQ(old_size + size, q.size());
      EXPECT_EQ(old_count + 1, q.GetCount());
    }

    DummyObject popped;
    while (q.size() > q.max_quarantine_size()) {
      old_size = q.size();
      old_count = q.GetCount();
      EXPECT_TRUE(q.Pop(&popped));
      EXPECT_EQ(old_size - popped.size, q.size());
      EXPECT_EQ(old_count - 1, q.GetCount());
    }
    EXPECT_FALSE(q.Pop(&popped));
  }

  size_t old_size = q.size();
  size_t old_count = q.GetCount();
  TestShardedQuarantine::ObjectVector os;
  q.Empty(&os);
  EXPECT_EQ(0u, q.size());
  EXPECT_EQ(0u, q.GetCount());
  EXPECT_EQ(old_count, os.size());
  size_t emptied_size = 0;
  for (size_t i = 0; i < os.size(); ++i)
    emptied_size += os[i].size;
  EXPECT_EQ(old_size, emptied_size);
}

}  // namespace quarantines
}  // namespace asan
}  // namespace agent
