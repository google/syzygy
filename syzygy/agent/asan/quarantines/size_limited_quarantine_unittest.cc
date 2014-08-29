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

#include "syzygy/agent/asan/quarantines/size_limited_quarantine.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace agent {
namespace asan {
namespace quarantines {

// A dummy lightweight object for storing in a quarantine under test.
// This is outside of the anonymous namespace to keep gmock happy.
struct DummyObject {
  size_t size;

  DummyObject() : size(0) { }
  explicit DummyObject(size_t size) : size(size) { }
  DummyObject(const DummyObject& o) : size(o.size) { }  // NOLINT
};

std::ostream& operator<<(std::ostream& os, const DummyObject& o) {
  os << "DummyObject(size=" << o.size << ")";
  return os;
}

bool operator==(const DummyObject& o1, const DummyObject& o2) {
  return o1.size == o2.size;
}

namespace {

struct DummyObjectSizeFunctor {
  size_t operator()(const DummyObject& o) {
    return o.size;
  }
};

typedef std::vector<DummyObject> DummyObjectVector;

class TestQuarantine
    : public SizeLimitedQuarantineImpl<DummyObject, DummyObjectSizeFunctor> {
 public:
  TestQuarantine() { }
  virtual ~TestQuarantine() { }

 protected:
  // @name SizeLimitedQuarantine interface.
  // @{
  bool PushImpl(const DummyObject& o) {
    objects_.push_back(o);
    return true;
  }

  void PopImpl(DummyObject* o) {
    DCHECK_NE(static_cast<DummyObject*>(NULL), o);
    DCHECK(!objects_.empty());
    *o = objects_.back();
    objects_.pop_back();
  }

  void EmptyImpl(DummyObjectVector* os) {
    DCHECK_NE(static_cast<DummyObjectVector*>(NULL), os);
    os->swap(objects_);
  }
  // @}

  DummyObjectVector objects_;
};

}  // namespace

TEST(SizeLimitedQuarantineTest, ConstructorsSettersAndGetters) {
  TestQuarantine q;
  EXPECT_EQ(TestQuarantine::kUnboundedSize, q.max_object_size());
  EXPECT_EQ(TestQuarantine::kUnboundedSize, q.max_quarantine_size());
  EXPECT_EQ(0u, q.size());
  EXPECT_EQ(0u, q.GetCount());

  q.set_max_object_size(100);
  EXPECT_EQ(100u, q.max_object_size());

  q.set_max_quarantine_size(1000);
  EXPECT_EQ(1000u, q.max_quarantine_size());
}

TEST(SizeLimitedQuarantineTest, NoSizeLimit) {
  TestQuarantine q;
  for (size_t i = 0; i < 1000; ++i) {
    q.Push(DummyObject(i * 1000));
    EXPECT_EQ(i + 1, q.GetCount());
  }
}

TEST(SizeLimitedQuarantineTest, MaxObjectSizeEnforced) {
  TestQuarantine q;
  q.set_max_object_size(10);
  for (size_t i = 1; i < 20; ++i) {
    if (i <= 10) {
      EXPECT_TRUE(q.Push(DummyObject(i)));
      EXPECT_EQ(i, q.GetCount());
    } else {
      EXPECT_FALSE(q.Push(DummyObject(i)));
      EXPECT_EQ(10u, q.GetCount());
    }
  }
}

TEST(SizeLimitedQuarantineTest, InvariantEnforced) {
  TestQuarantine q;
  DummyObject o(10);

  q.set_max_quarantine_size(15);

  EXPECT_TRUE(q.Push(o));
  EXPECT_EQ(10u, q.size());
  EXPECT_EQ(1u, q.GetCount());

  EXPECT_FALSE(q.Pop(&o));
  EXPECT_EQ(10u, q.size());
  EXPECT_EQ(1u, q.GetCount());

  EXPECT_TRUE(q.Push(o));
  EXPECT_EQ(20u, q.size());
  EXPECT_EQ(2u, q.GetCount());

  EXPECT_TRUE(q.Pop(&o));
  EXPECT_EQ(10u, q.size());
  EXPECT_EQ(1u, q.GetCount());

  EXPECT_FALSE(q.Pop(&o));
  EXPECT_EQ(10u, q.size());
  EXPECT_EQ(1u, q.GetCount());
}

TEST(SizeLimitedQuarantineTest, EmptyWorks) {
  TestQuarantine q;
  DummyObject o(10);

  EXPECT_TRUE(q.Push(o));
  EXPECT_TRUE(q.Push(o));
  EXPECT_TRUE(q.Push(o));
  EXPECT_EQ(30u, q.size());
  EXPECT_EQ(3u, q.GetCount());

  DummyObjectVector os;
  q.Empty(&os);

  EXPECT_THAT(os, testing::ElementsAre(o, o, o));
}

}  // namespace quarantines
}  // namespace asan
}  // namespace agent
