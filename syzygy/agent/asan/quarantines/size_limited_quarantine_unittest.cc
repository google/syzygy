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

  bool PopImpl(DummyObject* o) {
    DCHECK_NE(static_cast<DummyObject*>(NULL), o);
    DCHECK(!objects_.empty());
    *o = objects_.back();
    objects_.pop_back();
    return true;
  }

  void EmptyImpl(DummyObjectVector* os) {
    DCHECK_NE(static_cast<DummyObjectVector*>(NULL), os);
    os->swap(objects_);
  }

  size_t GetLockIdImpl(const DummyObject& o) { return 0; }
  void LockImpl(size_t lock_id) {}
  void UnlockImpl(size_t lock_id) {}
  // @}

  DummyObjectVector objects_;
};

}  // namespace

TEST(SizeLimitedQuarantineTest, ConstructorsSettersAndGetters) {
  TestQuarantine q;
  EXPECT_EQ(TestQuarantine::kUnboundedSize, q.max_object_size());
  EXPECT_EQ(TestQuarantine::kUnboundedSize, q.max_quarantine_size());
  EXPECT_EQ(0u, q.GetSizeForTesting());
  EXPECT_EQ(0u, q.GetCountForTesting());

  q.set_max_object_size(100);
  EXPECT_EQ(100u, q.max_object_size());

  q.set_max_quarantine_size(1000);
  EXPECT_EQ(1000u, q.max_quarantine_size());
}

TEST(SizeLimitedQuarantineTest, NoSizeLimit) {
  TestQuarantine q;
  for (size_t i = 0; i < 1000; ++i) {
    q.Push(DummyObject(i * 1000));
    EXPECT_EQ(i + 1, q.GetCountForTesting());
  }
}

TEST(SizeLimitedQuarantineTest, MaxObjectSizeEnforced) {
  TestQuarantine q;
  q.set_max_object_size(10);
  for (size_t i = 1; i < 20; ++i) {
    if (i <= 10) {
      EXPECT_TRUE(q.Push(DummyObject(i)).push_successful);
      EXPECT_EQ(i, q.GetCountForTesting());
    } else {
      EXPECT_FALSE(q.Push(DummyObject(i)).push_successful);
      EXPECT_EQ(10u, q.GetCountForTesting());
    }
  }
}

TEST(SizeLimitedQuarantineTest, InvariantEnforced) {
  TestQuarantine q;
  DummyObject o(10);

  q.set_max_quarantine_size(15);

  EXPECT_TRUE(q.Push(o).push_successful);
  EXPECT_EQ(10u, q.GetSizeForTesting());
  EXPECT_EQ(1u, q.GetCountForTesting());

  EXPECT_FALSE(q.Pop(&o).pop_successful);
  EXPECT_EQ(10u, q.GetSizeForTesting());
  EXPECT_EQ(1u, q.GetCountForTesting());

  EXPECT_TRUE(q.Push(o).push_successful);
  EXPECT_EQ(20u, q.GetSizeForTesting());
  EXPECT_EQ(2u, q.GetCountForTesting());

  EXPECT_TRUE(q.Pop(&o).pop_successful);
  EXPECT_EQ(10u, q.GetSizeForTesting());
  EXPECT_EQ(1u, q.GetCountForTesting());

  EXPECT_FALSE(q.Pop(&o).pop_successful);
  EXPECT_EQ(10u, q.GetSizeForTesting());
  EXPECT_EQ(1u, q.GetCountForTesting());
}

TEST(SizeLimitedQuarantineTest, EmptyWorks) {
  TestQuarantine q;
  DummyObject o(10);

  EXPECT_TRUE(q.Push(o).push_successful);
  EXPECT_TRUE(q.Push(o).push_successful);
  EXPECT_TRUE(q.Push(o).push_successful);
  EXPECT_EQ(30u, q.GetSizeForTesting());
  EXPECT_EQ(3u, q.GetCountForTesting());

  DummyObjectVector os;
  q.Empty(&os);

  EXPECT_THAT(os, testing::ElementsAre(o, o, o));
}

TEST(SizeLimitedQuarantineTest, GetQuarantineColor) {
  const size_t kMaxSize = 1000;
  const size_t kOverbudgetSize = 10;

  TestQuarantine q;
  q.set_max_quarantine_size(kMaxSize);
  q.SetOverbudgetSize(kOverbudgetSize);

  // Test all values to make sure they fit in the right color.
  int i = 0;
  for (; i <= q.GetMaxSizeForColorForTesting(TrimColor::GREEN); i++)
    EXPECT_EQ(TrimColor::GREEN, q.GetQuarantineColor(i));

  for (; i <= q.GetMaxSizeForColorForTesting(TrimColor::YELLOW); i++)
    EXPECT_EQ(TrimColor::YELLOW, q.GetQuarantineColor(i));

  for (; i <= q.GetMaxSizeForColorForTesting(TrimColor::RED); i++)
    EXPECT_EQ(TrimColor::RED, q.GetQuarantineColor(i));

  // Testing all the Black values would take too long, so only test the first
  // few.
  for (; i < q.GetMaxSizeForColorForTesting(TrimColor::RED) * 2; i++)
    EXPECT_EQ(TrimColor::BLACK, q.GetQuarantineColor(i));
}

TEST(SizeLimitedQuarantineTest, GetMaxSizeForColorForTesting) {
  const size_t kMaxQuarantineSize = 1000;
  const size_t kOverbudgetSize = 2048;

  TestQuarantine q;
  q.set_max_quarantine_size(kMaxQuarantineSize);

  // There should only be two limits by default.
  EXPECT_EQ(q.GetMaxSizeForColorForTesting(TrimColor::GREEN),
            q.GetMaxSizeForColorForTesting(TrimColor::YELLOW));
  EXPECT_EQ(q.GetMaxSizeForColorForTesting(TrimColor::YELLOW),
            q.GetMaxSizeForColorForTesting(TrimColor::RED));
  EXPECT_LT(q.GetMaxSizeForColorForTesting(TrimColor::RED),
            q.GetMaxSizeForColorForTesting(TrimColor::BLACK));

  q.SetOverbudgetSize(kOverbudgetSize);
  // Yellow is set at the max size.
  EXPECT_EQ(kMaxQuarantineSize,
            q.GetMaxSizeForColorForTesting(TrimColor::YELLOW));
  // There should be 4 limits now that an overbudget size is set.
  EXPECT_LT(q.GetMaxSizeForColorForTesting(TrimColor::GREEN),
            q.GetMaxSizeForColorForTesting(TrimColor::YELLOW));
  EXPECT_LT(q.GetMaxSizeForColorForTesting(TrimColor::YELLOW),
            q.GetMaxSizeForColorForTesting(TrimColor::RED));
  EXPECT_LT(q.GetMaxSizeForColorForTesting(TrimColor::RED),
            q.GetMaxSizeForColorForTesting(TrimColor::BLACK));
}

TEST(SizeLimitedQuarantineTest, SetOverbudgetSize) {
  const size_t kMaxQuarantineSize = 10 * 1024;
  const size_t kMinBudgetSize = 1024;
  TestQuarantine q;
  q.set_max_quarantine_size(kMaxQuarantineSize);
  EXPECT_EQ(0, q.GetOverbudgetSizeForTesting());

  // Min is 1k.
  q.SetOverbudgetSize(kMinBudgetSize - 1);
  EXPECT_EQ(kMinBudgetSize, q.GetOverbudgetSizeForTesting());
  q.SetOverbudgetSize(0);

  // Max is max_quarantine_size/2.
  q.SetOverbudgetSize(kMaxQuarantineSize);
  EXPECT_EQ(kMaxQuarantineSize / 2, q.GetOverbudgetSizeForTesting());
  q.SetOverbudgetSize(0);

  q.SetOverbudgetSize(kMinBudgetSize * 2);
  EXPECT_EQ(kMinBudgetSize * 2, q.GetOverbudgetSizeForTesting());

  q.SetOverbudgetSize(0);
  EXPECT_EQ(0, q.GetOverbudgetSizeForTesting());
}

}  // namespace quarantines
}  // namespace asan
}  // namespace agent
