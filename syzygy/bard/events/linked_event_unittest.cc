// Copyright 2015 Google Inc. All Rights Reserved.
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

#include "syzygy/bard/events/linked_event.h"

#include "base/synchronization/lock.h"
#include "base/threading/simple_thread.h"
#include "gtest/gtest.h"

namespace bard {
namespace events {

namespace {

class TestEvent : public EventInterface {
 public:
  TestEvent() : played_(false) {}

  EventType type() const override { return static_cast<EventType>(0); }

  bool Play(void* backdrop) override {
    base::AutoLock auto_lock(lock_);
    played_ = true;
    return true;
  }

  bool Equals(const EventInterface* rhs) const override {
    NOTREACHED();
    return false;
  }

  bool played() const {
    base::AutoLock auto_lock(const_cast<base::Lock&>(lock_));
    return played_;
  }

 protected:
  base::Lock lock_;
  bool played_;
};

class TestRunner : public base::DelegateSimpleThread::Delegate {
 public:
  TestRunner(LinkedEvent* event, void* backdrop)
      : test_event_(event), test_backdrop_(backdrop) {}

  void Run() override { test_event_->Play(test_backdrop_); }

 protected:
  LinkedEvent* test_event_;
  void* test_backdrop_;
};

class LinkedEventTest : public testing::Test {
 public:
  // The backdrop isn't used, but can't be null. Simply generate a dummy
  // address.
  LinkedEventTest()
      : empty_backdrop_(reinterpret_cast<void*>(0xBAADF00D)),
        linked_event1_(std::unique_ptr<EventInterface>(new TestEvent())),
        linked_event2_(std::unique_ptr<EventInterface>(new TestEvent())),
        linked_event3_(std::unique_ptr<EventInterface>(new TestEvent())),
        runner1_(&linked_event1_, empty_backdrop_),
        runner2_(&linked_event2_, empty_backdrop_),
        runner3_(&linked_event3_, empty_backdrop_) {}

 protected:
  void* empty_backdrop_;

  LinkedEvent linked_event1_;
  LinkedEvent linked_event2_;
  LinkedEvent linked_event3_;

  TestRunner runner1_;
  TestRunner runner2_;
  TestRunner runner3_;
};

}  // namespace

TEST_F(LinkedEventTest, TestOneLink) {
  base::DelegateSimpleThread thread1(&runner1_, "First Thread");
  base::DelegateSimpleThread thread2(&runner2_, "Second Thread");

  linked_event2_.AddDep(&linked_event1_);

  thread2.Start();

  EXPECT_FALSE(
      reinterpret_cast<const TestEvent*>(linked_event1_.event())->played());
  EXPECT_FALSE(
      reinterpret_cast<const TestEvent*>(linked_event2_.event())->played());

  thread1.Start();
  thread1.Join();

  thread2.Join();

  EXPECT_TRUE(
      reinterpret_cast<const TestEvent*>(linked_event1_.event())->played());
  EXPECT_TRUE(
      reinterpret_cast<const TestEvent*>(linked_event2_.event())->played());
}

TEST_F(LinkedEventTest, TestChainLink) {
  base::DelegateSimpleThread thread1(&runner1_, "First Thread");
  base::DelegateSimpleThread thread2(&runner2_, "Second Thread");
  base::DelegateSimpleThread thread3(&runner3_, "Third Thread");

  linked_event2_.AddDep(&linked_event1_);
  linked_event3_.AddDep(&linked_event2_);

  thread3.Start();

  EXPECT_FALSE(
      reinterpret_cast<const TestEvent*>(linked_event1_.event())->played());
  EXPECT_FALSE(
      reinterpret_cast<const TestEvent*>(linked_event2_.event())->played());
  EXPECT_FALSE(
      reinterpret_cast<const TestEvent*>(linked_event3_.event())->played());

  thread2.Start();

  EXPECT_FALSE(
      reinterpret_cast<const TestEvent*>(linked_event1_.event())->played());
  EXPECT_FALSE(
      reinterpret_cast<const TestEvent*>(linked_event2_.event())->played());
  EXPECT_FALSE(
      reinterpret_cast<const TestEvent*>(linked_event3_.event())->played());

  thread1.Start();
  thread1.Join();
  thread2.Join();
  thread3.Join();

  EXPECT_TRUE(
      reinterpret_cast<const TestEvent*>(linked_event1_.event())->played());
  EXPECT_TRUE(
      reinterpret_cast<const TestEvent*>(linked_event2_.event())->played());
  EXPECT_TRUE(
      reinterpret_cast<const TestEvent*>(linked_event3_.event())->played());
}

TEST_F(LinkedEventTest, TestMultipleDependency) {
  base::DelegateSimpleThread thread1(&runner1_, "First Thread");
  base::DelegateSimpleThread thread2(&runner2_, "Second Thread");
  base::DelegateSimpleThread thread3(&runner3_, "Third Thread");

  linked_event3_.AddDep(&linked_event1_);
  linked_event3_.AddDep(&linked_event2_);

  thread3.Start();

  EXPECT_FALSE(
      reinterpret_cast<const TestEvent*>(linked_event1_.event())->played());
  EXPECT_FALSE(
      reinterpret_cast<const TestEvent*>(linked_event2_.event())->played());
  EXPECT_FALSE(
      reinterpret_cast<const TestEvent*>(linked_event3_.event())->played());

  thread2.Start();

  EXPECT_FALSE(
      reinterpret_cast<const TestEvent*>(linked_event1_.event())->played());
  EXPECT_TRUE(
      reinterpret_cast<const TestEvent*>(linked_event2_.event())->played());
  EXPECT_FALSE(
      reinterpret_cast<const TestEvent*>(linked_event3_.event())->played());

  thread1.Start();
  thread1.Join();
  thread2.Join();
  thread3.Join();

  EXPECT_TRUE(
      reinterpret_cast<const TestEvent*>(linked_event1_.event())->played());
  EXPECT_TRUE(
      reinterpret_cast<const TestEvent*>(linked_event2_.event())->played());
  EXPECT_TRUE(
      reinterpret_cast<const TestEvent*>(linked_event3_.event())->played());
}

}  // namespace events
}  // namespace bard
