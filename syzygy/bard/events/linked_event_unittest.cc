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

#include "base/memory/scoped_ptr.h"
#include "base/synchronization/lock.h"
#include "base/threading/simple_thread.h"
#include "gtest/gtest.h"

namespace bard {

namespace {

class TestLinkedEvent : public LinkedEvent {
 public:
  using LinkedEvent::prequels_;
  using LinkedEvent::sequels_;

  TestLinkedEvent() : played_(false) {}

  const char* name() const override { return "TestLinkedEvent"; }

  bool PlayImpl(void* backdrop) override {
    base::AutoLock auto_lock(lock_);
    played_ = true;
    return true;
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
  LinkedEventTest()
      : runner1_(&event1_, empty_backdrop_),
        runner2_(&event2_, empty_backdrop_),
        runner3_(&event3_, empty_backdrop_) {}

 protected:
  void* empty_backdrop_;

  TestLinkedEvent event1_;
  TestLinkedEvent event2_;
  TestLinkedEvent event3_;

  TestRunner runner1_;
  TestRunner runner2_;
  TestRunner runner3_;
};

}  // namespace

TEST_F(LinkedEventTest, TestOneLink) {
  CausalLink link;

  base::DelegateSimpleThread thread1(&runner1_, "First Thread");
  base::DelegateSimpleThread thread2(&runner2_, "Second Thread");

  event1_.sequels_.insert(&link);
  event2_.prequels_.insert(&link);

  thread2.Start();

  EXPECT_FALSE(event1_.played());
  EXPECT_FALSE(event2_.played());

  thread1.Start();
  thread1.Join();
  thread2.Join();

  EXPECT_TRUE(event1_.played());
  EXPECT_TRUE(event2_.played());
}

TEST_F(LinkedEventTest, TestChainLink) {
  CausalLink link1_2;
  CausalLink link2_3;

  base::DelegateSimpleThread thread1(&runner1_, "First Thread");
  base::DelegateSimpleThread thread2(&runner2_, "Second Thread");
  base::DelegateSimpleThread thread3(&runner3_, "Third Thread");

  event1_.sequels_.insert(&link1_2);
  event2_.prequels_.insert(&link1_2);

  event2_.sequels_.insert(&link2_3);
  event3_.prequels_.insert(&link2_3);

  thread3.Start();

  EXPECT_FALSE(event1_.played());
  EXPECT_FALSE(event2_.played());
  EXPECT_FALSE(event3_.played());

  thread2.Start();

  EXPECT_FALSE(event1_.played());
  EXPECT_FALSE(event2_.played());
  EXPECT_FALSE(event3_.played());

  thread1.Start();
  thread1.Join();
  thread2.Join();
  thread3.Join();

  EXPECT_TRUE(event1_.played());
  EXPECT_TRUE(event2_.played());
  EXPECT_TRUE(event3_.played());
}

TEST_F(LinkedEventTest, TestMultipleDependency) {
  CausalLink link1_3;
  CausalLink link2_3;

  base::DelegateSimpleThread thread1(&runner1_, "First Thread");
  base::DelegateSimpleThread thread2(&runner2_, "Second Thread");
  base::DelegateSimpleThread thread3(&runner3_, "Third Thread");

  event1_.sequels_.insert(&link1_3);
  event3_.prequels_.insert(&link1_3);

  event2_.sequels_.insert(&link2_3);
  event3_.prequels_.insert(&link2_3);

  thread3.Start();

  EXPECT_FALSE(event1_.played());
  EXPECT_FALSE(event2_.played());
  EXPECT_FALSE(event3_.played());

  thread2.Start();

  EXPECT_FALSE(event1_.played());
  EXPECT_TRUE(event2_.played());
  EXPECT_FALSE(event3_.played());

  thread1.Start();
  thread1.Join();
  thread2.Join();
  thread3.Join();

  EXPECT_TRUE(event1_.played());
  EXPECT_TRUE(event2_.played());
  EXPECT_TRUE(event3_.played());
}

}  // namespace bard
