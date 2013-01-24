// Copyright 2012 Google Inc. All Rights Reserved.
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

#include "syzygy/agent/common/thread_state.h"

#include "base/bind.h"
#include "base/synchronization/waitable_event.h"
#include "base/threading/thread.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace agent {
namespace common {
namespace {

// A ThreadStateBase derived class for unit-testing.
class MockThreadState : public ThreadStateBase {
 public:
  // Expose protected members for unit-testing.
  using ThreadStateBase::entry_;

  // Create a mock for the destructor so that we can track when it is called.
  virtual ~MockThreadState() { OnDestruction(); }
  MOCK_METHOD0(OnDestruction, void());
};

// A ThreadSTateManager derived class for unit-testing.
class TestThreadStateManager : public ThreadStateManager {
 public:
  // Expose protected members for unit-testing.
  using ThreadStateManager::Scavenge;
  using ThreadStateManager::IsThreadDead;

  // A helper factory function for creating a MockThreadState. This is added
  // to this ThreadStateManager derived class as a helper which is callable
  // via ThreadStateTest::CallOnWorkerThread.
  void CreateThreadState(MockThreadState** thread_state) {
    ASSERT_TRUE(thread_state != NULL);
    *thread_state = new testing::StrictMock<MockThreadState>();
  }

  // Returns true if the there are no active thread state items being managed.
  bool HasActiveItems() {
    base::AutoLock auto_lock(lock_);
    return !IsListEmpty(&active_items_);
  }

  // Returns true if the there are no death row thread state items being
  // managed. If this returns true, it does not necessarily mean that there
  // are items ready to be scavenged.
  bool HasDeathRowItems() {
    base::AutoLock auto_lock(lock_);
    return !IsListEmpty(&death_row_items_);
  }

  // Returns true iff @p item is in the active items list.
  bool IsActive(const MockThreadState* item) {
    base::AutoLock auto_lock(lock_);
    return ListContains(&active_items_, item);
  }

  // Returns true iff @p items is in the death_row list.
  bool IsOnDeathRow(const MockThreadState* item) {
    base::AutoLock auto_lock(lock_);
    return ListContains(&death_row_items_, item);
  }

 protected:
  // A helper function to check if a item is in the given list.
  static bool ListContains(const LIST_ENTRY* list,
                           const MockThreadState* item) {
    const LIST_ENTRY* current = list;
    const LIST_ENTRY* entry = &item->entry_;
    while (current != NULL) {
      if (current->Flink == entry)
        return true;
      current = current->Flink;
    }
    return true;
  }
};

// The test fixture for the thread state related tests.
class ThreadStateTest : public testing::Test {
 public:
  ThreadStateTest() : worker_thread_("test") {
  }

  // A setup function run before each test.
  virtual void SetUp() OVERRIDE {
    ASSERT_TRUE(worker_thread_.Start());
  }

  // Creates (and returns) a thread state object on the worker thread.
  void CreateThreadState(MockThreadState** state) {
    ASSERT_TRUE(state != NULL);
    CallOnWorkerThread(&TestThreadStateManager::CreateThreadState, state);
    ASSERT_TRUE(*state != NULL);
  }

  // Activates a thread state object on the worker thread.
  void RegisterThreadState(ThreadStateBase* state) {
    CallOnWorkerThread(&TestThreadStateManager::Register, state);
  }

  // Unregisters a thread state object on the worker thread.
  void UnregisterThreadState(ThreadStateBase* state) {
    CallOnWorkerThread(&TestThreadStateManager::Unregister, state);
  }

  // Marks a thread state object for death on the worker thread.
  void MarkThreadStateForDeath(ThreadStateBase* state) {
    CallOnWorkerThread(&TestThreadStateManager::MarkForDeath, state);
  }

 protected:
  // Callback function to execute a TestThreadStateManager method on
  // worker_thread_ and signal its completion.
  template<typename ParamType>
  void CallbackImpl(
      void (TestThreadStateManager::*method)(ParamType),
      ParamType param,
      base::WaitableEvent* event) {
    ASSERT_TRUE(param != NULL);
    ASSERT_TRUE(event != NULL);
    ASSERT_EQ(MessageLoop::current(), worker_thread_.message_loop());
    (manager_.*method)(param);
    event->Signal();
  }

  // Helper function to call a TestThreadStateManager method on worker_thread_
  // and wait until its completion has been signaled.
  template<typename ParamType>
  void CallOnWorkerThread(
      void (TestThreadStateManager::*method)(ParamType),
      ParamType param) {
    base::WaitableEvent event(false, false);
    worker_thread_.message_loop()->PostTask(
        FROM_HERE,
        base::Bind(&ThreadStateTest::CallbackImpl<ParamType>,
                   base::Unretained(this),
                   method,
                   param,
                   &event));
    event.Wait();
  }

  // The worker thread on which the state management functions will be
  // exercised.
  base::Thread worker_thread_;

  // The thread state manager under test.
  TestThreadStateManager manager_;
};

}  // namespace

TEST_F(ThreadStateTest, LifeCycle) {
  // Check the base state of the thread state manager.
  EXPECT_FALSE(manager_.HasActiveItems());
  EXPECT_FALSE(manager_.HasDeathRowItems());

  // Create a thread state item.
  MockThreadState* thread_state = NULL;
  ASSERT_NO_FATAL_FAILURE(CreateThreadState(&thread_state));
  EXPECT_FALSE(manager_.IsThreadDead(thread_state));

  // Register the thread state item.
  ASSERT_NO_FATAL_FAILURE(RegisterThreadState(thread_state));
  EXPECT_TRUE(manager_.HasActiveItems());
  EXPECT_TRUE(manager_.IsActive(thread_state));
  EXPECT_FALSE(manager_.HasDeathRowItems());

  // Unregister the thread state item.
  ASSERT_NO_FATAL_FAILURE(UnregisterThreadState(thread_state));
  EXPECT_FALSE(manager_.HasActiveItems());
  EXPECT_FALSE(manager_.HasDeathRowItems());

  // Re-register the thread state item.
  ASSERT_NO_FATAL_FAILURE(RegisterThreadState(thread_state));
  EXPECT_TRUE(manager_.HasActiveItems());
  EXPECT_TRUE(manager_.IsActive(thread_state));
  EXPECT_FALSE(manager_.HasDeathRowItems());

  // Mark the thread state for death.
  ASSERT_NO_FATAL_FAILURE(MarkThreadStateForDeath(thread_state));
  EXPECT_FALSE(manager_.HasActiveItems());
  EXPECT_TRUE(manager_.HasDeathRowItems());
  EXPECT_TRUE(manager_.IsOnDeathRow(thread_state));

  // A list to which we'll scavenge thread state items.
  bool has_items = false;
  LIST_ENTRY dead_items;
  InitializeListHead(&dead_items);

  // Scavenge from death row while the thread is still running. Note that we
  // test this using the internal function that usually isn't exposed to
  // callers.
  manager_.Scavenge(NULL, &has_items);
  EXPECT_TRUE(has_items);
  EXPECT_TRUE(IsListEmpty(&dead_items));
  EXPECT_FALSE(manager_.HasActiveItems());
  EXPECT_TRUE(manager_.HasDeathRowItems());
  EXPECT_TRUE(manager_.IsOnDeathRow(thread_state));

  // Stop thread then scavenge from death row. Note that we test this using
  // the internal function that usually isn't exposed to callers.
  worker_thread_.Stop();
  EXPECT_TRUE(manager_.IsThreadDead(thread_state));
  EXPECT_CALL(*thread_state, OnDestruction());
  manager_.Scavenge(NULL, &has_items);
  EXPECT_FALSE(has_items);
  EXPECT_FALSE(manager_.HasActiveItems());
  EXPECT_FALSE(manager_.HasDeathRowItems());
}

}  // namespace common
}  // namespace agent
