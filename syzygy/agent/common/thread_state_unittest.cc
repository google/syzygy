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

#include "base/atomic_ref_count.h"
#include "base/bind.h"
#include "base/synchronization/waitable_event.h"
#include "base/threading/thread.h"
#include "gtest/gtest.h"

namespace agent {
namespace common {
namespace {

// A ThreadStateBase derived class for unit-testing.
class TestThreadState : public ThreadStateBase {
 public:
  // Expose protected members for unit-testing.
  using ThreadStateBase::entry_;

  explicit TestThreadState(base::AtomicRefCount* ref) : ref_(ref) {
    base::AtomicRefCountInc(ref_);
  }
  virtual ~TestThreadState() {
    base::AtomicRefCountDec(ref_);
  }

 private:
  base::AtomicRefCount* ref_;
};

// A ThreadStateManager derived class for unit-testing.
class TestThreadStateManager : public ThreadStateManager {
 public:
  // Expose protected members for unit-testing.
  using ThreadStateManager::Scavenge;
  using ThreadStateManager::IsThreadDead;

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
  bool IsActive(const TestThreadState* item) {
    base::AutoLock auto_lock(lock_);
    return ListContains(&active_items_, item);
  }

  // Returns true iff @p items is in the death_row list.
  bool IsOnDeathRow(const TestThreadState* item) {
    base::AutoLock auto_lock(lock_);
    return ListContains(&death_row_items_, item);
  }

 protected:
  // A helper function to check if a item is in the given list.
  static bool ListContains(const LIST_ENTRY* list,
                           const TestThreadState* item) {
    return IsNodeOnList(const_cast<LIST_ENTRY*>(list),
                        const_cast<LIST_ENTRY*>(&item->entry_));
  }
};

// The test fixture for the thread state related tests.
class ThreadStateTest : public testing::Test {
 public:
  ThreadStateTest()
      : worker_thread_("test"),
        manager_(),
        thread_states_(0) {
  }

  // A setup function run before each test.
  virtual void SetUp() OVERRIDE {
    manager_.reset(new TestThreadStateManager);
    ASSERT_TRUE(worker_thread_.Start());
  }

  // A helper factory function for creating a TestThreadState.
  void CreateThreadStateImpl(TestThreadState** thread_state) {
    ASSERT_TRUE(thread_state != NULL);
    *thread_state = new TestThreadState(&thread_states_);
  }

  // Creates (and returns) a thread state object on the worker thread.
  void CreateThreadState(TestThreadState** state) {
    ASSERT_TRUE(state != NULL);
    CallOnWorkerThread(
        base::Bind(&ThreadStateTest::CreateThreadStateImpl,
                   base::Unretained(this),
                   state));
    ASSERT_TRUE(*state != NULL);
  }

  // Activates a thread state object on the worker thread.
  void RegisterThreadState(ThreadStateBase* state) {
    CallOnWorkerThread(
        base::Bind(&TestThreadStateManager::Register,
                   base::Unretained(manager_.get()),
                   state));
  }

  // Unregisters a thread state object on the worker thread.
  void UnregisterThreadState(ThreadStateBase* state) {
    CallOnWorkerThread(
        base::Bind(&TestThreadStateManager::Unregister,
                   base::Unretained(manager_.get()),
                   state));
  }

  // Marks a thread state object for death on the worker thread.
  void MarkThreadStateForDeath(ThreadStateBase* state) {
    CallOnWorkerThread(
        base::Bind(&TestThreadStateManager::MarkForDeath,
                   base::Unretained(manager_.get()),
                   state));
  }

 protected:
  // Callback function to execute a TestThreadStateManager method on
  // worker_thread_ and signal its completion.
  void CallbackImpl(
      base::Closure task,
      base::WaitableEvent* event) {
    ASSERT_TRUE(event != NULL);
    ASSERT_EQ(base::MessageLoop::current(), worker_thread_.message_loop());
    task.Run();
    event->Signal();
  }

  // Helper function to call a closure on worker_thread_
  // and wait until its completion has been signaled.
  void CallOnWorkerThread(base::Closure task) {
    base::WaitableEvent event(false, false);
    worker_thread_.message_loop()->PostTask(
        FROM_HERE,
        base::Bind(&ThreadStateTest::CallbackImpl,
                   base::Unretained(this),
                   task,
                   &event));
    event.Wait();
  }

  // A counter for the number of outstanding thread states.
  base::AtomicRefCount thread_states_;

  // The worker thread on which the state management functions will be
  // exercised.
  base::Thread worker_thread_;

  // The thread state manager under test.
  scoped_ptr<TestThreadStateManager> manager_;
};

}  // namespace

TEST_F(ThreadStateTest, LifeCycle) {
  // Check the base state of the thread state manager_->
  EXPECT_FALSE(manager_->HasActiveItems());
  EXPECT_FALSE(manager_->HasDeathRowItems());

  // Create a thread state item.
  TestThreadState* thread_state = NULL;
  ASSERT_NO_FATAL_FAILURE(CreateThreadState(&thread_state));
  EXPECT_FALSE(manager_->IsThreadDead(thread_state));

  // Register the thread state item.
  ASSERT_NO_FATAL_FAILURE(RegisterThreadState(thread_state));
  EXPECT_TRUE(manager_->HasActiveItems());
  EXPECT_TRUE(manager_->IsActive(thread_state));
  EXPECT_FALSE(manager_->HasDeathRowItems());

  // Unregister the thread state item.
  ASSERT_NO_FATAL_FAILURE(UnregisterThreadState(thread_state));
  EXPECT_FALSE(manager_->HasActiveItems());
  EXPECT_FALSE(manager_->HasDeathRowItems());

  // Re-register the thread state item.
  ASSERT_NO_FATAL_FAILURE(RegisterThreadState(thread_state));
  EXPECT_TRUE(manager_->HasActiveItems());
  EXPECT_TRUE(manager_->IsActive(thread_state));
  EXPECT_FALSE(manager_->HasDeathRowItems());

  // Mark the thread state for death.
  ASSERT_NO_FATAL_FAILURE(MarkThreadStateForDeath(thread_state));
  EXPECT_FALSE(manager_->HasActiveItems());
  EXPECT_TRUE(manager_->HasDeathRowItems());
  EXPECT_TRUE(manager_->IsOnDeathRow(thread_state));

  // A list to which we'll scavenge thread state items.
  bool has_items = false;
  LIST_ENTRY dead_items;
  InitializeListHead(&dead_items);

  // Scavenge from death row while the thread is still running. Note that we
  // test this using the internal function that usually isn't exposed to
  // callers.
  has_items = manager_->Scavenge();
  EXPECT_TRUE(has_items);
  EXPECT_TRUE(IsListEmpty(&dead_items));
  EXPECT_FALSE(manager_->HasActiveItems());
  EXPECT_TRUE(manager_->HasDeathRowItems());
  EXPECT_TRUE(manager_->IsOnDeathRow(thread_state));

  // Stop thread then scavenge from death row. Note that we test this using
  // the internal function that usually isn't exposed to callers.
  worker_thread_.Stop();
  EXPECT_TRUE(manager_->IsThreadDead(thread_state));
  EXPECT_TRUE(base::AtomicRefCountIsOne(&thread_states_));
  has_items = manager_->Scavenge();
  EXPECT_FALSE(has_items);
  EXPECT_FALSE(manager_->HasActiveItems());
  EXPECT_FALSE(manager_->HasDeathRowItems());
  EXPECT_TRUE(base::AtomicRefCountIsZero(&thread_states_));
}

TEST_F(ThreadStateTest, DeletesAllThreadStatesOnDestruction) {
  TestThreadState* thread_state = NULL;
  ASSERT_NO_FATAL_FAILURE(CreateThreadState(&thread_state));
  ASSERT_NO_FATAL_FAILURE(RegisterThreadState(thread_state));

  // We expect the thread state to be destroyed on deletion of the manager.
  EXPECT_TRUE(base::AtomicRefCountIsOne(&thread_states_));

  manager_.reset();

  EXPECT_TRUE(base::AtomicRefCountIsZero(&thread_states_));
}

}  // namespace common
}  // namespace agent
