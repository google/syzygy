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

#include "syzygy/agent/asan/timed_try.h"

#include "base/synchronization/condition_variable.h"
#include "base/synchronization/lock.h"
#include "base/threading/simple_thread.h"
#include "base/time/time.h"
#include "gtest/gtest.h"
#include "syzygy/common/recursive_lock.h"

namespace agent {
namespace asan {

namespace {

// A thread body that acquires a lock, waits a certain amount of time, then
// releases it. Signals when it has acquired the lock for unittest
// synchronization purposes.
template<typename LockType>
class TimedTryTestRunner : public base::DelegateSimpleThread::Delegate {
 public:
  TimedTryTestRunner(base::TimeDelta delta, LockType* lock)
      : cv_(&cv_lock_), held_(false), delta_(delta), lock_(lock) {
    DCHECK_NE(static_cast<LockType*>(NULL), lock);
  }

  virtual void Run() {
    lock_->Acquire();

    // Notify that the lock has been acquired.
    {
      base::AutoLock lock(cv_lock_);
      held_ = true;
      cv_.Signal();
    }

    base::Time end = base::Time::Now() + delta_;
    while (true) {
      base::Time now = base::Time::Now();
      if (now >= end)
        break;
      base::TimeDelta remaining = end - now;
      ::Sleep(remaining.InMillisecondsRoundedUp());
    }

    lock_->Release();
  }

  void WaitUntilHeld() {
    base::AutoLock auto_lock(cv_lock_);
    if (held_)
      return;
    cv_.Wait();
  }

 private:
  // Used for signalling when the lock has been acquired.
  base::Lock cv_lock_;
  base::ConditionVariable cv_;
  bool held_;

  base::TimeDelta delta_;
  LockType* lock_;

  DISALLOW_COPY_AND_ASSIGN(TimedTryTestRunner);
};

base::TimeDelta kDelay(base::TimeDelta::FromMilliseconds(100));

template <typename LockType>
void TimedTryTestImpl() {
  LockType lock;

  TimedTryTestRunner<LockType> runner(kDelay * 2, &lock);
  base::DelegateSimpleThread thread(&runner, "TimedTryTestRunner");

  // Grab the lock.
  EXPECT_TRUE(TimedTry<LockType>(kDelay, &lock));
  lock.AssertAcquired();

  // Try to grab the lock but expect a timeout.
  base::Time t0 = base::Time::Now();
  thread.Start();
  lock.Release();
  runner.WaitUntilHeld();
  ASSERT_FALSE(TimedTry<LockType>(kDelay, &lock));

  // Try to grab the lock again, expecting success this time.
  ASSERT_TRUE(TimedTry<LockType>(kDelay * 10, &lock));
  lock.Release();
  base::Time t1 = base::Time::Now();
  EXPECT_LE(kDelay * 2, t1 - t0);

  thread.Join();
}

template <typename LockType>
void AutoTimedTryTestImpl() {
  LockType lock;

  TimedTryTestRunner<LockType> runner(kDelay * 2, &lock);
  base::DelegateSimpleThread thread(&runner, "TimedTryTestRunner");

  base::Time t0;
  {
    AutoTimedTry<LockType> timed_try(kDelay, &lock);
    EXPECT_TRUE(timed_try.is_acquired());
    t0 = base::Time::Now();
    thread.Start();
  }
  runner.WaitUntilHeld();

  // Try to grab the lock, but expect it to fail as the lock will be held
  // longer than we try.
  {
    AutoTimedTry<LockType> timed_try(kDelay, &lock);
    EXPECT_FALSE(timed_try.is_acquired());
  }

  // Try to grab the lock and expect it to succeed, as the wait is longer than
  // the lock will be held.
  {
    AutoTimedTry<LockType> timed_try(kDelay * 10, &lock);
    base::Time t1 = base::Time::Now();
    EXPECT_LE(kDelay * 2, t1 - t0);
  }

  thread.Join();
}

}  // namespace

TEST(TimedTryTest, BaseLock) {
  ASSERT_NO_FATAL_FAILURE(TimedTryTestImpl<base::Lock>());
}

TEST(AutoTimedTryTest, BaseLock) {
  ASSERT_NO_FATAL_FAILURE(AutoTimedTryTestImpl<base::Lock>());
}

TEST(TimedTryTest, CommonRecursiveLock) {
  ASSERT_NO_FATAL_FAILURE(TimedTryTestImpl<common::RecursiveLock>());
}

TEST(AutoTimedTryTest, CommonRecursiveLock) {
  ASSERT_NO_FATAL_FAILURE(AutoTimedTryTestImpl<common::RecursiveLock>());
}

}  // namespace asan
}  // namespace agent
