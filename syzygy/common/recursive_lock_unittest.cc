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

#include "syzygy/common/recursive_lock.h"

#include "base/memory/scoped_vector.h"
#include "base/threading/simple_thread.h"
#include "gtest/gtest.h"

namespace common {

namespace {

// We use a thread-safe random function to avoid all of the various threads
// consistently producing the exact same random values.
size_t Rand(size_t min, size_t max) {
  static base::Lock lock;
  base::AutoLock auto_lock(lock);
  size_t r = rand();
  double v = static_cast<double>(r) / static_cast<double>(RAND_MAX);
  v *= max - min;
  r = min + static_cast<size_t>(::round(v));
  return r;
}

// A thread that grabs a recursive lock repeatedly, to random recursion depths.
class RecursiveLockTestRunner : public base::DelegateSimpleThread::Delegate {
 public:
  RecursiveLockTestRunner(size_t lock_count, RecursiveLock* recursive_lock)
      : lock_count_(lock_count), recursive_lock_(recursive_lock) {
  }

  virtual void Run() {
    // The precision of 'Sleep' is in ticks, and we want to wait for 0 or 1
    // ticks.
    static const size_t kOneTickInMs = 15;
    static const size_t kMaxTryCount = 40;

    // Repeatedly grab the lock, with varying recursion depths.
    while (lock_count_ > 0) {
      ::Sleep(kOneTickInMs * Rand(0, 1));

      // Choose a random depth with which to acquire this thread.
      size_t depth = Rand(1, 40);
      for (size_t i = 0; i < depth; ++i) {
        // Every second time we acquire the lock we try it with 'try'.
        if ((i % 2) == 0) {
          // Try to acquire a few times.
          size_t try_count = 0;
          while (try_count < kMaxTryCount && !recursive_lock_->Try()) {
            ++try_count;
            ::Sleep(kOneTickInMs * Rand(0, 1));
          }

          // If we didn't acquire the lock by calling 'Try', then grab it
          // with a blocking acquisition.
          if (try_count == kMaxTryCount)
            recursive_lock_->Acquire();
        } else {
          // Otherwise, simply block on the lock.
          recursive_lock_->Acquire();
        }
      }

      // Release the thread half of the number of times.
      for (size_t i = 0; i < depth / 2; ++i)
        recursive_lock_->Release();

      // Grab and release it a secondary time. This causes an 'up down up down'
      // motion on the recursion depth.
      size_t depth1 = Rand(0, 20);
      for (size_t i = 0; i < depth1; ++i)
        recursive_lock_->Acquire();
      for (size_t i = 0; i < depth1; ++i)
        recursive_lock_->Release();

      // And release the rest of the initial acquisitions.
      for (size_t i = depth / 2; i < depth; ++i)
        recursive_lock_->Release();

      --lock_count_;
    }
  }

 private:
  // The number of times this thread should grab the lock.
  size_t lock_count_;
  // The lock that is being grabbed.
  RecursiveLock* recursive_lock_;
};

}  // namespace

TEST(RecursiveLock, StressTest) {
  static const size_t kCyclesPerThread = 100;
  static const size_t kThreadCount = 50;
  RecursiveLock lock;

  lock.Acquire();
  ScopedVector<RecursiveLockTestRunner> runners;
  ScopedVector<base::DelegateSimpleThread> threads;
  for (size_t i = 0; i < kThreadCount; ++i) {
    runners.push_back(new RecursiveLockTestRunner(kCyclesPerThread, &lock));
    threads.push_back(new base::DelegateSimpleThread(runners.back(),
                                                     "RecursiveLockTest"));
    threads.back()->Start();
  }
  lock.Release();

  for (size_t i = 0; i < threads.size(); ++i)
    threads[i]->Join();
}

}  // namespace common
