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
//
// Declares a recursive lock primitive. This lock is necessary when emulating
// certain Windows primitives, where these locks are common.

#ifndef SYZYGY_COMMON_RECURSIVE_LOCK_H_
#define SYZYGY_COMMON_RECURSIVE_LOCK_H_

#include "base/synchronization/condition_variable.h"
#include "base/synchronization/lock.h"

namespace common {

// A recursive lock allows multiple acquisitions of the lock from the same
// thread, keeping track of the number of acquisitions. Only once the lock has
// been released the same number of times does it return to the unlocked state.
class RecursiveLock {
 public:
  // Constructor.
  RecursiveLock();

  // Raises an exception/breakpoint under debug builds if the lock is not
  // acquired. Optimized away in release builds.
  void AssertAcquired();

  // Acquires the lock, blocking until it is available. This must be followed
  // at some point by a matching call to 'Release' from the same thread.
  void Acquire();

  // Releases the lock. This can only be called from the thread that currently
  // owns the lock.
  void Release();

  // Attempts to acquire the lock, without blocking.
  // @returns true if the attempt was successful (the lock is now owned by the
  //     calling thread), false otherwise.
  bool Try();

 protected:
  // The internal lock logic. Returns true if the lock is acquired, false
  // otherwise. If |wait| is true then this blocks until the lock is acquired.
  bool TryImpl(bool wait);

  // Ensures thread safety for this object.
  base::Lock lock_;
  // A condition variable that is signalled when the lock is freed. Under lock_.
  base::ConditionVariable lock_is_free_;
  // The ID of the thread holding the lock. This is zero if no thread holds the
  // lock. Under lock_.
  size_t thread_id_;
  // Holds the recursion depth. Under lock_.
  size_t recursion_;

 private:
  DISALLOW_COPY_AND_ASSIGN(RecursiveLock);
};

// A scoped lock helper for recursive locks.
class AutoRecursiveLock {
 public:
  explicit AutoRecursiveLock(RecursiveLock& recursive_lock)
      : recursive_lock_(recursive_lock) {
    recursive_lock_.Acquire();
  }

  ~AutoRecursiveLock() {
    recursive_lock_.Release();
  }

 protected:
  RecursiveLock& recursive_lock_;

 private:
  DISALLOW_COPY_AND_ASSIGN(AutoRecursiveLock);
};

}  // namespace common

#endif  // SYZYGY_COMMON_RECURSIVE_LOCK_H_
