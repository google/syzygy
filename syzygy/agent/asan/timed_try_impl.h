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
// Utility functions for spending a fixed amount of time trying to acquire
// a base::Lock (or any lock with the same API).

#ifndef SYZYGY_AGENT_ASAN_TIMED_TRY_IMPL_H_
#define SYZYGY_AGENT_ASAN_TIMED_TRY_IMPL_H_

#ifndef SYZYGY_AGENT_ASAN_TIMED_TRY_H_
#error Meant to be included from timed_try.h only.
#endif

#include "base/logging.h"
#include "base/time/time.h"

namespace agent {
namespace asan {

// A simple functor that calls LockType::Try.
template<typename LockType>
struct BasicLockTryFunctor {
  bool operator()(LockType* lock) {
    DCHECK_NE(static_cast<LockType*>(NULL), lock);
    return lock->Try();
  }
};

template<typename LockType, typename LockTryFunctor>
bool TimedTry(base::TimeDelta delta, LockType* lock) {
  DCHECK_NE(static_cast<LockType*>(NULL), lock);

  // Try at least once, even if |delta| is zero or negative.
  LockTryFunctor try_lock;
  if (try_lock(lock))
    return true;

  // Try repeatedly, until timeout.
  base::Time end = base::Time::Now() + delta;
  while (base::Time::Now() < end) {
    // Spin a bunch of times.
    for (size_t i = 0; i < 100; ++i)
      if (try_lock(lock))
        return true;

    // Cede the processor to another thread, hoping the lock will become
    // available at some point.
    ::SwitchToThread();
  }

  return false;
}

template<typename LockType, typename LockTryFunctor>
AutoTimedTry<LockType, LockTryFunctor>::AutoTimedTry(
    base::TimeDelta delta, LockType* lock)
    : lock_(lock) {
  DCHECK_NE(static_cast<LockType*>(NULL), lock);
  is_acquired_ = TimedTry(delta, lock);
}

template<typename LockType, typename LockTryFunctor>
AutoTimedTry<LockType, LockTryFunctor>::~AutoTimedTry() {
  if (is_acquired_)
    lock_->Release();
}

template<typename LockType, typename LockTryFunctor>
bool AutoTimedTry<LockType, LockTryFunctor>::is_acquired() const {
  return is_acquired_;
}

}  // namespace asan
}  // namespace agent

#endif  // SYZYGY_AGENT_ASAN_TIMED_TRY_IMPL_H_
