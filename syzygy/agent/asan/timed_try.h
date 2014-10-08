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

#ifndef SYZYGY_AGENT_ASAN_TIMED_TRY_H_
#define SYZYGY_AGENT_ASAN_TIMED_TRY_H_

#include "base/time/time.h"

namespace agent {
namespace asan {

// Spends at most |delta| time trying to acquire the given |lock|. The time
// limit is a guideline and not precise. This function tries to grab the lock
// by repeatedly calling 'LockType::Try' via LockTryFunctor.
// @tparam LockType The type of the lock to be acquired.
// @param delta The maximum amount of time to spend trying to acquire the lock.
// @param lock The lock to be acquired.
// @returns true if the lock has been acquired, false otherwise.
template<typename LockType>
bool TimedTry(base::TimeDelta delta, LockType* lock);

// A scoped timed try lock.
// @tparam LockType The type of the lock to be acquired.
template<typename LockType>
class AutoTimedTry {
 public:
  AutoTimedTry(base::TimeDelta delta, LockType* lock);
  ~AutoTimedTry();
  bool is_acquired() const;

 private:
  LockType* lock_;
  bool is_acquired_;

  DISALLOW_COPY_AND_ASSIGN(AutoTimedTry);
};

}  // namespace asan
}  // namespace agent

#include "syzygy/agent/asan/timed_try_impl.h"

#endif  // SYZYGY_AGENT_ASAN_TIMED_TRY_H_
