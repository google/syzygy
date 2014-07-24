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

#include "base/logging.h"

namespace common {

RecursiveLock::RecursiveLock()
    : lock_is_free_(&lock_), thread_id_(0), recursion_(0) {
}

void RecursiveLock::AssertAcquired() {
  DWORD thread_id = ::GetCurrentThreadId();
  base::AutoLock lock(lock_);

  DCHECK_EQ(thread_id, thread_id_);
  DCHECK_LE(0u, recursion_);
}

void RecursiveLock::Acquire() {
  TryImpl(true);
}

void RecursiveLock::Release() {
  DWORD thread_id = ::GetCurrentThreadId();
  base::AutoLock lock(lock_);

  DCHECK_EQ(thread_id, thread_id_);
  DCHECK_LT(0u, recursion_);

  // Decrement the recursion count. If the lock is now free then clear the
  // thread ID and notify a waiting thread.
  --recursion_;
  if (recursion_ == 0) {
    thread_id_ = 0;
    lock_is_free_.Signal();
  }
}

bool RecursiveLock::Try() {
  return TryImpl(false);
}

bool RecursiveLock::TryImpl(bool wait) {
  DWORD thread_id = ::GetCurrentThreadId();
  base::AutoLock lock(lock_);

  // Reentrancy on the same thread.
  if (thread_id_ == thread_id) {
    ++recursion_;
    return true;
  }

  // If we're not willing to wait and the lock is not free to acquire then
  // bail out.
  if (!wait && thread_id_ != 0)
    return false;

  // Somebody else has the lock so let's wait for them to release it.
  while (thread_id_ != 0)
    // This releases lock_ and waits for a signal, thus 'Acquire' does not busy
    // loop.
    lock_is_free_.Wait();

  // Acquire the lock.
  DCHECK_EQ(0u, thread_id_);
  DCHECK_EQ(0u, recursion_);
  thread_id_ = thread_id;
  recursion_ = 1;

  return true;
}

}  // namespace common
