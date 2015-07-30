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

#include "syzygy/bard/causal_link.h"

namespace bard {

CausalLink::CausalLink() : cv_(&lock_), signaled_(false) {
}

void CausalLink::Wait() {
  base::AutoLock auto_lock(lock_);
  // Wait until link is signaled.
  while (!signaled_)
    cv_.Wait();
}

bool CausalLink::TimedWait(const base::TimeDelta& max_time) {
  base::AutoLock auto_lock(lock_);
  // Wait up to the maximum allowed time or up to receiving a Broadcast
  // signal.
  cv_.TimedWait(max_time);

  if (!signaled_)
    return false;
  return true;
}

void CausalLink::Signal() {
  base::AutoLock auto_lock(lock_);
  // Mark the link as signaled and broadcast, which unblocks all the
  // waiting threads.
  signaled_ = true;
  cv_.Broadcast();
}

void CausalLink::Reset() {
  base::AutoLock auto_lock(lock_);
  // Mark the link as unsignaled.
  signaled_ = false;
}

}  // namespace bard
