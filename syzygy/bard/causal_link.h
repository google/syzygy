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
//
// Declares a CausalLink to represent dependencies between two events.
#ifndef SYZYGY_BARD_CAUSAL_LINK_H_
#define SYZYGY_BARD_CAUSAL_LINK_H_

#include "base/synchronization/waitable_event.h"

namespace bard {

// A link between two events, to represent dependencies and stop threads
// while their dependencies have not been met yet.
class CausalLink {
 public:
  CausalLink();

  // Resets the link to an un-signaled state.
  void Reset();

  // Toggles the state of this link to be signaled. This will unblock all
  // threads actively waiting on the link, and any future threads that
  // attempt to wait.
  void Signal();

  // @returns true if this link is in a signaled state, false otherwise.
  bool IsSignaled();

  // Blocks the calling thread and waits indefinitely for the link to be
  // signaled. If the event has already been signaled, returns immediately.
  void Wait();

  // Blocks the calling thread until @p max_time has elapsed or the link
  // is signaled, whichever comes first.
  // @param max_time the maximum time the link should wait before returning.
  // @returns true if returning because the link was signaled, false if due
  //     to a timeout.
  bool TimedWait(const base::TimeDelta& max_time);

 private:
  base::WaitableEvent event_;

  DISALLOW_COPY_AND_ASSIGN(CausalLink);
};

}  // namespace bard

#endif  // SYZYGY_BARD_CAUSAL_LINK_H_
