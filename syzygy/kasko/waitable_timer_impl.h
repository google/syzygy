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

#ifndef SYZYGY_KASKO_WAITABLE_TIMER_IMPL_H_
#define SYZYGY_KASKO_WAITABLE_TIMER_IMPL_H_

#include <windows.h>

#include <memory>

#include "base/macros.h"
#include "base/win/scoped_handle.h"
#include "syzygy/kasko/waitable_timer.h"

namespace base {
class TimeDelta;
}  // namespace base

namespace kasko {

// Implements WaitableTimer using a fixed timer interval.
class WaitableTimerImpl : public WaitableTimer {
 public:
  // Creates an instance with a fixed timer interval. Each time the timer is
  // started, it will become signaled after the given interval elapses.
  // @param interval The fixed timer interval.
  // @returns a WaitableTimer instance, or NULL in case of an error.
  static std::unique_ptr<WaitableTimer> Create(const base::TimeDelta& interval);

  ~WaitableTimerImpl() override;

  // WaitableTimer implementation.
  void Start() override;
  HANDLE GetHANDLE() override;

 private:
  // Instantiates an instance using the pre-created waitable timer handle and a
  // fixed interval.
  // @param handle A waitable timer HANDLE.
  // @param interval The fixed timer interval.
  explicit WaitableTimerImpl(base::win::ScopedHandle handle,
                             const base::TimeDelta& interval);

  // A waitable timer HANDLE.
  base::win::ScopedHandle handle_;
  // The fixed timer interval, in a format suitable for SetWaitableTimer.
  LARGE_INTEGER interval_;

  DISALLOW_COPY_AND_ASSIGN(WaitableTimerImpl);
};

}  // namespace kasko

#endif  // SYZYGY_KASKO_WAITABLE_TIMER_IMPL_H_
