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

#include "syzygy/kasko/waitable_timer_impl.h"

#include <windows.h>

#include "base/time/time.h"
#include "syzygy/common/com_utils.h"

namespace kasko {

// static
std::unique_ptr<WaitableTimer> WaitableTimerImpl::Create(
    const base::TimeDelta& interval) {
  std::unique_ptr<WaitableTimer> result;
  base::win::ScopedHandle handle(::CreateWaitableTimer(NULL, TRUE, NULL));
  if (handle.IsValid())
    result.reset(new WaitableTimerImpl(std::move(handle), interval));
  return std::move(result);
}

WaitableTimerImpl::~WaitableTimerImpl() {}

void WaitableTimerImpl::Start() {
  if (!::SetWaitableTimer(handle_.Get(), &interval_, 0, NULL, NULL, FALSE))
    LOG(ERROR) << "Unexpected failure to set a timer: " << ::common::LogWe();
}

HANDLE WaitableTimerImpl::GetHANDLE() {
  return handle_.Get();
}

WaitableTimerImpl::WaitableTimerImpl(base::win::ScopedHandle handle,
                                     const base::TimeDelta& interval)
    : handle_(handle.Take()), interval_() {
  interval_.QuadPart = (-interval.InMicroseconds()) *
                       (base::Time::kNanosecondsPerMicrosecond / 100);
}

}  // namespace kasko
