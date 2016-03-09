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

#ifndef SYZYGY_BARD_TRACE_LIVE_MAP_IMPL_H_
#define SYZYGY_BARD_TRACE_LIVE_MAP_IMPL_H_

#include "base/logging.h"

namespace bard {

template <typename T>
bool TraceLiveMap<T>::AddMapping(T trace, T live) {
  DCHECK((trace == nullptr) == (live == nullptr));
  if (trace == nullptr && live == nullptr)
    return true;

  base::AutoLock auto_lock(lock_);

  auto insert_trace_live = trace_live_.insert(std::make_pair(trace, live));

  if (!insert_trace_live.second) {
    LOG(ERROR) << "Trace argument was previously added: " << trace;
    return false;
  }

  auto insert_live_trace = live_trace_.insert(std::make_pair(live, trace));

  if (!insert_live_trace.second) {
    LOG(ERROR) << "Live argument was previously added: " << live;
    trace_live_.erase(insert_trace_live.first);
    return false;
  }

  return true;
}

template <typename T>
bool TraceLiveMap<T>::RemoveMapping(T trace, T live) {
  DCHECK((trace == nullptr) == (live == nullptr));
  if (trace == nullptr && live == nullptr)
    return true;

  base::AutoLock auto_lock(lock_);

  auto find_trace_live = trace_live_.find(trace);
  auto find_live_trace = live_trace_.find(live);

  if (find_trace_live == trace_live_.end()) {
    LOG(ERROR) << "Trace was not previously added:" << trace;
    return false;
  }

  if (find_live_trace == live_trace_.end()) {
    LOG(ERROR) << "Live was not previously added: " << live;
    return false;
  }

  trace_live_.erase(find_trace_live);
  live_trace_.erase(find_live_trace);
  return true;
}

template <typename T>
bool TraceLiveMap<T>::GetLiveFromTrace(T trace, T* live) {
  DCHECK_NE(static_cast<T*>(nullptr), live);
  if (trace == nullptr) {
    *live = nullptr;
    return true;
  }

  base::AutoLock auto_lock(lock_);

  auto live_it = trace_live_.find(trace);
  if (live_it == trace_live_.end()) {
    LOG(ERROR) << "Trace argument was not previously added: " << trace;
    return false;
  }

  *live = live_it->second;
  return true;
}

template <typename T>
bool TraceLiveMap<T>::GetTraceFromLive(T live, T* trace) {
  DCHECK_NE(static_cast<T*>(nullptr), trace);
  if (live == nullptr) {
    *trace = nullptr;
    return true;
  }

  base::AutoLock auto_lock(lock_);

  auto trace_it = live_trace_.find(live);
  if (trace_it == live_trace_.end()) {
    LOG(ERROR) << "Live argument was not previously added: " << live;
    return false;
  }

  *trace = trace_it->second;
  return true;
}

template <typename T>
void TraceLiveMap<T>::Clear() {
  trace_live_.clear();
  live_trace_.clear();
}

}  // namespace bard

#endif  // SYZYGY_BARD_TRACE_LIVE_MAP_IMPL_H_
