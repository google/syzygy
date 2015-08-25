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

#include "syzygy/bard/events/heap_size_event.h"

#include "syzygy/bard/backdrops/heap_backdrop.h"
#include "syzygy/trace/common/clock.h"

namespace bard {
namespace events {

HeapSizeEvent::HeapSizeEvent(HANDLE trace_heap,
                             DWORD flags,
                             LPCVOID trace_alloc,
                             SIZE_T trace_size)
    : trace_heap_(trace_heap),
      flags_(flags),
      trace_alloc_(trace_alloc),
      trace_size_(trace_size) {
}

bool HeapSizeEvent::Play(void* backdrop) {
  DCHECK_NE(static_cast<void*>(nullptr), backdrop);

  using bard::backdrops::HeapBackdrop;
  HeapBackdrop* heap_backdrop = reinterpret_cast<HeapBackdrop*>(backdrop);

  HANDLE live_heap = INVALID_HANDLE_VALUE;
  LPVOID live_alloc = nullptr;

  if (!heap_backdrop->heap_map().GetLiveFromTrace(trace_heap_, &live_heap) ||
      !heap_backdrop->alloc_map().GetLiveFromTrace(
          const_cast<LPVOID>(trace_alloc_), &live_alloc)) {
    return false;
  }

  uint64_t t0 = ::trace::common::GetTsc();
  SIZE_T live_size = heap_backdrop->HeapSize(live_heap, flags_, live_alloc);
  uint64_t t1 = ::trace::common::GetTsc();

  if (live_size != trace_size_) {
    LOG(ERROR) << "HeapSize returned an unexpected allocation size.";
    return false;
  }

  heap_backdrop->UpdateStats(type(), t1 - t0);

  return true;
}

}  // namespace events
}  // namespace bard
