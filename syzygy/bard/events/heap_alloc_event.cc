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

#include "syzygy/bard/events/heap_alloc_event.h"

#include "syzygy/bard/backdrops/heap_backdrop.h"
#include "syzygy/trace/common/clock.h"

namespace bard {
namespace events {

HeapAllocEvent::HeapAllocEvent(HANDLE trace_heap,
                               DWORD flags,
                               SIZE_T bytes,
                               LPVOID trace_alloc)
    : trace_heap_(trace_heap),
      flags_(flags),
      bytes_(bytes),
      trace_alloc_(trace_alloc) {
}

const char* HeapAllocEvent::name() const {
  return "HeapAllocEvent";
}

bool HeapAllocEvent::PlayImpl(void* backdrop) {
  DCHECK_NE(static_cast<void*>(nullptr), backdrop);

  using bard::backdrops::HeapBackdrop;
  HeapBackdrop* heap_backdrop = reinterpret_cast<HeapBackdrop*>(backdrop);

  HANDLE live_heap = INVALID_HANDLE_VALUE;

  if (!heap_backdrop->heap_map().GetLiveFromTrace(trace_heap_, &live_heap))
    return false;

  uint64_t t0 = ::trace::common::GetTsc();
  LPVOID live_alloc = heap_backdrop->HeapAlloc(live_heap, flags_, bytes_);
  uint64_t t1 = ::trace::common::GetTsc();

  if (!live_alloc && trace_alloc_) {
    LOG(ERROR) << "HeapAlloc failed to allocate memory.";
    return false;
  }

  if (live_alloc) {
    if (!trace_alloc_) {
      // No need to keep this allocation if it failed in the trace file.
      heap_backdrop->HeapFree(live_heap, flags_, live_alloc);
    } else if (!heap_backdrop->alloc_map().AddMapping(trace_alloc_,
                                                      live_alloc)) {
      return false;
    }
  }

  heap_backdrop->UpdateStats(name(), t1 - t0);

  return true;
}

}  // namespace events
}  // namespace bard
