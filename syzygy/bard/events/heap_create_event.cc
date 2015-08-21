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

#include "syzygy/bard/events/heap_create_event.h"

#include "syzygy/bard/backdrops/heap_backdrop.h"
#include "syzygy/trace/common/clock.h"

namespace bard {
namespace events {

HeapCreateEvent::HeapCreateEvent(DWORD options,
                                 SIZE_T initial_size,
                                 SIZE_T maximum_size,
                                 HANDLE trace_heap)
    : options_(options),
      initial_size_(initial_size),
      maximum_size_(maximum_size),
      trace_heap_(trace_heap) {
}

bool HeapCreateEvent::PlayImpl(void* backdrop) {
  DCHECK_NE(static_cast<void*>(nullptr), backdrop);

  using bard::backdrops::HeapBackdrop;
  HeapBackdrop* heap_backdrop = reinterpret_cast<HeapBackdrop*>(backdrop);

  uint64_t t0 = ::trace::common::GetTsc();
  HANDLE live_heap =
      heap_backdrop->HeapCreate(options_, initial_size_, maximum_size_);
  uint64_t t1 = ::trace::common::GetTsc();

  if (!live_heap && trace_heap_) {
    LOG(ERROR) << "HeapCreate failed to create a new heap.";
    return false;
  }

  if (live_heap) {
    if (!trace_heap_) {
      // No need to keep this heap.
      heap_backdrop->HeapDestroy(live_heap);
    } else if (!heap_backdrop->heap_map().AddMapping(trace_heap_, live_heap)) {
      return false;
    }
  }

  heap_backdrop->UpdateStats(type(), t1 - t0);

  return true;
}

}  // namespace events
}  // namespace bard
