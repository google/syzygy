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
#include "syzygy/bard/events/play_util.h"

namespace bard {
namespace events {

HeapCreateEvent::HeapCreateEvent(uint32_t stack_trace_id,
                                 DWORD options,
                                 SIZE_T initial_size,
                                 SIZE_T maximum_size,
                                 HANDLE trace_heap)
    : stack_trace_id_(stack_trace_id),
      options_(options),
      initial_size_(initial_size),
      maximum_size_(maximum_size),
      trace_heap_(trace_heap) {
}

bool HeapCreateEvent::Save(const EventInterface* const event,
                           core::OutArchive* out_archive) {
  DCHECK_NE(static_cast<EventInterface*>(nullptr), event);
  DCHECK_NE(static_cast<core::OutArchive*>(nullptr), out_archive);

  const HeapCreateEvent* derived_event =
      reinterpret_cast<const HeapCreateEvent*>(event);

  return out_archive->Save(derived_event->stack_trace_id_) &&
         out_archive->Save(derived_event->options_) &&
         out_archive->Save(derived_event->initial_size_) &&
         out_archive->Save(derived_event->maximum_size_) &&
         out_archive->Save(
             reinterpret_cast<uintptr_t>(derived_event->trace_heap_));
}

std::unique_ptr<HeapCreateEvent> HeapCreateEvent::Load(
    core::InArchive* in_archive) {
  DCHECK_NE(static_cast<core::InArchive*>(nullptr), in_archive);

  uint32_t stack_trace_id = 0;
  DWORD options = 0;
  SIZE_T initial_size = 0;
  SIZE_T maximum_size = 0;
  uintptr_t trace_heap;
  if (in_archive->Load(&stack_trace_id) && in_archive->Load(&options) &&
      in_archive->Load(&initial_size) && in_archive->Load(&maximum_size) &&
      in_archive->Load(&trace_heap)) {
    return std::unique_ptr<HeapCreateEvent>(
        new HeapCreateEvent(stack_trace_id, options, initial_size, maximum_size,
                            reinterpret_cast<HANDLE>(trace_heap)));
  }
  return nullptr;
}

bool HeapCreateEvent::Play(void* backdrop) {
  DCHECK_NE(static_cast<void*>(nullptr), backdrop);

  using bard::backdrops::HeapBackdrop;
  HeapBackdrop* heap_backdrop = reinterpret_cast<HeapBackdrop*>(backdrop);

  uint64_t timing = 0;
  HANDLE live_heap = InvokeOnBackdrop(stack_trace_id_, &timing, heap_backdrop,
                                      &HeapBackdrop::HeapCreate, options_,
                                      initial_size_, maximum_size_);

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

  heap_backdrop->UpdateStats(type(), timing);

  return true;
}

bool HeapCreateEvent::Equals(const EventInterface* rhs) const {
  DCHECK_NE(static_cast<EventInterface*>(nullptr), rhs);

  if (rhs->type() != kHeapCreateEvent)
    return false;

  const auto e = reinterpret_cast<const HeapCreateEvent*>(rhs);
  if (stack_trace_id_ != e->stack_trace_id_ || options_ != e->options_ ||
      initial_size_ != e->initial_size_ || maximum_size_ != e->maximum_size_ ||
      trace_heap_ != e->trace_heap_) {
    return false;
  }

  return true;
}

}  // namespace events
}  // namespace bard
