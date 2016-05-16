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
#include "syzygy/bard/events/play_util.h"

namespace bard {
namespace events {

HeapAllocEvent::HeapAllocEvent(uint32_t stack_trace_id,
                               HANDLE trace_heap,
                               DWORD flags,
                               SIZE_T bytes,
                               LPVOID trace_alloc)
    : stack_trace_id_(stack_trace_id),
      trace_heap_(trace_heap),
      flags_(flags),
      bytes_(bytes),
      trace_alloc_(trace_alloc) {
}

bool HeapAllocEvent::Save(const EventInterface* const event,
                          core::OutArchive* out_archive) {
  DCHECK_NE(static_cast<EventInterface*>(nullptr), event);
  DCHECK_NE(static_cast<core::OutArchive*>(nullptr), out_archive);

  const HeapAllocEvent* derived_event =
      reinterpret_cast<const HeapAllocEvent*>(event);

  return out_archive->Save(derived_event->stack_trace_id_) &&
         out_archive->Save(
             reinterpret_cast<uintptr_t>(derived_event->trace_heap_)) &&
         out_archive->Save(derived_event->flags_) &&
         out_archive->Save(derived_event->bytes_) &&
         out_archive->Save(
             reinterpret_cast<uintptr_t>(derived_event->trace_alloc_));
}

std::unique_ptr<HeapAllocEvent> HeapAllocEvent::Load(
    core::InArchive* in_archive) {
  DCHECK_NE(static_cast<core::InArchive*>(nullptr), in_archive);

  uint32_t stack_trace_id = 0;
  uintptr_t trace_heap = 0;
  DWORD flags = 0;
  SIZE_T bytes = 0;
  uintptr_t trace_alloc = 0;
  if (in_archive->Load(&stack_trace_id) && in_archive->Load(&trace_heap) &&
      in_archive->Load(&flags) && in_archive->Load(&bytes) &&
      in_archive->Load(&trace_alloc)) {
    return std::unique_ptr<HeapAllocEvent>(new HeapAllocEvent(
        stack_trace_id, reinterpret_cast<HANDLE>(trace_heap), flags, bytes,
        reinterpret_cast<LPVOID>(trace_alloc)));
  }
  return nullptr;
}

bool HeapAllocEvent::Play(void* backdrop) {
  DCHECK_NE(static_cast<void*>(nullptr), backdrop);

  using bard::backdrops::HeapBackdrop;
  HeapBackdrop* heap_backdrop = reinterpret_cast<HeapBackdrop*>(backdrop);

  HANDLE live_heap = INVALID_HANDLE_VALUE;

  if (!heap_backdrop->heap_map().GetLiveFromTrace(trace_heap_, &live_heap))
    return false;

  uint64_t timing = 0;
  LPVOID live_alloc =
      InvokeOnBackdrop(stack_trace_id_, &timing, heap_backdrop,
                       &HeapBackdrop::HeapAlloc, live_heap, flags_, bytes_);

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

  heap_backdrop->UpdateStats(type(), timing);

  return true;
}

bool HeapAllocEvent::Equals(const EventInterface* rhs) const {
  DCHECK_NE(static_cast<EventInterface*>(nullptr), rhs);

  if (rhs->type() != kHeapAllocEvent)
    return false;

  const auto e = reinterpret_cast<const HeapAllocEvent*>(rhs);
  if (stack_trace_id_ != e->stack_trace_id_ || trace_heap_ != e->trace_heap_ ||
      flags_ != e->flags_ || bytes_ != e->bytes_ ||
      trace_alloc_ != e->trace_alloc_) {
    return false;
  }

  return true;
}

}  // namespace events
}  // namespace bard
