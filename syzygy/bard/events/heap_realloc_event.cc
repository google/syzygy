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

#include "syzygy/bard/events/heap_realloc_event.h"

#include "syzygy/bard/backdrops/heap_backdrop.h"
#include "syzygy/bard/events/play_util.h"

namespace bard {
namespace events {

HeapReAllocEvent::HeapReAllocEvent(uint32_t stack_trace_id,
                                   HANDLE trace_heap,
                                   DWORD flags,
                                   LPVOID trace_alloc,
                                   SIZE_T bytes,
                                   LPVOID trace_realloc)
    : stack_trace_id_(stack_trace_id),
      trace_heap_(trace_heap),
      flags_(flags),
      trace_alloc_(trace_alloc),
      bytes_(bytes),
      trace_realloc_(trace_realloc) {
}

bool HeapReAllocEvent::Save(const EventInterface* const event,
                            core::OutArchive* out_archive) {
  DCHECK_NE(static_cast<EventInterface*>(nullptr), event);
  DCHECK_NE(static_cast<core::OutArchive*>(nullptr), out_archive);

  const HeapReAllocEvent* derived_event =
      reinterpret_cast<const HeapReAllocEvent*>(event);

  return out_archive->Save(derived_event->stack_trace_id_) &&
         out_archive->Save(
             reinterpret_cast<uintptr_t>(derived_event->trace_heap_)) &&
         out_archive->Save(derived_event->flags_) &&
         out_archive->Save(
             reinterpret_cast<uintptr_t>(derived_event->trace_alloc_)) &&
         out_archive->Save(derived_event->bytes_) &&
         out_archive->Save(
             reinterpret_cast<uintptr_t>(derived_event->trace_realloc_));
}

std::unique_ptr<HeapReAllocEvent> HeapReAllocEvent::Load(
    core::InArchive* in_archive) {
  DCHECK_NE(static_cast<core::InArchive*>(nullptr), in_archive);

  uint32_t stack_trace_id = 0;
  uintptr_t trace_heap = 0;
  DWORD flags = 0;
  uintptr_t trace_alloc = 0;
  SIZE_T bytes = 0;
  uintptr_t trace_realloc = 0;
  if (in_archive->Load(&stack_trace_id) && in_archive->Load(&trace_heap) &&
      in_archive->Load(&flags) && in_archive->Load(&trace_alloc) &&
      in_archive->Load(&bytes) && in_archive->Load(&trace_realloc)) {
    return std::unique_ptr<HeapReAllocEvent>(new HeapReAllocEvent(
        stack_trace_id, reinterpret_cast<HANDLE>(trace_heap), flags,
        reinterpret_cast<LPVOID>(trace_alloc), bytes,
        reinterpret_cast<LPVOID>(trace_realloc)));
  }
  return nullptr;
}

bool HeapReAllocEvent::Play(void* backdrop) {
  DCHECK_NE(static_cast<void*>(nullptr), backdrop);

  using bard::backdrops::HeapBackdrop;
  HeapBackdrop* heap_backdrop = reinterpret_cast<HeapBackdrop*>(backdrop);

  HANDLE live_heap = INVALID_HANDLE_VALUE;
  LPVOID live_alloc = nullptr;

  if (!heap_backdrop->heap_map().GetLiveFromTrace(trace_heap_, &live_heap) ||
      !heap_backdrop->alloc_map().GetLiveFromTrace(trace_alloc_, &live_alloc)) {
    return false;
  }

  uint64_t timing = 0;
  LPVOID live_realloc = InvokeOnBackdrop(
      stack_trace_id_, &timing, heap_backdrop, &HeapBackdrop::HeapReAlloc,
      live_heap, flags_, live_alloc, bytes_);

  if (!live_realloc && trace_realloc_) {
    LOG(ERROR) << "HeapReAlloc failed to allocate memory.";
    return false;
  }

  if (live_realloc) {
    if (!trace_realloc_) {
      // No need to keep the new allocation or remove the previous allocation.
      heap_backdrop->HeapFree(live_heap, flags_, live_realloc);
    } else if (!heap_backdrop->alloc_map().RemoveMapping(trace_alloc_,
                                                         live_alloc) ||
               !heap_backdrop->alloc_map().AddMapping(trace_realloc_,
                                                      live_realloc)) {
      return false;
    }
  }

  heap_backdrop->UpdateStats(type(), timing);

  return true;
}

bool HeapReAllocEvent::Equals(const EventInterface* rhs) const {
  DCHECK_NE(static_cast<EventInterface*>(nullptr), rhs);

  if (rhs->type() != kHeapReAllocEvent)
    return false;

  const auto e = reinterpret_cast<const HeapReAllocEvent*>(rhs);
  if (stack_trace_id_ != e->stack_trace_id_ || trace_heap_ != e->trace_heap_ ||
      flags_ != e->flags_ || trace_alloc_ != e->trace_alloc_ ||
      bytes_ != e->bytes_ || trace_realloc_ != e->trace_realloc_) {
    return false;
  }

  return true;
}

}  // namespace events
}  // namespace bard
