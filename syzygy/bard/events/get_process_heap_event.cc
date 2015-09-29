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

#include "syzygy/bard/events/get_process_heap_event.h"

#include "syzygy/bard/backdrops/heap_backdrop.h"
#include "syzygy/trace/common/clock.h"

namespace bard {
namespace events {

GetProcessHeapEvent::GetProcessHeapEvent(HANDLE trace_heap)
    : trace_heap_(trace_heap) {
}

bool GetProcessHeapEvent::Save(const EventInterface* const event,
                               core::OutArchive* out_archive) {
  DCHECK_NE(static_cast<EventInterface*>(nullptr), event);
  DCHECK_NE(static_cast<core::OutArchive*>(nullptr), out_archive);

  const GetProcessHeapEvent* derived_event =
      reinterpret_cast<const GetProcessHeapEvent*>(event);

  return out_archive->Save(
      reinterpret_cast<uintptr_t>(derived_event->trace_heap_));
}

scoped_ptr<GetProcessHeapEvent> GetProcessHeapEvent::Load(
    core::InArchive* in_archive) {
  DCHECK_NE(static_cast<core::InArchive*>(nullptr), in_archive);

  uintptr_t trace_heap;
  if (in_archive->Load(&trace_heap)) {
    return scoped_ptr<GetProcessHeapEvent>(
        new GetProcessHeapEvent(reinterpret_cast<HANDLE>(trace_heap)));
  }
  return nullptr;
}

bool GetProcessHeapEvent::Play(void* backdrop) {
  DCHECK_NE(static_cast<void*>(nullptr), backdrop);

  using bard::backdrops::HeapBackdrop;
  HeapBackdrop* heap_backdrop = reinterpret_cast<HeapBackdrop*>(backdrop);

  uint64_t t0 = ::trace::common::GetTsc();
  HANDLE live_heap = heap_backdrop->GetProcessHeap();
  uint64_t t1 = ::trace::common::GetTsc();

  if (!live_heap && trace_heap_) {
    LOG(ERROR) << "GetProcessHeap failed to get the process heap.";
    return false;
  }

  if (live_heap && trace_heap_ &&
      !heap_backdrop->heap_map().AddMapping(trace_heap_, live_heap)) {
    return false;
  }

  heap_backdrop->UpdateStats(type(), t1 - t0);

  return true;
}

bool GetProcessHeapEvent::Equals(const EventInterface* rhs) const {
  DCHECK_NE(static_cast<EventInterface*>(nullptr), rhs);

  if (rhs->type() != kGetProcessHeapEvent)
    return false;

  const auto e = reinterpret_cast<const GetProcessHeapEvent*>(rhs);
  if (trace_heap_ != e->trace_heap_)
    return false;

  return true;
}

}  // namespace events
}  // namespace bard
