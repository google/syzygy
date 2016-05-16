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

#include "syzygy/bard/events/heap_set_information_event.h"

#include "syzygy/bard/backdrops/heap_backdrop.h"
#include "syzygy/trace/common/clock.h"

namespace bard {
namespace events {

HeapSetInformationEvent::HeapSetInformationEvent(
    uint32_t stack_trace_id,
    HANDLE trace_heap,
    HEAP_INFORMATION_CLASS info_class,
    PVOID info,
    SIZE_T info_length,
    BOOL trace_succeeded)
    : stack_trace_id_(stack_trace_id),
      trace_heap_(trace_heap),
      info_class_(info_class),
      info_(info),
      info_length_(info_length),
      trace_succeeded_(trace_succeeded) {
}

bool HeapSetInformationEvent::Save(const EventInterface* const event,
                                   core::OutArchive* out_archive) {
  DCHECK_NE(static_cast<EventInterface*>(nullptr), event);
  DCHECK_NE(static_cast<core::OutArchive*>(nullptr), out_archive);

  const HeapSetInformationEvent* derived_event =
      reinterpret_cast<const HeapSetInformationEvent*>(event);

  return out_archive->Save(derived_event->stack_trace_id_) &&
         out_archive->Save(
             reinterpret_cast<uintptr_t>(derived_event->trace_heap_)) &&
         out_archive->Save(static_cast<uint32_t>(derived_event->info_class_)) &&
         out_archive->Save(reinterpret_cast<uintptr_t>(derived_event->info_)) &&
         out_archive->Save(derived_event->info_length_) &&
         out_archive->Save(derived_event->trace_succeeded_);
}

std::unique_ptr<HeapSetInformationEvent> HeapSetInformationEvent::Load(
    core::InArchive* in_archive) {
  DCHECK_NE(static_cast<core::InArchive*>(nullptr), in_archive);

  uint32_t stack_trace_id = 0;
  uintptr_t trace_heap = 0;
  uint32_t info_class = 0;
  uintptr_t info = 0;
  SIZE_T info_length = 0;
  BOOL trace_succeeded = 0;
  if (in_archive->Load(&stack_trace_id) && in_archive->Load(&trace_heap) &&
      in_archive->Load(&info_class) && in_archive->Load(&info) &&
      in_archive->Load(&info_length) && in_archive->Load(&trace_succeeded)) {
    return std::unique_ptr<HeapSetInformationEvent>(new HeapSetInformationEvent(
        stack_trace_id, reinterpret_cast<HANDLE>(trace_heap),
        static_cast<HEAP_INFORMATION_CLASS>(info_class),
        reinterpret_cast<PVOID>(info), info_length, trace_succeeded));
  }
  return nullptr;
}

bool HeapSetInformationEvent::Play(void* backdrop) {
  DCHECK_NE(static_cast<void*>(nullptr), backdrop);

  using bard::backdrops::HeapBackdrop;
  HeapBackdrop* heap_backdrop = reinterpret_cast<HeapBackdrop*>(backdrop);

  HANDLE live_heap = INVALID_HANDLE_VALUE;

  if (!heap_backdrop->heap_map().GetLiveFromTrace(trace_heap_, &live_heap))
    return false;

  uint64_t t0 = ::trace::common::GetTsc();
  BOOL live_succeeded = heap_backdrop->HeapSetInformation(
      live_heap, info_class_, info_, info_length_);
  uint64_t t1 = ::trace::common::GetTsc();

  if (live_succeeded != trace_succeeded_) {
    LOG(ERROR) << "HeapSetInformation "
               << (live_succeeded ? "succeeded" : "failed")
               << " when it was supposed to "
               << (trace_succeeded_ ? "succeed" : "fail") << ".";
    return false;
  }

  heap_backdrop->UpdateStats(type(), t1 - t0);

  return true;
}

bool HeapSetInformationEvent::Equals(const EventInterface* rhs) const {
  DCHECK_NE(static_cast<EventInterface*>(nullptr), rhs);

  if (rhs->type() != kHeapSetInformationEvent)
    return false;

  const auto e = reinterpret_cast<const HeapSetInformationEvent*>(rhs);
  if (stack_trace_id_ != e->stack_trace_id_ || trace_heap_ != e->trace_heap_ ||
      info_class_ != e->info_class_ || info_ != e->info_ ||
      info_length_ != e->info_length_ ||
      trace_succeeded_ != e->trace_succeeded_) {
    return false;
  }

  return true;
}

}  // namespace events
}  // namespace bard
