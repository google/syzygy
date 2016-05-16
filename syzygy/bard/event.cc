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
//
// Declares an interface for recording events, which can be played by a
// story teller in an arbitrary order, and during which stats can be
// collected for user analysis.

#include "syzygy/bard/event.h"

#include "syzygy/bard/events/heap_alloc_event.h"
#include "syzygy/bard/events/heap_create_event.h"
#include "syzygy/bard/events/heap_destroy_event.h"
#include "syzygy/bard/events/heap_free_event.h"
#include "syzygy/bard/events/heap_realloc_event.h"
#include "syzygy/bard/events/heap_set_information_event.h"
#include "syzygy/bard/events/heap_size_event.h"
#include "syzygy/bard/events/linked_event.h"

namespace bard {

// This ensures that Save and Load are kept up to date with the enumeration.
static_assert(static_cast<int>(EventInterface::kHeapSizeEvent + 1) ==
                  static_cast<int>(EventInterface::kMaxEventType),
              "all event types must be implemented");

// static
bool EventInterface::Save(const EventInterface* event,
                          core::OutArchive* out_archive) {
  DCHECK_NE(static_cast<EventInterface*>(nullptr), event);
  DCHECK_NE(static_cast<core::OutArchive*>(nullptr), out_archive);

  static_assert((kMaxEventType & 0xFFFF) == kMaxEventType,
                "event type counts must fit in 16-bits");
  if (!out_archive->Save(static_cast<uint16_t>(event->type())))
    return false;

  switch (event->type()) {
    case kLinkedEvent:
      return events::LinkedEvent::Save(event, out_archive);
    case kHeapAllocEvent:
      return events::HeapAllocEvent::Save(event, out_archive);
    case kHeapCreateEvent:
      return events::HeapCreateEvent::Save(event, out_archive);
    case kHeapDestroyEvent:
      return events::HeapDestroyEvent::Save(event, out_archive);
    case kHeapFreeEvent:
      return events::HeapFreeEvent::Save(event, out_archive);
    case kHeapReAllocEvent:
      return events::HeapReAllocEvent::Save(event, out_archive);
    case kHeapSetInformationEvent:
      return events::HeapSetInformationEvent::Save(event, out_archive);
    case kHeapSizeEvent:
      return events::HeapSizeEvent::Save(event, out_archive);
    case kMaxEventType:
      break;
      // No default case is specified so that the compiler will complain if a
      // new type is defined by not handled here.
  }

  NOTREACHED();
  return false;
}

// static
std::unique_ptr<EventInterface> EventInterface::Load(
    core::InArchive* in_archive) {
  DCHECK_NE(static_cast<core::InArchive*>(nullptr), in_archive);

  uint16_t type = 0;
  if (!in_archive->Load(&type))
    return false;

  switch (static_cast<EventType>(type)) {
    case kLinkedEvent:
      return events::LinkedEvent::Load(in_archive);
    case kHeapAllocEvent:
      return events::HeapAllocEvent::Load(in_archive);
    case kHeapCreateEvent:
      return events::HeapCreateEvent::Load(in_archive);
    case kHeapDestroyEvent:
      return events::HeapDestroyEvent::Load(in_archive);
    case kHeapFreeEvent:
      return events::HeapFreeEvent::Load(in_archive);
    case kHeapReAllocEvent:
      return events::HeapReAllocEvent::Load(in_archive);
    case kHeapSetInformationEvent:
      return events::HeapSetInformationEvent::Load(in_archive);
    case kHeapSizeEvent:
      return events::HeapSizeEvent::Load(in_archive);
    case kMaxEventType:
      break;
      // No default case is specified so that the compiler will complain if a
      // new type is defined by not handled here.
  }

  NOTREACHED();
  return nullptr;
}

}  // namespace bard
