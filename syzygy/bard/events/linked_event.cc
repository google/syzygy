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

#include "syzygy/bard/events/linked_event.h"

namespace bard {
namespace events {

LinkedEvent::LinkedEvent(std::unique_ptr<EventInterface> event) {
  DCHECK_NE(static_cast<EventInterface*>(nullptr), event.get());
  event_ = std::move(event);
}

bool LinkedEvent::Play(void* backdrop) {
  DCHECK_NE(static_cast<void*>(nullptr), backdrop);

  for (auto& dep : deps_) {
    DCHECK_NE(static_cast<base::WaitableEvent*>(nullptr),
              dep->waitable_event_.get());
    dep->waitable_event_->Wait();
  }

  // Play the wrapped event.
  if (!event_->Play(backdrop))
    return false;

  // If this LinkedEvent is itself an input dependency of another
  // LinkedEvent then fire the signal.
  if (waitable_event_.get())
    waitable_event_->Signal();

  return true;
}

bool LinkedEvent::Equals(const EventInterface* rhs) const {
  DCHECK_NE(static_cast<EventInterface*>(nullptr), rhs);
  if (rhs->type() != kLinkedEvent)
    return false;
  const auto* e = reinterpret_cast<const LinkedEvent*>(rhs);
  if (!this->event_->Equals(e->event_.get()))
    return false;

  // Check that the dependencies are the same in number and content.
  if (deps_.size() != e->deps_.size())
    return false;
  for (size_t i = 0; i < deps_.size(); ++i) {
    const LinkedEvent* dep1 = deps_[i];
    const LinkedEvent* dep2 = e->deps_[i];
    if (!dep1->event_->Equals(dep2->event()))
      return false;
  }

  return true;
}

// static
bool LinkedEvent::Save(const EventInterface* const event,
                       core::OutArchive* out_archive) {
  DCHECK_NE(static_cast<EventInterface*>(nullptr), event);
  DCHECK_NE(static_cast<core::OutArchive*>(nullptr), out_archive);
  if (event->type() != kLinkedEvent)
    return false;
  const auto* e = reinterpret_cast<const LinkedEvent*>(event);
  return EventInterface::Save(e->event_.get(), out_archive);
}

// static
std::unique_ptr<LinkedEvent> LinkedEvent::Load(core::InArchive* in_archive) {
  DCHECK_NE(static_cast<core::InArchive*>(nullptr), in_archive);
  std::unique_ptr<EventInterface> e = EventInterface::Load(in_archive);
  return std::unique_ptr<LinkedEvent>(new LinkedEvent(std::move(e)));
}

bool LinkedEvent::AddDep(EventInterface* dep) {
  DCHECK_NE(static_cast<EventInterface*>(nullptr), dep);

  if (dep->type() != kLinkedEvent)
    return false;

  // Get the underlying LinkedEvent. If this event hasn't yet been used as an
  // input dependency then allocate a waitable_event_ so that it can work as
  // one.
  LinkedEvent* e = reinterpret_cast<LinkedEvent*>(dep);
  if (!e->waitable_event_.get())
    e->waitable_event_.reset(new base::WaitableEvent(true, false));

  deps_.push_back(e);
  return true;
}

}  // namespace events
}  // namespace bard
