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
// Composition of the Event interface that admits dependencies between
// events.
#ifndef SYZYGY_BARD_EVENTS_LINKED_EVENT_H_
#define SYZYGY_BARD_EVENTS_LINKED_EVENT_H_

#include <memory>
#include <set>

#include "base/synchronization/waitable_event.h"
#include "syzygy/bard/event.h"

namespace bard {
namespace events {

// Specialization of EventInterface that allows for cross-event dependencies to
// be expressed.
class LinkedEvent : public EventInterface {
 public:
  // Constructor.
  // @param event Wrapped event.
  explicit LinkedEvent(std::unique_ptr<EventInterface> event);
  ~LinkedEvent() override {}

  // @name EventInterface implementation.
  // @{
  EventType type() const override { return kLinkedEvent; }
  bool Play(void* backdrop) override;
  bool Equals(const EventInterface* rhs) const override;
  // @}

  // @name Serialization methods.
  // @{
  // This method only saves the contained event, and not the actual list of
  // deps.
  static bool Save(const EventInterface* const event,
                   core::OutArchive* out_archive);
  static std::unique_ptr<LinkedEvent> Load(core::InArchive* in_archive);
  // @}

  // Adds a dependency to this event.
  // @param dep an event that must happen before this one. This must itself
  //     be a linked event.
  // @returns true on success, false otherwise.
  // @note This method is not thread safe, so BYOL.
  bool AddDep(EventInterface* dep);

  // @name Accessors.
  // @{
  const EventInterface* event() const { return event_.get(); }
  const std::vector<LinkedEvent*>& deps() const { return deps_; }
  // @}

 private:
  // This is only allocated if this event becomes an output dependency of any
  // others.
  std::unique_ptr<base::WaitableEvent> waitable_event_;

  // The event that this LinkedEvent refers to.
  std::unique_ptr<EventInterface> event_;
  // The list of input dependencies. These are events that must be played
  // before this event is played.
  std::vector<LinkedEvent*> deps_;

  DISALLOW_COPY_AND_ASSIGN(LinkedEvent);
};

}  // namespace events
}  // namespace bard

#endif  // SYZYGY_BARD_EVENTS_LINKED_EVENT_H_
