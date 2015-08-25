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

#include <set>

#include "base/memory/scoped_ptr.h"
#include "base/synchronization/waitable_event.h"
#include "syzygy/bard/event.h"

namespace bard {
namespace events {

// Composition of Event interface that admits dependencies between
// events.
class LinkedEvent {
 public:
  explicit LinkedEvent(scoped_ptr<EventInterface> event);

  // LinkedEvent dependencies setter.
  // @param prequel an event that must happen before this one.
  void AddPrequel(LinkedEvent* prequel);

  // Plays the recorded function call, possibly modifying the current
  // backdrop.
  // @note The backdrop is a piece of user data, specific to a set of
  // events, whose exact type is dictated by convention.
  // @param backdrop the backdrop.
  // @returns true if Play succeeds without any problems, false otherwise.
  bool Play(void* backdrop);

  // @name Accessors.
  // @{
  const EventInterface* event() const { return event_.get(); }
  // @}

 private:
  base::WaitableEvent waitable_event_;

  // The event that this LinkedEvent refers to.
  scoped_ptr<EventInterface> event_;
  // The prequel events must be played before this one.
  std::set<LinkedEvent*> prequels_;

  DISALLOW_COPY_AND_ASSIGN(LinkedEvent);
};

}  // namespace events
}  // namespace bard

#endif  // SYZYGY_BARD_EVENTS_LINKED_EVENT_H_
