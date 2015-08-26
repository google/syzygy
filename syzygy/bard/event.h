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
#ifndef SYZYGY_BARD_EVENT_H_
#define SYZYGY_BARD_EVENT_H_

namespace bard {

// Interface for storing and playing events.
class EventInterface {
 public:
  // Enum of all non-abstract classes that extend the EventInterface.
  // New events should only be added at the end of the Enum (but before
  // kMaxEventType), to maintain backwards compatibility for
  // serialization/deserialization.
  enum EventType {
    kGetProcessHeapEvent,
    kHeapAllocEvent,
    kHeapCreateEvent,
    kHeapDestroyEvent,
    kHeapFreeEvent,
    kHeapReAllocEvent,
    kHeapSetInformationEvent,
    kHeapSizeEvent,
    // This must come last.
    kMaxEventType
  };

  virtual ~EventInterface() { }

  // This event's EventType.
  // @returns the EventType enum representing this event.
  virtual EventType type() const = 0;

  // Plays the recorded function call, possibly modifying the current
  // backdrop.
  // @note The backdrop is a piece of user data, specific to a set of
  // events, whose exact type is dictated by convention.
  // @param backdrop the backdrop.
  // @returns true if Play succeeds without any problems, false otherwise.
  virtual bool Play(void* backdrop) = 0;

  // NOTE: Every non-abstract class that extends Event should
  // also implement two static serialization functions:
  //
  // Serialize an Event in an OutArchive.
  // @param event a ponter to the event to be serialized.
  // @param out_archive where to serialize the event.
  // @returns true on success, false otherwise.
  //
  // static bool Save(const EventInterface* const event,
  //                  core::OutArchive* out_archive);
  //
  // Deserialize an event from an InArchive.
  // @param in_archive from where to deserialize this event.
  // @returns a scoped__ptr to the newly created event on success,
  //     an nullptr scoped_ptr otherwise.
  //
  // static std::scoped_ptr<DerivedEvent> Load(core::InArchive* in_archive);
  //
  // This is done instead of creating virtual methods, for those would require
  // empty constructors and initialization checks, requiring way more effort
  // to maintain.
  //
  // NOTE: A DerivedEvent event should NOT save its own type in the Save method.
  // That should be done by a root serialization, which will need to read the
  // type to call the appropriate static save method from the appropriate class.
};

}  // namespace bard

#endif  // SYZYGY_BARD_EVENT_H_
