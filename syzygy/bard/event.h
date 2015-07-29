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

// Interface for storing and replaying events.
class EventInterface {
 public:
  virtual ~EventInterface() { }

  // Event name.
  // @returns the name of this event.
  virtual const char* name() const = 0;

  // Replays the recorded function call, possibly modifying the current
  // backdrop.
  // @note The backdrop is a piece of user data, specific to a set of
  // events, whose exact type is dictated by convention.
  // @param backdrop the backdrop.
  // @returns true if Play succeeds without any problems, false otherwise.
  virtual bool Play(void* backdrop) = 0;
};

}  // namespace bard

#endif  // SYZYGY_BARD_EVENT_H_
