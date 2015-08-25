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
// Declares an event to represent a HeapCreate function call.
#ifndef SYZYGY_BARD_EVENTS_HEAP_CREATE_EVENT_H_
#define SYZYGY_BARD_EVENTS_HEAP_CREATE_EVENT_H_

#include "syzygy/bard/events/linked_event.h"

namespace bard {
namespace events {

// An event that wraps a call to HeapCreate, to be played against a
// HeapBackdrop.
class HeapCreateEvent : public EventInterface {
 public:
  HeapCreateEvent(DWORD options,
                  SIZE_T initial_size,
                  SIZE_T maximum_size,
                  HANDLE trace_heap);

  // @name EventInterface implementation.
  // @{
  EventType type() const override { return kGetProcessHeapEvent; }
  bool Play(void* backdrop) override;
  // @}

  // @name Accessors.
  // @{
  DWORD options() const { return options_; }
  SIZE_T initial_size() const { return initial_size_; }
  SIZE_T maximum_size() const { return maximum_size_; }
  HANDLE trace_heap() const { return trace_heap_; }
  // @}

 private:
  // Arguments to HeapCreate.
  DWORD options_;
  SIZE_T initial_size_;
  SIZE_T maximum_size_;

  // Recorded return value.
  HANDLE trace_heap_;

  DISALLOW_COPY_AND_ASSIGN(HeapCreateEvent);
};

}  // namespace events
}  // namespace bard

#endif  // SYZYGY_BARD_EVENTS_HEAP_CREATE_EVENT_H_
