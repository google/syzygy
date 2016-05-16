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

#include <windows.h>
#include <memory>

#include "syzygy/bard/event.h"

namespace bard {
namespace events {

// An event that wraps a call to HeapCreate, to be played against a
// HeapBackdrop.
class HeapCreateEvent : public EventInterface {
 public:
  HeapCreateEvent(uint32_t stack_trace_id,
                  DWORD options,
                  SIZE_T initial_size,
                  SIZE_T maximum_size,
                  HANDLE trace_heap);

  // @name EventInterface implementation.
  // @{
  EventType type() const override { return kHeapCreateEvent; }
  bool Play(void* backdrop) override;
  bool Equals(const EventInterface* rhs) const override;
  // @}

  // @name Serialization methods.
  // @{
  static bool Save(const EventInterface* const event,
                   core::OutArchive* out_archive);
  static std::unique_ptr<HeapCreateEvent> Load(core::InArchive* in_archive);
  // @}

  // @name Accessors.
  // @{
  uint32_t stack_trace_id() const { return stack_trace_id_; }
  DWORD options() const { return options_; }
  SIZE_T initial_size() const { return initial_size_; }
  SIZE_T maximum_size() const { return maximum_size_; }
  HANDLE trace_heap() const { return trace_heap_; }
  // @}

 private:
  // The stack trace ID that will be used during playback.
  uint32_t stack_trace_id_;

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
