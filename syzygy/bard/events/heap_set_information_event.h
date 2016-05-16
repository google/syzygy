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
// Declares an event to represent a HeapSetInformation function call.
#ifndef SYZYGY_BARD_EVENTS_HEAP_SET_INFORMATION_EVENT_H_
#define SYZYGY_BARD_EVENTS_HEAP_SET_INFORMATION_EVENT_H_

#include <windows.h>
#include <memory>

#include "syzygy/bard/event.h"

namespace bard {
namespace events {

// An event that wraps a call to HeapSetInformation, to be played against
// a HeapBackdrop.
class HeapSetInformationEvent : public EventInterface {
 public:
  HeapSetInformationEvent(uint32_t stack_trace_id,
                          HANDLE trace_heap,
                          HEAP_INFORMATION_CLASS info_class,
                          PVOID info,
                          SIZE_T info_length,
                          BOOL trace_succeeded);

  // @name EventInterface implementation.
  // @{
  EventType type() const override { return kHeapSetInformationEvent; }
  bool Play(void* backdrop) override;
  bool Equals(const EventInterface* rhs) const override;
  // @}

  // @name Serialization methods.
  // @{
  static bool Save(const EventInterface* const event,
                   core::OutArchive* out_archive);
  static std::unique_ptr<HeapSetInformationEvent> Load(
      core::InArchive* in_archive);
  // @}

  // @name Accessors.
  // @{
  uint32_t stack_trace_id() const { return stack_trace_id_; }
  HANDLE trace_heap() const { return trace_heap_; }
  HEAP_INFORMATION_CLASS info_class() const { return info_class_; }
  PVOID info() const { return info_; }
  SIZE_T info_length() const { return info_length_; }
  BOOL trace_succeeded() const { return trace_succeeded_; }
  // @}

 private:
  // The stack trace ID that will be used during playback.
  uint32_t stack_trace_id_;

  // Arguments to HeapSetInformation.
  HANDLE trace_heap_;
  HEAP_INFORMATION_CLASS info_class_;
  PVOID info_;
  SIZE_T info_length_;

  // Recorded return value.
  BOOL trace_succeeded_;

  DISALLOW_COPY_AND_ASSIGN(HeapSetInformationEvent);
};

}  // namespace events
}  // namespace bard

#endif  // SYZYGY_BARD_EVENTS_HEAP_SET_INFORMATION_EVENT_H_
