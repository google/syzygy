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
// Declares an event to represent a HeapSize function call.
#ifndef SYZYGY_BARD_EVENTS_HEAP_SIZE_EVENT_H_
#define SYZYGY_BARD_EVENTS_HEAP_SIZE_EVENT_H_

#include <windows.h>
#include <memory>

#include "syzygy/bard/event.h"

namespace bard {
namespace events {

// An event that wraps a call to HeapSize, to be played against a
// HeapBackdrop.
class HeapSizeEvent : public EventInterface {
 public:
  HeapSizeEvent(uint32_t stack_trace_id,
                HANDLE trace_heap,
                DWORD flags,
                LPCVOID trace_alloc,
                SIZE_T trace_size);

  // @name EventInterface implementation.
  // @{
  EventType type() const override { return kHeapSizeEvent; }
  bool Play(void* backdrop) override;
  bool Equals(const EventInterface* rhs) const override;
  // @}

  // @name Serialization methods.
  // @{
  static bool Save(const EventInterface* const event,
                   core::OutArchive* out_archive);
  static std::unique_ptr<HeapSizeEvent> Load(core::InArchive* in_archive);
  // @}

  // @name Accessors.
  // @{
  uint32_t stack_trace_id() const { return stack_trace_id_; }
  HANDLE trace_heap() const { return trace_heap_; }
  DWORD flags() const { return flags_; }
  LPCVOID trace_alloc() const { return trace_alloc_; }
  SIZE_T trace_size() const { return trace_size_; }
  // @}

 private:
  // The stack trace ID that will be used during playback.
  uint32_t stack_trace_id_;

  // Arguments to HeapSize.
  HANDLE trace_heap_;
  DWORD flags_;
  LPCVOID trace_alloc_;

  // Recorded return value.
  SIZE_T trace_size_;

  DISALLOW_COPY_AND_ASSIGN(HeapSizeEvent);
};

}  // namespace events
}  // namespace bard

#endif  // SYZYGY_BARD_EVENTS_HEAP_SIZE_EVENT_H_
