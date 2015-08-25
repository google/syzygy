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
// Declares an event to represent a HeapReAlloc function call.
#ifndef SYZYGY_BARD_EVENTS_HEAP_REALLOC_EVENT_H_
#define SYZYGY_BARD_EVENTS_HEAP_REALLOC_EVENT_H_

#include "syzygy/bard/events/linked_event.h"

namespace bard {
namespace events {

// An event that wraps a call to HeapReAlloc, to be played against a
// HeapBackdrop.
class HeapReAllocEvent : public EventInterface {
 public:
  HeapReAllocEvent(HANDLE trace_heap,
                   DWORD flags,
                   LPVOID trace_alloc,
                   SIZE_T bytes,
                   LPVOID trace_realloc);

  // @name EventInterface implementation.
  // @{
  EventType type() const override { return kGetProcessHeapEvent; }
  bool Play(void* backdrop) override;
  // @}

  // @name Accessors.
  // @{
  HANDLE trace_heap() const { return trace_heap_; }
  DWORD flags() const { return flags_; }
  LPVOID trace_alloc() const { return trace_alloc_; }
  SIZE_T bytes() const { return bytes_; }
  LPVOID trace_realloc() const { return trace_realloc_; }
  // @}

 private:
  // Arguments to HeapReAlloc.
  HANDLE trace_heap_;
  DWORD flags_;
  LPVOID trace_alloc_;
  SIZE_T bytes_;

  // Recorded return value.
  LPVOID trace_realloc_;

  DISALLOW_COPY_AND_ASSIGN(HeapReAllocEvent);
};

}  // namespace events
}  // namespace bard

#endif  // SYZYGY_BARD_EVENTS_HEAP_REALLOC_EVENT_H_
