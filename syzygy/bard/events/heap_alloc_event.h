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
// Declares an event to represent a HeapAlloc function call.
#ifndef SYZYGY_BARD_EVENTS_HEAP_ALLOC_EVENT_H_
#define SYZYGY_BARD_EVENTS_HEAP_ALLOC_EVENT_H_

#include "syzygy/bard/events/linked_event.h"

namespace bard {
namespace events {

// An event that wraps a call to HeapAlloc, to be played against a
// HeapBackdrop.
class HeapAllocEvent : public LinkedEvent {
 public:
  HeapAllocEvent(HANDLE trace_heap,
                 DWORD flags,
                 SIZE_T bytes,
                 LPVOID trace_alloc);

  // Event implementation.
  const char* name() const override;

  // @name Accessors.
  // @{
  HANDLE trace_heap() const { return trace_heap_; }
  DWORD flags() const { return flags_; }
  SIZE_T bytes() const { return bytes_; }
  LPVOID trace_alloc() const { return trace_alloc_; }
  // @}

 private:
  // LinkedEvent implementation.
  bool PlayImpl(void* backdrop) override;

  // Arguments to HeapAlloc.
  HANDLE trace_heap_;
  DWORD flags_;
  SIZE_T bytes_;

  // Recorded return value.
  LPVOID trace_alloc_;

  DISALLOW_COPY_AND_ASSIGN(HeapAllocEvent);
};

}  // namespace events
}  // namespace bard

#endif  // SYZYGY_BARD_EVENTS_HEAP_ALLOC_EVENT_H_
