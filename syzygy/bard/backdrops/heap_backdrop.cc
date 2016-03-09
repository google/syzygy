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

#include "syzygy/bard/backdrops/heap_backdrop.h"

#include "base/logging.h"

namespace bard {
namespace backdrops {

HeapBackdrop::HeapBackdrop() {
}

LPVOID HeapBackdrop::HeapAlloc(HANDLE heap, DWORD flags, SIZE_T bytes) {
  DCHECK(!heap_alloc_.is_null());
  return heap_alloc_.Run(heap, flags, bytes);
}

HANDLE HeapBackdrop::HeapCreate(DWORD options,
                                SIZE_T initial_size,
                                SIZE_T maximum_size) {
  DCHECK(!heap_create_.is_null());
  return heap_create_.Run(options, initial_size, maximum_size);
}

BOOL HeapBackdrop::HeapDestroy(HANDLE heap) {
  DCHECK(!heap_destroy_.is_null());
  return heap_destroy_.Run(heap);
}

BOOL HeapBackdrop::HeapFree(HANDLE heap, DWORD flags, LPVOID mem) {
  DCHECK(!heap_free_.is_null());
  return heap_free_.Run(heap, flags, mem);
}

LPVOID HeapBackdrop::HeapReAlloc(HANDLE heap,
                                 DWORD flags,
                                 LPVOID mem,
                                 SIZE_T bytes) {
  DCHECK(!heap_realloc_.is_null());
  return heap_realloc_.Run(heap, flags, mem, bytes);
}

BOOL HeapBackdrop::HeapSetInformation(HANDLE heap,
                                      HEAP_INFORMATION_CLASS info_class,
                                      PVOID info,
                                      SIZE_T info_length) {
  DCHECK(!heap_set_information_.is_null());
  return heap_set_information_.Run(heap, info_class, info, info_length);
}

SIZE_T HeapBackdrop::HeapSize(HANDLE heap, DWORD flags, LPCVOID mem) {
  DCHECK(!heap_size_.is_null());
  return heap_size_.Run(heap, flags, mem);
}

void HeapBackdrop::UpdateStats(EventType type, uint64_t time) {
  base::AutoLock auto_lock(lock_);

  auto stats = total_stats_.insert(std::make_pair(type, struct Stats())).first;
  stats->second.calls++;
  stats->second.time += time;
}

bool HeapBackdrop::TearDown() {
  // Destroy heaps created via AddExistingHeap.
  for (auto live_heap : existing_heaps_) {
    HANDLE trace_heap = nullptr;
    if (!heap_map_.GetTraceFromLive(live_heap, &trace_heap))
      return false;
    ::HeapDestroy(live_heap);
    // This can only fail under racy use of this class.
    CHECK(heap_map_.RemoveMapping(trace_heap, live_heap));
  }

  // Remove the heap created by SetProcessHeap. This can only fail under racy
  // use of this class.
  HANDLE live_ph = ::GetProcessHeap();
  HANDLE trace_ph = nullptr;
  if (heap_map_.GetTraceFromLive(live_ph, &trace_ph))
    CHECK(heap_map_.RemoveMapping(trace_ph, live_ph));

  // Handle any other heaps that were created via the HeapDestroy callback.
  for (auto heap_pair : heap_map_.live_trace()) {
    DCHECK(!heap_destroy_.is_null());
    if (!heap_destroy_.Run(heap_pair.first))
      return false;
  }
  heap_map_.Clear();

  // Since the heaps are clear, also clear the maps.
  alloc_map_.Clear();
  existing_heaps_.clear();

  return true;
}

bool HeapBackdrop::SetProcessHeap(void* proc_heap) {
  HANDLE ph = ::GetProcessHeap();
  return heap_map_.AddMapping(proc_heap, ph);
}

bool HeapBackdrop::AddExistingHeap(void* heap) {
  HANDLE h = ::HeapCreate(0, 0, 0);
  if (!h)
    return false;
  existing_heaps_.push_back(h);
  return heap_map_.AddMapping(heap, h);
}

}  // namespace backdrops
}  // namespace bard
