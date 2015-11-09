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
// A minimal test harness that invokes all of the functions that are observed
// by the memory profiler. The harness also uses threading so that the traces
// produced by profiling this harness put the grinder through its paces.
//
// The threads are actually executed sequentially so that there's no need for
// locks, but the analysis should infer that they can be run concurrently and
// automatically infer required points of synchronization.
//
// The output of the grinder should look like the following (with a minimal set
// of dependencies drawn as arrows):
//
//     WorkerThread1                       WorkerThread2
//     -------------                       -------------
//  1: create heap 0                       create heap 3
//  2: create alloc 0 on heap 0            create alloc 3 on heap 3
//  3: create heap 1 --------------------> create alloc 4 on heap 1
//  4: create alloc 1 on heap 1 ---------> get size of alloc 1 on heap 1
//  5: create alloc 2 on heap 1            realloc alloc 1 on heap 1
//  6: free alloc 2 on heap 1              free alloc 1 on heap 1
//  7: get process heap 2                  free alloc 4 on heap 1
//  8: set info on heap 2                  destroy heap 1
//  9: free alloc 0 on heap 0              free alloc 3 on heap 3
// 10: destroy heap 0                      destroy heap 3

#include "windows.h"

namespace {

// Heap that has shared use across two threads.
HANDLE shared_heap = nullptr;

// Allocation that has shared use across two threads. Allocated from
// shared_heap.
void* shared_alloc = nullptr;

DWORD WINAPI WorkerThread1Main(LPVOID param) {
  // Allocate a heap and a buffer on this thread.
  HANDLE heap = ::HeapCreate(0, 0, 0);                     // 1
  void* alloc1 = ::HeapAlloc(heap, HEAP_ZERO_MEMORY, 42);  // 2

  shared_heap = ::HeapCreate(0, 0, 0);                  // 3
  shared_alloc = ::HeapAlloc(shared_heap, 0, 1 << 20);  // 4

  void* alloc2 = ::HeapAlloc(shared_heap, 0, 16);  // 5
  ::HeapFree(shared_heap, 0, alloc2);              // 6

  // Tinker with the process heap a bit.
  HANDLE process_heap = ::GetProcessHeap();                              // 7
  ::HeapSetInformation(process_heap, HeapEnableTerminationOnCorruption,  // 8
                       0, 0);

  // Free the allocation and heap made on this thread.
  ::HeapFree(heap, 0, alloc1);  // 9
  alloc1 = nullptr;
  ::HeapDestroy(heap);  // 10
  heap = nullptr;

  return 0;
}

DWORD WINAPI WorkerThread2Main(LPVOID param) {
  // Allocate a heap and a buffer on this thread.
  HANDLE heap = ::HeapCreate(0, 0, 0);                       // 1
  void* alloc1 = ::HeapAlloc(heap, HEAP_ZERO_MEMORY, 1024);  // 2

  // Create an allocation on this thread that is only used on this thread,
  // but which references the shared heap.
  HANDLE alloc2 = ::HeapAlloc(shared_heap, 0, 347);  // 3

  // Query and then free the shared allocation.
  ::HeapSize(shared_heap, 0, shared_alloc);                         // 4
  shared_alloc = ::HeapReAlloc(shared_heap, 0, shared_alloc, 500);  // 5
  ::HeapFree(shared_heap, 0, shared_alloc);                         // 6
  shared_alloc = nullptr;

  // Free the shared_heap allocation made on this thread.
  ::HeapFree(shared_heap, 0, alloc2);  // 7

  // Free the shared heap.
  ::HeapDestroy(shared_heap);  // 8
  shared_heap = nullptr;

  ::HeapFree(heap, 0, alloc1);  // 9
  alloc1 = nullptr;
  ::HeapDestroy(heap);  // 10
  heap = nullptr;

  return 0;
}

}  // namespace

int main(int argc, const char* const* argv) {
  // The controlled tests (with known expectations) are run on independent
  // threads. This keeps them separated from the CRT code that runs on the main
  // thread and which we don't directly control.

  DWORD worker_thread_1_id = 0;
  HANDLE worker_thread_1 = ::CreateThread(nullptr, 0, WorkerThread1Main,
                                          nullptr, 0, &worker_thread_1_id);
  ::WaitForSingleObject(worker_thread_1, INFINITE);

  DWORD worker_thread_2_id = 0;
  HANDLE worker_thread_2 = ::CreateThread(nullptr, 0, WorkerThread2Main,
                                          nullptr, 0, &worker_thread_2_id);
  ::WaitForSingleObject(worker_thread_2, INFINITE);

  return 0;
}
