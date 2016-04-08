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
// The output of the grinder should look like the following (with a minimal set
// of dependencies drawn as arrows):
//
//     WorkerThread1                       WorkerThread2
//     -------------                       -------------
//  0: create heap 0                       create heap 3
//  1: create alloc 0 on heap 0            create alloc 3 on heap 3
//  2: create heap 1 --------------------> create alloc 4 on heap 1
//  3: create alloc 1 on heap 1 ---------> get size of alloc 1 on heap 1
//  4: create alloc 2 on heap 1            realloc alloc 1 on heap 1
//  5: free alloc 2 on heap 1 -----+       free alloc 1 on heap 1
//  6: set info on heap 2          |       free alloc 4 on heap 1
//  7: free alloc 0 on heap 0      +-----> destroy heap 1
//  8: destroy heap 0                      free alloc 3 on heap 3
//  9:                                     destroy heap 3
//
// The mutexes ensure that the sequence of events happens as follows:
//
// Phase 0: Thread1: 0, 1, 2, 3, 4
// Phase 1: Thread2: 0, 1, 2, 3, 4, 5, 6
// Phase 2: Thread1: 5, 6, 7, 8
// Phase 3: Thread2: 7, 8, 9

#include <assert.h>
#include <windows.h>

namespace {

// Mutex synchronizing access to shared_heap and shared_alloc.
HANDLE shared_mutex = nullptr;

// The current 'phase'. This is used to coordinate the sequence of events
// across the two threads. This is necessary to ensure the dependencies are
// exactly as wanted, without unintentional dependencies caused by allocation
// reuse in a heap. Modified under |shared_mutex|.
size_t phase = 0;

// Heap that has shared use across two threads. Modified under |shared_mutex|.
HANDLE shared_heap = nullptr;

// Allocation that has shared use across two threads. Allocated from
// shared_heap. Modified under |shared_mutex|.
void* shared_alloc = nullptr;

// Helper function for acquiring |shared_mutex| on the current thread and in
// the desired phase.
void AcquireMutex(size_t desired_phase) {
  while (true) {
    while (::WaitForSingleObject(shared_mutex, INFINITE) != WAIT_OBJECT_0) {}
    if (desired_phase == phase)
      return;
    ::ReleaseMutex(shared_mutex);
    ::Sleep(10);
  }
}

// Releases the mutex and increments the phase.
void ReleaseMutex() {
  ++phase;
  ::ReleaseMutex(shared_mutex);
}

// Body of the first worker thread. This thread is responsible for creating the
// shared heap and allocation.
DWORD WINAPI WorkerThread1Main(LPVOID param) {
  AcquireMutex(0);
  assert(shared_heap == nullptr);
  assert(shared_alloc == nullptr);

  // Allocate a heap and a buffer on this thread.
  HANDLE heap = ::HeapCreate(0, 0, 0);                     // 0
  void* alloc1 = ::HeapAlloc(heap, HEAP_ZERO_MEMORY, 42);  // 1

  shared_heap = ::HeapCreate(0, 0, 0);                  // 2
  shared_alloc = ::HeapAlloc(shared_heap, 0, 1 << 20);  // 3

  void* alloc2 = ::HeapAlloc(shared_heap, 0, 16);  // 4

  ReleaseMutex();
  AcquireMutex(2);

  ::HeapFree(shared_heap, 0, alloc2);              // 5

  // Tinker with the process heap a bit.
  HANDLE process_heap = ::GetProcessHeap();
  ::HeapSetInformation(process_heap, HeapEnableTerminationOnCorruption,  // 6
                       0, 0);

  // Free the allocation and heap made on this thread.
  ::HeapFree(heap, 0, alloc1);  // 7
  alloc1 = nullptr;
  ::HeapDestroy(heap);  // 8
  heap = nullptr;

  ReleaseMutex();

  return 0;
}

// Body of the second worker thread. This thread is responsible for releasing
// the shared heap and allocation.
DWORD WINAPI WorkerThread2Main(LPVOID param) {
  AcquireMutex(1);
  assert(shared_heap != nullptr);
  assert(shared_alloc != nullptr);

  // Allocate a heap and a buffer on this thread.
  HANDLE heap = ::HeapCreate(0, 0, 0);                       // 0
  void* alloc1 = ::HeapAlloc(heap, HEAP_ZERO_MEMORY, 1024);  // 1

  // Create an allocation on this thread that is only used on this thread,
  // but which references the shared heap.
  HANDLE alloc2 = ::HeapAlloc(shared_heap, 0, 347);  // 2

  // Query and then free the shared allocation.
  ::HeapSize(shared_heap, 0, shared_alloc);                         // 3
  shared_alloc = ::HeapReAlloc(shared_heap, 0, shared_alloc, 500);  // 4
  ::HeapFree(shared_heap, 0, shared_alloc);                         // 5
  shared_alloc = nullptr;

  // Free the shared_heap allocation made on this thread.
  ::HeapFree(shared_heap, 0, alloc2);  // 6

  ReleaseMutex();
  AcquireMutex(3);

  // Free the shared heap.
  ::HeapDestroy(shared_heap);  // 7
  shared_heap = nullptr;

  ::HeapFree(heap, 0, alloc1);  // 8
  alloc1 = nullptr;
  ::HeapDestroy(heap);  // 9
  heap = nullptr;

  ::ReleaseMutex(shared_mutex);

  return 0;
}

}  // namespace

int main(int argc, const char* const* argv) {
  // The controlled tests (with known expectations) are run on independent
  // threads. This keeps them separated from the CRT code that runs on the main
  // thread and which we don't directly control.

  // Create a mutex not owned by anyone.
  shared_mutex = ::CreateMutex(NULL, FALSE, NULL);

  // Run the two threads simultaneously and wait for them both to finish.
  DWORD worker_thread_1_id = 0;
  HANDLE worker_thread_1 = ::CreateThread(nullptr, 0, WorkerThread1Main,
                                          nullptr, 0, &worker_thread_1_id);
  DWORD worker_thread_2_id = 0;
  HANDLE worker_thread_2 = ::CreateThread(nullptr, 0, WorkerThread2Main,
                                          nullptr, 0, &worker_thread_2_id);
  ::WaitForSingleObject(worker_thread_1, INFINITE);
  ::WaitForSingleObject(worker_thread_2, INFINITE);

  // Destroy the mutex.
  ::CloseHandle(shared_mutex);

  return 0;
}
