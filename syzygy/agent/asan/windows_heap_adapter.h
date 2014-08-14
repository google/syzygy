// Copyright 2014 Google Inc. All Rights Reserved.
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
// Implements an all-static class that act as a proxy between the Windows heap
// interceptors and the ASan heaps.
#ifndef SYZYGY_AGENT_ASAN_WINDOWS_HEAP_ADAPTER_H_
#define SYZYGY_AGENT_ASAN_WINDOWS_HEAP_ADAPTER_H_

#include <windows.h>

#include "base\logging.h"

namespace agent {
namespace asan {

class HeapManagerInterface;

// A WindowsHeapAdapter is responsible for translating the calls to the Windows
// heap functions to their counterparts in a heap manager.
//
// This is an all static class which, once initialized with a
// HeapManagerInterface, simply redirects the calls to this manager.
class WindowsHeapAdapter {
 public:
  // Setup the WindowsHeapAdapter that this adapter delegates to.
  // @param heap_manager The heap manager that his adapter should use.
  static void SetUp(HeapManagerInterface* heap_manager);

  // Tear down this adapter.
  static void TearDown();

  // @name Windows Heap API.
  // @{
  static HANDLE HeapCreate(DWORD options,
                           SIZE_T initial_size,
                           SIZE_T maximum_size);
  static BOOL HeapDestroy(HANDLE heap);
  static LPVOID HeapAlloc(HANDLE heap, DWORD flags, SIZE_T bytes);
  static LPVOID WINAPI HeapReAlloc(HANDLE heap,
                                   DWORD flags,
                                   LPVOID mem,
                                   SIZE_T bytes);
  static BOOL HeapFree(HANDLE heap, DWORD flags, LPVOID mem);
  static SIZE_T HeapSize(HANDLE heap, DWORD flags, LPCVOID mem);
  static BOOL HeapValidate(HANDLE heap, DWORD flags, LPCVOID mem);
  static SIZE_T HeapCompact(HANDLE heap, DWORD flags);
  static BOOL HeapLock(HANDLE heap);
  static BOOL HeapUnlock(HANDLE heap);
  static BOOL HeapWalk(HANDLE heap, LPPROCESS_HEAP_ENTRY entry);
  static BOOL HeapSetInformation(HANDLE heap,
                                 HEAP_INFORMATION_CLASS info_class,
                                 PVOID info,
                                 SIZE_T info_length);
  static BOOL HeapQueryInformation(HANDLE heap,
                                   HEAP_INFORMATION_CLASS info_class,
                                   PVOID info,
                                   SIZE_T info_length,
                                   PSIZE_T return_length);
  // @}

 private:
  // The heap manager that we use internally.
  static HeapManagerInterface* heap_manager_;

  DISALLOW_COPY_AND_ASSIGN(WindowsHeapAdapter);
};

}  // namespace asan
}  // namespace agent

#endif  // SYZYGY_AGENT_ASAN_WINDOWS_HEAP_ADAPTER_H_
