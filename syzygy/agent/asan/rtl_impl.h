// Copyright 2012 Google Inc. All Rights Reserved.
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
// Implement the Asan RTL functions.
#ifndef SYZYGY_AGENT_ASAN_RTL_IMPL_H_
#define SYZYGY_AGENT_ASAN_RTL_IMPL_H_

#include <windows.h>

namespace agent {
namespace asan {

class AsanRuntime;
struct AsanErrorInfo;

// Initialize the Asan runtime library global variables.
// @param runtime The Asan runtime manager.
void SetUpRtl(AsanRuntime* runtime);

// Tear down the runtime library.
void TearDownRtl();

}  // namespace asan
}  // namespace agent

// Exposes the Asan Rtl functions.
extern "C" {

// This function isn't intercepted anymore (after v0.8.6.1), it's just here for
// backward compatibility.
HANDLE WINAPI asan_GetProcessHeap();

HANDLE WINAPI asan_HeapCreate(DWORD options,
                              SIZE_T initial_size,
                              SIZE_T maximum_size);

BOOL WINAPI asan_HeapDestroy(HANDLE heap);

LPVOID WINAPI asan_HeapAlloc(HANDLE heap,
                             DWORD flags,
                             SIZE_T bytes);

LPVOID WINAPI asan_HeapReAlloc(HANDLE heap,
                               DWORD flags,
                               LPVOID mem,
                               SIZE_T bytes);

BOOL WINAPI asan_HeapFree(HANDLE heap,
                          DWORD flags,
                          LPVOID mem);

SIZE_T WINAPI asan_HeapSize(HANDLE heap,
                            DWORD flags,
                            LPCVOID mem);

BOOL WINAPI asan_HeapValidate(HANDLE heap,
                              DWORD flags,
                              LPCVOID mem);

SIZE_T WINAPI asan_HeapCompact(HANDLE heap,
                               DWORD flags);

BOOL WINAPI asan_HeapLock(HANDLE heap);

BOOL WINAPI asan_HeapUnlock(HANDLE heap);

BOOL WINAPI asan_HeapWalk(HANDLE heap,
                          LPPROCESS_HEAP_ENTRY entry);

BOOL WINAPI asan_HeapSetInformation(
    HANDLE heap, HEAP_INFORMATION_CLASS info_class,
    PVOID info, SIZE_T info_length);

BOOL WINAPI asan_HeapQueryInformation(
    HANDLE heap, HEAP_INFORMATION_CLASS info_class,
    PVOID info, SIZE_T info_length, PSIZE_T return_length);

// @name Testing seams.
// @{
typedef void (*AsanErrorCallBack)(agent::asan::AsanErrorInfo*);
void WINAPI asan_SetCallBack(AsanErrorCallBack callback);
// Allows specifying a callback that will be called by the OnException handler
// in block.h utility funtions.
typedef void (*OnExceptionCallback)(EXCEPTION_POINTERS*);
void WINAPI asan_SetOnExceptionCallback(OnExceptionCallback callback);
// @}

// @name Experiment state enumerator, used to expose SyzyASAN experiments to
//     the client and from there to e.g. finch.
// @{
// Called once for each experiment.
// @param experiment_name the name of the experiement.
// @param experiment_group the selected group for this instance of this
//    experiement.
typedef void(WINAPI* AsanExperimentCallback)(const char* experiment_name,
                                             const char* experiment_group);
// Calls @p callback once for each experiment this runtime is performing.
// @param callback a function that will be invoked recursively zero or more
//     times to enumerate the experiments and their state.
void WINAPI asan_EnumExperiments(AsanExperimentCallback callback);
// @}

int asan_CrashForException(EXCEPTION_POINTERS* exception);

// This functions allows manually initializing the crash reporter used by the
// runtime.
//
// It should only be used if the deferred initialization flag has been used by
// the instrumented image (via the corresponding environment variable or at
// instrumentation time) and should only be called once. Trying to initialize
// the crash reporter a second time will result in undefined behavior.
//
// Manually controlling the initialization of the crash reporter is useful when
// there's no crash reporter available at initialization time (i.e. the
// instrumented process hasn't been initialized it yet). In addition to
// instrumenting with the deferred initialization flag, the instrumented image
// should do something like the following:
//
//   InitializeCrashReporter();
//   typedef VOID(WINAPI* SyzyAsanInitializeCrashReporterFn)();
//   HMODULE handle = ::GetModuleHandle(L"syzyasan_rtl.dll");
//   SyzyAsanInitializeCrashReporterFn syzyasan_init_crash_reporter =
//       reinterpret_cast<SyzyAsanInitializeCrashReporterFn>(
//             ::GetProcAddress(handle, "asan_InitializeCrashReporter"));
//   syzyasan_init_crash_reporter();
void WINAPI asan_InitializeCrashReporter();

}  // extern "C"

#endif  // SYZYGY_AGENT_ASAN_RTL_IMPL_H_
