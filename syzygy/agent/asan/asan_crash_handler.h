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
// Utilities for catching unhandled exceptions in an ASAN instrumented
// process. Installs a process wide filter that gets a first look at the
// exception prior to passing it on for further processing.

#ifndef SYZYGY_AGENT_ASAN_ASAN_CRASH_HANDLER_H_
#define SYZYGY_AGENT_ASAN_ASAN_CRASH_HANDLER_H_

#include <windows.h>
#include <set>

#include "base/callback.h"
#include "base/synchronization/lock.h"

namespace agent {
namespace asan {

class AsanCrashHandler {
 public:
  // A callback that will be invoked when an external unhandled exception is
  // being filtered.
  // |exception| is a pointer to an exception record pointer. If the callback
  //     wishes to create a new exception record it may do so and modify the
  //     pointer.
  typedef base::Callback<void(struct _EXCEPTION_POINTERS** /* exception */)>
      OnExceptionCallback;

  // Registers the ASAN unhandled exception filter with the system. This needs
  // to be called early in the process lifetime in order to ensure exceptions
  // are caught. By default the filter is enabled across all threads.
  static void Initialize();

  // Disables the filter for the calling thread.
  static void DisableForCurrentThread();

  // Enables the filter for the calling thread.
  static void EnableForCurrentThread();

  // Sets the OnExceptionCallback that will be invoked by the process wide
  // unhandled exception filter, if and only if the filter is enabled.
  static void SetOnExceptionCallback(OnExceptionCallback callback);

 protected:
  // The unhandled exception filter that we install for the process.
  // We rely on being initialized *after* Breakpad in chrome.exe. This allows
  // us to get our exception handler on top of Breakpad's, seeing crashes
  // before it does.
  static LONG WINAPI UnhandledExceptionFilter(
      struct _EXCEPTION_POINTERS* exception);

  // Used for ensuring we don't have collisions between crashing threads.
  static base::Lock lock_;

  // Is set to true once we've been initialized. Under lock_.
  static bool unhandled_exception_filter_registered_;

  // The previous top-level unhandled exception filter. Under lock_.
  static LPTOP_LEVEL_EXCEPTION_FILTER previous_unhandled_exception_filter_;

  // The registered OnExceptionCallback. Under lock_.
  static OnExceptionCallback on_exception_callback_;

  // The set of threads for which exception filtering is disabled. Under lock_.
  static std::set<DWORD> disabled_thread_ids_;
};

}  // namespace asan
}  // namespace agent

#endif  // SYZYGY_AGENT_ASAN_ASAN_CRASH_HANDLER_H_
